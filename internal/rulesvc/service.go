// Package rulesvc coordinates committed SQLite state and nftables enforcement.
// A mutation stages writes in SQLite, applies the candidate, then commits.
// On ambiguous apply/commit failure it reconciles from the committed database;
// on interruption the same recovery happens during the next startup.
package rulesvc

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/k6nfmm7dbr-commits/nft-forward/internal/forward"
	"github.com/k6nfmm7dbr-commits/nft-forward/internal/resolve"
)

// RuleStore 是本服务需要的持久层能力（由 forward.Store 实现）。
// 抽象成接口便于故障注入测试（模拟 SQLite 写入失败）。
type RuleStore interface {
	ListActive(context.Context) ([]*forward.Rule, error)
	ReserveID(context.Context) (int64, error)
	Transaction(context.Context, func(forward.Mutation) error) error
}

// Enforcer 抽象「把当前规则集同步到 nftables」的能力。
// 由 policy.Service 实现（它掌握 allow set / qblock 等运行时状态）。
type Enforcer interface {
	// ApplyRules 用给定规则集（未删除的全部规则）同步 nft。
	// 实现必须：先 nft -c 校验、再应用；不重建表；失败返回错误且不改变系统。
	ApplyRules(ctx context.Context, rules []*forward.Rule) error

	// Hold 获取 enforcement 互斥并返回释放函数。
	//
	// 为什么必须暴露：一次变更包含「nft apply」与「DB 写入」两步。若周期
	// reconcile 在两步之间插入，它会按旧的 DB 状态重建 nft，把刚应用的变更
	// 冲掉。持锁覆盖整个变更过程即可消除该窗口。
	Hold() func()
}

// GuardProvider 返回当前保留端口表（面板端口、SSH 端口等）。
type GuardProvider func() forward.GuardPorts

// Notifier 在变更成功提交后被调用（用于 SSE 广播）。
type Notifier func()

// Service 是规则变更服务。
type Service struct {
	store        RuleStore
	enforcer     Enforcer
	alloc        *forward.Allocator
	resolver     resolve.Resolver
	guards       GuardProvider
	notify       Notifier
	mutationLock func(context.Context) (forward.GuardPorts, func(), error)
	now          func() time.Time

	// mu 串行化所有变更：分配端口 → 冲突检查 → 落库在同一临界区内完成，
	// 因此并发创建不可能拿到同一个随机端口（TestRandomPortConcurrentCreate）。
	mu sync.Mutex
}

// New 构造服务。
func New(store RuleStore, enf Enforcer, resolver resolve.Resolver, guards GuardProvider) *Service {
	if resolver == nil {
		resolver = resolve.NewSystemResolver(5 * time.Second)
	}
	if guards == nil {
		guards = func() forward.GuardPorts { return forward.GuardPorts{} }
	}
	return &Service{
		store:    store,
		enforcer: enf,
		alloc:    forward.NewAllocator(nil, nil),
		resolver: resolver,
		guards:   guards,
		now:      time.Now,
	}
}

// SetAllocator 覆盖端口分配器（测试注入确定随机源）。
func (s *Service) SetAllocator(a *forward.Allocator) {
	if a != nil {
		s.alloc = a
	}
}

// SetClock 注入时钟（测试用）。
func (s *Service) SetClock(fn func() time.Time) {
	if fn != nil {
		s.now = fn
	}
}

// SetNotifier 设置提交成功后的通知回调。
func (s *Service) SetNotifier(fn Notifier) { s.notify = fn }

// SetMutationLock allows the daemon to serialize rule changes with external
// config/port operations, obtaining current guard ports inside the file lock.
// It must be configured before serving requests.
func (s *Service) SetMutationLock(lock func(context.Context) (forward.GuardPorts, func(), error)) {
	s.mutationLock = lock
}

func (s *Service) lockMutation(ctx context.Context) (forward.GuardPorts, func(), error) {
	var release func()
	guards := s.guards()
	if s.mutationLock != nil {
		var err error
		guards, release, err = s.mutationLock(ctx)
		if err != nil {
			return nil, nil, err
		}
	}
	s.mu.Lock()
	unlock := s.hold()
	return guards, func() {
		unlock()
		s.mu.Unlock()
		if release != nil {
			release()
		}
	}, nil
}

// CreateInput 是创建规则的入参（只含用户可配置字段）。
//
// ListenPort == 0 表示「留空 → 由后端安全随机分配」。
type CreateInput struct {
	Name          string
	Protocol      string
	ListenPort    int
	TargetAddress string
	TargetPort    int
	Enabled       *bool
}

// UpdateInput 是编辑规则的入参。nil 字段表示不修改。
//
// 注意：编辑时 ListenPort 必须显式给出有效值。前端清空端口不会被「偷偷」换成
// 随机端口 —— 那只是新建规则的语义。
type UpdateInput struct {
	Name          *string
	Protocol      *string
	ListenPort    *int
	TargetAddress *string
	TargetPort    *int
	Enabled       *bool
}

// PolicyInput 是配额 / IP 限制变更入参。
type PolicyInput struct {
	QuotaEnabled    *bool
	QuotaLimitBytes *int64
	IPLimitEnabled  *bool
	IPLimitMax      *int
	// QuotaResetTo 非 nil 时把配额基线重置为该值（调用方传入当前累计流量）。
	QuotaResetTo *int64
}

// ErrNotFound 表示规则不存在或已删除。
var ErrNotFound = errors.New("规则不存在或已删除")

// dnsConcurrency 是后台 DNS 刷新的并发上限。
//
// 上限的意义：域名规则可能有几十条，全部并发查询会瞬间打满 DNS 服务端与本机
// socket；串行又会让一轮刷新耗时 = 规则数 × 超时。8 是折中值，配合 resolve
// 层每次查询 5s 超时，最坏一轮 = ceil(N/8) × 5s，且全程不持任何锁。
const dnsConcurrency = 8

// Create 创建规则。返回落库后的正式规则（含最终监听端口与解析结果）。
//
// DNS 解析在**加锁之前**完成：它只依赖用户提交的目标地址，不需要看已有规则。
// 这样一次域名解析超时（最长 5s）不会把其它规则的 CRUD 全部堵住。
func (s *Service) Create(ctx context.Context, in CreateInput) (*forward.Rule, error) {
	cand := &forward.Rule{
		Name:          in.Name,
		Enabled:       in.Enabled == nil || *in.Enabled,
		Protocol:      in.Protocol,
		ListenPort:    in.ListenPort,
		TargetAddress: in.TargetAddress,
		TargetPort:    in.TargetPort,
	}
	// 先规范化字段（含目标地址严格校验），再分配端口：
	// 端口分配需要知道协议，协议非法时必须先报错。
	if err := forward.Normalize(cand); err != nil {
		return nil, err
	}
	if !forward.ValidPort(cand.TargetPort) {
		return nil, fmt.Errorf("目标端口必须在 1-65535: %d", cand.TargetPort)
	}

	// 域名目标：创建时必须能解析出至少一个 A 或 AAAA，否则拒绝创建 ——
	// 不给用户留下一条一开始就完全不工作的规则。（锁外执行）
	var rstate resolve.State
	if cand.IsDomainTarget() {
		rstate = resolve.Resolve(ctx, s.resolver, cand.TargetAddress, resolve.State{}, s.now())
		if rstate.Empty() {
			return nil, fmt.Errorf("无法解析目标域名 %s：%s", cand.TargetAddress, rstate.Err)
		}
	}

	guards, unlock, err := s.lockMutation(ctx)
	if err != nil {
		return nil, err
	}
	defer unlock()

	existing, err := s.store.ListActive(ctx)
	if err != nil {
		return nil, fmt.Errorf("读取规则列表失败: %w", err)
	}
	if cand.ListenPort == 0 {
		p, aerr := s.alloc.Allocate(cand, existing, guards)
		if aerr != nil {
			return nil, aerr
		}
		cand.ListenPort = p
	}
	if err := forward.CheckConflicts(cand, existing, guards); err != nil {
		return nil, err
	}
	if cand.IsDomainTarget() {
		applyResolve(cand, rstate)
	}

	id, err := s.store.ReserveID(ctx)
	if err != nil {
		return nil, fmt.Errorf("分配规则 ID 失败: %w", err)
	}
	cand.ID = id
	if err := s.transact(ctx, append(existing, cand), func(m forward.Mutation) error { return m.Create(cand) }); err != nil {
		return nil, err
	}
	s.fire()
	return cand, nil
}

// Update 编辑规则（转发设置）。
//
// 与 Create 同理：新目标是域名时，DNS 解析在加锁前完成（只依赖用户输入），
// 锁内只做校验、nft apply、落库。
func (s *Service) Update(ctx context.Context, id int64, in UpdateInput) (*forward.Rule, error) {
	// 锁外预解析：仅当调用方显式给了目标地址且它是域名。
	var newTarget string
	var pre *resolve.State
	if in.TargetAddress != nil {
		norm, _, terr := forward.NormalizeTarget(*in.TargetAddress)
		if terr != nil {
			return nil, terr
		}
		newTarget = norm
		if forward.IsDomain(norm) {
			st := resolve.Resolve(ctx, s.resolver, norm, resolve.State{}, s.now())
			pre = &st
		}
	}

	guards, unlock, err := s.lockMutation(ctx)
	if err != nil {
		return nil, err
	}
	defer unlock()

	existing, cur, err := s.load(ctx, id)
	if err != nil {
		return nil, err
	}
	cand := *cur
	if in.Name != nil {
		cand.Name = *in.Name
	}
	if in.Protocol != nil {
		cand.Protocol = *in.Protocol
	}
	if in.ListenPort != nil {
		if *in.ListenPort == 0 {
			// 编辑时端口留空是无效输入：绝不静默换一个随机端口。
			return nil, fmt.Errorf("请输入监听端口")
		}
		cand.ListenPort = *in.ListenPort
	}
	if in.TargetPort != nil {
		cand.TargetPort = *in.TargetPort
	}
	if in.Enabled != nil {
		cand.Enabled = *in.Enabled
	}
	targetChanged := false
	if in.TargetAddress != nil {
		targetChanged = newTarget != cur.TargetAddress
		cand.TargetAddress = newTarget
	}
	if err := forward.CheckConflicts(&cand, existing, guards); err != nil {
		return nil, err
	}

	// 目标变了就重新解析：
	//   · 新目标是域名 → 必须能解析（同创建语义；结果来自锁外预解析）；
	//   · 新目标是 IP  → 清空解析状态（IP 目标不需要 DNS）。
	if targetChanged {
		if cand.IsDomainTarget() {
			if pre == nil || pre.Empty() {
				reason := "解析失败"
				if pre != nil && pre.Err != "" {
					reason = pre.Err
				}
				return nil, fmt.Errorf("无法解析目标域名 %s：%s", cand.TargetAddress, reason)
			}
			applyResolve(&cand, *pre)
		} else {
			clearResolve(&cand)
		}
	}

	if err := s.transact(ctx, s.withCandidate(existing, &cand), func(m forward.Mutation) error { return m.Update(&cand) }); err != nil {
		return nil, err
	}
	s.fire()
	return &cand, nil
}

// SetEnabled 启用/停用规则。
func (s *Service) SetEnabled(ctx context.Context, id int64, enabled bool) (*forward.Rule, error) {
	return s.Update(ctx, id, UpdateInput{Enabled: &enabled})
}

// UpdatePolicy 修改配额 / IP 限制。
//
// 走同一条流水线：策略变化会改变 nft 结构（IP 限制开关影响 allow set 声明），
// 因此必须由统一入口应用，不允许旁路。
//
// 配额与 IP 限制的变更**不触碰 named counter**：配额超限走 qblock set 元素，
// allow set 走元素增量，两者都不重写 counter 声明，因此累计流量不会被清零。
func (s *Service) UpdatePolicy(ctx context.Context, id int64, in PolicyInput) (*forward.Rule, error) {
	_, unlock, err := s.lockMutation(ctx)
	if err != nil {
		return nil, err
	}
	defer unlock()

	existing, cur, err := s.load(ctx, id)
	if err != nil {
		return nil, err
	}
	cand := *cur
	if in.QuotaEnabled != nil {
		cand.QuotaEnabled = *in.QuotaEnabled
	}
	if in.QuotaLimitBytes != nil {
		cand.QuotaLimitBytes = *in.QuotaLimitBytes
	}
	if in.IPLimitEnabled != nil {
		cand.IPLimitEnabled = *in.IPLimitEnabled
	}
	if in.IPLimitMax != nil {
		cand.IPLimitMax = *in.IPLimitMax
	}
	if in.QuotaResetTo != nil {
		// 只重置「已用」基线，绝不动 counter、绝不删历史。
		cand.QuotaResetBaseline = *in.QuotaResetTo
	}
	if cand.QuotaEnabled && cand.QuotaLimitBytes <= 0 {
		return nil, fmt.Errorf("启用配额时必须设置额度 > 0")
	}
	if cand.IPLimitEnabled && cand.IPLimitMax < 1 {
		return nil, fmt.Errorf("最大同时在线数必须 >= 1")
	}

	if err := s.transact(ctx, s.withCandidate(existing, &cand), func(m forward.Mutation) error { return m.Update(&cand) }); err != nil {
		return nil, err
	}
	s.fire()
	return &cand, nil
}

// Delete 软删除规则：撤销转发，但保留历史流量（今日/累计/每日全部保留）。
func (s *Service) Delete(ctx context.Context, id int64) error {
	_, unlock, err := s.lockMutation(ctx)
	if err != nil {
		return err
	}
	defer unlock()

	existing, cur, err := s.load(ctx, id)
	if err != nil {
		return err
	}
	remaining := make([]*forward.Rule, 0, len(existing))
	for _, r := range existing {
		if r.ID != cur.ID {
			remaining = append(remaining, r)
		}
	}
	if err := s.transact(ctx, remaining, func(m forward.Mutation) error { return m.SoftDelete(id) }); err != nil {
		return err
	}
	s.fire()
	return nil
}

// RefreshDNS resolves outside the mutation lock and discards results if
// the rule or its last-known-good state changed while lookup was in flight.
func (s *Service) RefreshDNS(ctx context.Context) (int, error) {
	existing, err := s.store.ListActive(ctx)
	if err != nil {
		return 0, err
	}
	type result struct {
		original *forward.Rule
		state    resolve.State
	}
	jobs := make(chan int)
	results := make([]result, len(existing))
	var wg sync.WaitGroup
	now := s.now()
	for i := 0; i < min(dnsConcurrency, len(existing)); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				if ctx.Err() != nil {
					continue
				}
				r := existing[i]
				prev := resolve.State{V4: r.ResolvedV4, V6: r.ResolvedV6, At: r.ResolvedAt, Status: r.ResolveStatus, Err: r.ResolveError}
				if r.IsDomainTarget() {
					state := resolve.Resolve(ctx, s.resolver, r.TargetAddress, prev, now)
					if state != prev {
						results[i] = result{r, state}
					}
				} else if prev != (resolve.State{}) {
					results[i] = result{original: r}
				}
			}
		}()
	}
	for i := range existing {
		if ctx.Err() != nil {
			break
		}
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	any := false
	for _, res := range results {
		any = any || res.original != nil
	}
	if !any {
		return 0, nil
	}

	_, unlock, err := s.lockMutation(ctx)
	if err != nil {
		return 0, err
	}
	defer unlock()
	current, err := s.store.ListActive(ctx)
	if err != nil {
		return 0, fmt.Errorf("读取规则列表失败: %w", err)
	}
	byID := make(map[int64]result, len(results))
	for _, res := range results {
		if res.original != nil {
			byID[res.original.ID] = res
		}
	}
	changed := 0
	var ups []forward.ResolvedUpdate
	for i, cur := range current {
		res, ok := byID[cur.ID]
		if !ok || *cur != *res.original {
			continue
		}
		cand := *cur
		applyResolve(&cand, res.state)
		current[i] = &cand
		ups = append(ups, forward.ResolvedUpdate{ID: cur.ID, V4: cand.ResolvedV4, V6: cand.ResolvedV6,
			At: cand.ResolvedAt, Status: cand.ResolveStatus, Err: cand.ResolveError})
		if cur.IsDomainTarget() && (cand.ResolvedV4 != cur.ResolvedV4 || cand.ResolvedV6 != cur.ResolvedV6) {
			changed++
		}
	}
	if len(ups) == 0 {
		return 0, nil
	}
	if changed == 0 {
		current = nil
	}
	err = s.transact(ctx, current, func(m forward.Mutation) error {
		for _, u := range ups {
			if err := m.UpdateResolved(u); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("DNS 刷新失败: %w", err)
	}
	if changed > 0 {
		s.fire()
	}
	return changed, nil
}

// ---- 内部辅助 ----

// hold 获取 enforcement 锁；enforcer 为 nil（测试）时返回空操作。
func (s *Service) hold() func() {
	if s.enforcer == nil {
		return func() {}
	}
	return s.enforcer.Hold()
}

// load 读取当前全部未删除规则与目标规则。
func (s *Service) load(ctx context.Context, id int64) ([]*forward.Rule, *forward.Rule, error) {
	existing, err := s.store.ListActive(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("读取规则列表失败: %w", err)
	}
	for _, r := range existing {
		if r.ID == id {
			return existing, r, nil
		}
	}
	return nil, nil, ErrNotFound
}

// withCandidate 用 candidate 替换同 ID 规则，返回新集合（不修改入参）。
func (s *Service) withCandidate(existing []*forward.Rule, cand *forward.Rule) []*forward.Rule {
	out := make([]*forward.Rule, 0, len(existing)+1)
	replaced := false
	for _, r := range existing {
		if cand.ID != 0 && r.ID == cand.ID {
			out = append(out, cand)
			replaced = true
			continue
		}
		out = append(out, r)
	}
	if !replaced {
		out = append(out, cand)
	}
	return out
}

// transact does not treat the old in-memory slice as truth after a commit
// error. Read the SQLite state after the transaction closes, using an
// independent bounded context even if the HTTP client has disconnected.
// A nil candidate means the edit only changes DNS metadata.
func (s *Service) transact(ctx context.Context, candidate []*forward.Rule, edit func(forward.Mutation) error) error {
	attempted := false
	var restore func()
	err := s.store.Transaction(ctx, func(m forward.Mutation) error {
		if err := edit(m); err != nil {
			return fmt.Errorf("数据库写入失败: %w", err)
		}
		if s.enforcer == nil || candidate == nil {
			return nil
		}
		attempted = true
		if e, ok := s.enforcer.(interface{ SaveRuntime() func() }); ok {
			restore = e.SaveRuntime()
		}
		var err error
		if e, ok := s.enforcer.(interface {
			ApplyRulesTx(context.Context, []*forward.Rule, *sql.Tx) error
		}); ok {
			err = e.ApplyRulesTx(ctx, candidate, m.SQLTx())
		} else {
			err = s.enforcer.ApplyRules(ctx, candidate)
		}
		if err != nil {
			return fmt.Errorf("无法应用 nftables 规则: %w", err)
		}
		return nil
	})
	if err == nil || !attempted {
		return err
	}

	if restore != nil {
		restore()
	}
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 20*time.Second)
	defer cancel()
	committed, rerr := s.store.ListActive(rctx)
	if rerr == nil {
		rerr = s.enforcer.ApplyRules(rctx, committed)
	}
	if rerr != nil {
		rerr = fmt.Errorf("无法恢复已提交规则的 nft 状态: %w", rerr)
		if e, ok := s.enforcer.(interface{ MarkUnready(error) }); ok {
			e.MarkUnready(rerr)
		}
		slog.Error("规则恢复失败", "err", rerr)
		return errors.Join(err, rerr)
	}
	return err
}

func (s *Service) fire() {
	if s.notify != nil {
		s.notify()
	}
}

// applyResolve 把解析状态写入规则副本。
func applyResolve(r *forward.Rule, st resolve.State) {
	r.ResolvedV4 = st.V4
	r.ResolvedV6 = st.V6
	r.ResolvedAt = st.At
	r.ResolveStatus = st.Status
	r.ResolveError = st.Err
}

// clearResolve 清空解析状态（IP 目标）。
func clearResolve(r *forward.Rule) {
	r.ResolvedV4 = ""
	r.ResolvedV6 = ""
	r.ResolvedAt = 0
	r.ResolveStatus = ""
	r.ResolveError = ""
}
