// Package rulesvc 是**唯一**的规则变更入口（RuleMutationService）。
//
// 为什么必须集中：Web API、CLI、后台 DNS reconcile 如果各自改库再各自调 nft，
// 就必然出现「DB 成功 / nft 失败」或反向的不一致。本包把所有变更统一成一条
// 事务化流水线：
//
//	读取正式状态
//	  ↓
//	构造 candidate（内存副本，绝不先落库）
//	  ↓
//	Validate（字段 + 目标地址 net/netip / hostname 严格校验）
//	  ↓
//	端口分配（留空→安全随机）+ 冲突检查（GuardPorts / 协议重叠）
//	  ↓
//	DNS 解析（域名目标；首次创建必须成功）
//	  ↓
//	DB 写入（创建时需要真实 ID —— nft 的 ct mark / counter 名都由 ID 决定）
//	  ↓
//	生成 nft candidate → `nft -c -f` 干跑校验 → `nft -f` 应用
//	  ↓
//	成功；任一步失败 → DB 与 nft 都回到变更前状态
//
// 为什么创建时先写库：nft 侧的 ct mark、named counter 名称全部由规则 ID 派生，
// ID 只有落库后才确定。因此创建路径是「插入取 ID → 应用 nft → 失败则物理删除
// 这条刚插入的行并回滚 nft」。刚创建的规则不可能有任何历史流量
// （counter 尚未存在、totals/daily 无记录），物理删除是安全且干净的 ——
// 这也是全仓唯一使用物理删除的地方；用户删除规则一律走软删除以保留历史。
//
// 编辑 / 策略 / 删除路径则相反：nft 先行（可靠可回滚），DB 收尾（不可逆）。
//
// 并发：所有变更串行化（mu），并在整个「nft + DB」过程中持有 enforcer 的
// enforcement 锁，避免周期 reconcile 在中间态按旧数据重建 nft。
package rulesvc

import (
	"context"
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
	ListActive(ctx context.Context) ([]*forward.Rule, error)
	Create(ctx context.Context, r *forward.Rule) (int64, error)
	Update(ctx context.Context, r *forward.Rule) error
	SoftDelete(ctx context.Context, id int64) error
	HardDelete(ctx context.Context, id int64) error
	UpdateResolved(ctx context.Context, id int64, v4, v6 string, at int64, status, errMsg string) error
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
	store    RuleStore
	enforcer Enforcer
	alloc    *forward.Allocator
	resolver resolve.Resolver
	guards   GuardProvider
	notify   Notifier
	now      func() time.Time

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

// Create 创建规则。返回落库后的正式规则（含最终监听端口与解析结果）。
func (s *Service) Create(ctx context.Context, in CreateInput) (*forward.Rule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	defer s.hold()()

	existing, err := s.store.ListActive(ctx)
	if err != nil {
		return nil, fmt.Errorf("读取规则列表失败: %w", err)
	}

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
	if cand.ListenPort == 0 {
		p, aerr := s.alloc.Allocate(cand, existing, s.guards())
		if aerr != nil {
			return nil, aerr
		}
		cand.ListenPort = p
	}
	if err := forward.CheckConflicts(cand, existing, s.guards()); err != nil {
		return nil, err
	}

	// 域名目标：创建时必须能解析出至少一个 A 或 AAAA，否则拒绝创建 ——
	// 不给用户留下一条一开始就完全不工作的规则。
	if cand.IsDomainTarget() {
		st := resolve.Resolve(ctx, s.resolver, cand.TargetAddress, resolve.State{}, s.now())
		if st.Empty() {
			return nil, fmt.Errorf("无法解析目标域名 %s：%s", cand.TargetAddress, st.Err)
		}
		applyResolve(cand, st)
	}

	// 写库取 ID（nft 侧对象名依赖 ID）。
	id, err := s.store.Create(ctx, cand)
	if err != nil {
		return nil, fmt.Errorf("数据库写入失败: %w", err)
	}
	cand.ID = id

	// 应用 nft；失败则物理删除这条刚插入的行并把 nft 恢复到变更前状态。
	if err := s.apply(ctx, append(append([]*forward.Rule{}, existing...), cand)); err != nil {
		if derr := s.store.HardDelete(ctx, id); derr != nil {
			slog.Error("创建失败后清理新规则失败，DB 与 nft 可能不一致（下一轮 reconcile 会自愈）",
				"id", id, "err", derr)
		}
		s.rollbackNFT(ctx, existing, "创建规则应用失败")
		return nil, fmt.Errorf("无法应用 nftables 规则: %w", err)
	}
	s.fire()
	return cand, nil
}

// Update 编辑规则（转发设置）。
func (s *Service) Update(ctx context.Context, id int64, in UpdateInput) (*forward.Rule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	defer s.hold()()

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
		norm, _, terr := forward.NormalizeTarget(*in.TargetAddress)
		if terr != nil {
			return nil, terr
		}
		targetChanged = norm != cur.TargetAddress
		cand.TargetAddress = norm
	}
	if err := forward.CheckConflicts(&cand, existing, s.guards()); err != nil {
		return nil, err
	}

	// 目标变了就重新解析：
	//   · 新目标是域名 → 必须能解析（同创建语义）；
	//   · 新目标是 IP  → 清空解析状态（IP 目标不需要 DNS）。
	if targetChanged {
		if cand.IsDomainTarget() {
			st := resolve.Resolve(ctx, s.resolver, cand.TargetAddress, resolve.State{}, s.now())
			if st.Empty() {
				return nil, fmt.Errorf("无法解析目标域名 %s：%s", cand.TargetAddress, st.Err)
			}
			applyResolve(&cand, st)
		} else {
			clearResolve(&cand)
		}
	}

	if err := s.applyWithRollback(ctx, s.withCandidate(existing, &cand), existing); err != nil {
		return nil, fmt.Errorf("无法应用 nftables 规则: %w", err)
	}
	if err := s.store.Update(ctx, &cand); err != nil {
		s.rollbackNFT(ctx, existing, "编辑规则落库失败")
		return nil, fmt.Errorf("数据库写入失败: %w", err)
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
	s.mu.Lock()
	defer s.mu.Unlock()
	defer s.hold()()

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

	if err := s.applyWithRollback(ctx, s.withCandidate(existing, &cand), existing); err != nil {
		return nil, fmt.Errorf("无法应用 nftables 规则: %w", err)
	}
	if err := s.store.Update(ctx, &cand); err != nil {
		s.rollbackNFT(ctx, existing, "策略落库失败")
		return nil, fmt.Errorf("数据库写入失败: %w", err)
	}
	s.fire()
	return &cand, nil
}

// Delete 软删除规则：撤销转发，但保留历史流量（今日/累计/每日全部保留）。
func (s *Service) Delete(ctx context.Context, id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	defer s.hold()()

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
	if err := s.applyWithRollback(ctx, remaining, existing); err != nil {
		return fmt.Errorf("无法应用 nftables 规则: %w", err)
	}
	if err := s.store.SoftDelete(ctx, id); err != nil {
		s.rollbackNFT(ctx, existing, "删除规则落库失败")
		return fmt.Errorf("数据库写入失败: %w", err)
	}
	s.fire()
	return nil
}

// RefreshDNS 对所有域名规则做一轮解析并在地址变化时同步 nft。
//
// 关键行为：
//   - 只有 last-known-good 地址真正变化才走 nft 同步（避免无谓重写）；
//   - DNS 临时失败保留旧地址（resolve.Resolve 已保证），只更新状态文本；
//   - 解析状态字段用独立 SQL 写入，不触碰用户配置字段，不抬 updated_at；
//   - 变化时走与 Web 变更完全相同的 apply 路径，因此 counter 不清零。
//
// 返回本轮发生地址变化的规则数。
func (s *Service) RefreshDNS(ctx context.Context) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	defer s.hold()()

	existing, err := s.store.ListActive(ctx)
	if err != nil {
		return 0, err
	}
	changed := 0
	next := make([]*forward.Rule, 0, len(existing))
	type pending struct {
		id    int64
		state resolve.State
	}
	var writes []pending

	for _, r := range existing {
		cp := *r
		if !cp.IsDomainTarget() {
			// IP 目标：清掉可能残留的解析状态（例如从域名改成 IP 的旧数据）。
			if cp.ResolveStatus != "" || cp.ResolvedV4 != "" || cp.ResolvedV6 != "" {
				clearResolve(&cp)
				writes = append(writes, pending{id: cp.ID, state: resolve.State{}})
			}
			next = append(next, &cp)
			continue
		}
		prev := resolve.State{V4: cp.ResolvedV4, V6: cp.ResolvedV6, At: cp.ResolvedAt,
			Status: cp.ResolveStatus, Err: cp.ResolveError}
		st := resolve.Resolve(ctx, s.resolver, cp.TargetAddress, prev, s.now())
		if st.Changed(prev) {
			changed++
		}
		applyResolve(&cp, st)
		writes = append(writes, pending{id: cp.ID, state: st})
		next = append(next, &cp)
	}

	if changed > 0 {
		// 地址有实际变化 → 同步 nft（结构签名变化会触发链重写，counter 保留）。
		if err := s.applyWithRollback(ctx, next, existing); err != nil {
			return 0, fmt.Errorf("DNS 目标更新应用失败: %w", err)
		}
	}
	// 状态落库：即使地址没变也要写（stale/ok 状态与错误文本需要反映到 UI）。
	for _, w := range writes {
		if err := s.store.UpdateResolved(ctx, w.id, w.state.V4, w.state.V6,
			w.state.At, w.state.Status, w.state.Err); err != nil {
			slog.Warn("写入 DNS 解析状态失败", "rule", w.id, "err", err)
		}
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

// apply 同步 nft（enforcer 为 nil 时为空操作）。
func (s *Service) apply(ctx context.Context, rules []*forward.Rule) error {
	if s.enforcer == nil {
		return nil
	}
	return s.enforcer.ApplyRules(ctx, rules)
}

// applyWithRollback 应用 next 规则集；失败时把 nft 恢复到 prev 状态。
func (s *Service) applyWithRollback(ctx context.Context, next, prev []*forward.Rule) error {
	if err := s.apply(ctx, next); err != nil {
		s.rollbackNFT(ctx, prev, "变更应用失败")
		return err
	}
	return nil
}

// rollbackNFT 把 nft 恢复到给定（变更前的正式）规则集。
func (s *Service) rollbackNFT(ctx context.Context, prev []*forward.Rule, reason string) {
	if s.enforcer == nil {
		return
	}
	// 用独立 ctx：请求 ctx 可能已被取消，回滚必须尽力完成。
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 20*time.Second)
	defer cancel()
	if err := s.enforcer.ApplyRules(rctx, prev); err != nil {
		slog.Error("nft 回滚失败，可能与数据库不一致（下一轮 reconcile 会自愈）",
			"reason", reason, "err", err)
		return
	}
	slog.Warn("已回滚 nftables 到变更前状态", "reason", reason)
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
