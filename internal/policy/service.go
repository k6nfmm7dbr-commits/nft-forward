// Package policy 编排「连接观测 → IP Slot 准入 → 配额判定 → nft 强制」。
//
// 设计原则：
//   - 在线 IP 以真实连接生命周期为依据（conntrack 是唯一事实来源）；
//   - allow set 的权威来源只能是 Granted slot，绝不让「观察到」直接进 allow set；
//   - nft 应用事务化（先 -c -f 检查，通过后 -f 应用），失败不落库成成功状态；
//   - 服务器自身发起的出站连接不算客户端（否则会虚占 IP 名额、挤掉真实用户）。
//
// ★ 两层 enforcement 必须彻底解耦（v0.3.1 收口）：
//
//	A. 静态 / 结构 enforcement —— **不依赖 conntrack**
//	   DNAT、FORWARD counter、quota 阻断集合、规则新增/删除/修改/启停、
//	   nft 自有对象自愈。conntrack 挂掉时这些必须照常执行，否则会出现
//	   「用户删除规则 → API 返回成功 → DB 已删 → nft 旧 DNAT 还在」的假成功。
//
//	B. 动态 IP Slot enforcement —— 依赖 conntrack
//	   observed / candidate / active / granted / rejected / slot release。
//	   conntrack 读取失败、不完整、不可用、无法确认真实连接状态时，
//	   **冻结上一轮 slot 状态**：不新增、不释放、不清空 allow set。
//
// 与 rulesvc 的关系：本包实现 rulesvc.Enforcer。所有规则变更由 rulesvc 统一
// 编排，本包只负责「把给定规则集 + 运行时状态同步到 nftables」，
// 并周期性自愈（结构被外部删除、配额翻转、IP 上下线）。
package policy

import (
	"context"
	"database/sql"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/k6nfmm7dbr-commits/nft-forward/internal/connection"
	"github.com/k6nfmm7dbr-commits/nft-forward/internal/forward"
	"github.com/k6nfmm7dbr-commits/nft-forward/internal/nft"
	"github.com/k6nfmm7dbr-commits/nft-forward/internal/traffic"
)

// 默认超时（可由 setter 覆盖，测试用）。
const (
	defaultIPIdle         = 60 * time.Second // 半开连接无流量判活窗口
	defaultUDPIdle        = 120 * time.Second
	defaultRejectedTTL    = 60 * time.Second
	defaultProvisionalTTL = 10 * time.Second
	// selfIPsTTL 是本机地址集合缓存时长（网卡增删 / DHCP 换址后自动跟上）。
	selfIPsTTL = 30 * time.Second
)

// IPEntry 是单个在线/被拒 IP 的展示快照。
type IPEntry struct {
	IP      string `json:"ip"`
	TCP     int    `json:"tcp"`
	UDP     int    `json:"udp"`
	Granted bool   `json:"granted"`
}

// RuleIPSnapshot 是单条规则的在线 IP 快照（供 API / SSE）。
type RuleIPSnapshot struct {
	RuleID       int64     `json:"rule_id"`
	Limited      bool      `json:"limited"`
	MaxIPs       int       `json:"max_ips"`
	GrantedCount int       `json:"granted_count"`
	IPs          []IPEntry `json:"ips"`
	Rejected     []IPEntry `json:"rejected"`
	// Frozen 表示本轮 conntrack 不可用，展示的是上一轮冻结状态。
	Frozen bool `json:"frozen,omitempty"`
}

// RuleQuotaState 是单条规则的配额状态。
type RuleQuotaState struct {
	RuleID     int64  `json:"rule_id"`
	Enabled    bool   `json:"quota_enabled"`
	LimitBytes int64  `json:"quota_limit_bytes"`
	UsedBytes  int64  `json:"quota_used_bytes"`
	State      string `json:"quota_state"` // unlimited / ok / exceeded
}

// RuleState 合并单条规则的配额与 IP 状态（供 API / SSE / 状态徽标）。
type RuleState struct {
	RuleID  int64
	Quota   RuleQuotaState
	IPs     RuleIPSnapshot
	ConnTCP int // 当前 TCP 连接数（已授权 IP 之和）
	ConnUDP int // 当前 UDP 会话数（已授权 IP 之和）
}

// Health 是策略层健康快照（供 /api/health 与 selftest）。
type Health struct {
	Ready           bool   `json:"ready"`
	LastError       string `json:"last_error,omitempty"`
	LastApplyOK     int64  `json:"last_apply_ok,omitempty"`
	LastApplyError  string `json:"last_apply_error,omitempty"`
	LastReconcileOK int64  `json:"last_reconcile_ok,omitempty"`
	ConntrackOK     bool   `json:"conntrack_ok"`
	ConntrackNote   string `json:"conntrack_note,omitempty"`
	// IPStateFrozen 表示当前在线 IP 状态处于冻结（conntrack 不可用）。
	IPStateFrozen bool `json:"ip_state_frozen,omitempty"`
	// LastHealOK 是最近一次「检测到自有对象缺失并成功重建」的时间。
	LastHealOK int64 `json:"last_heal_ok,omitempty"`
	// LastHealMissing 是最近一次自愈时缺失的对象描述。
	LastHealMissing string `json:"last_heal_missing,omitempty"`
}

// flowState 跟踪单条流的字节与活跃时刻（判活用）。
//
// ★ 为什么必须区分 LastChange 与 LastSeen：
//
//	LastChange = 最近一次字节数发生变化的时刻（真正的「有流量」）；
//	LastSeen   = 最近一次在 conntrack 里见到这条流的时刻。
//
// 旧实现只有一个 LastSeen 且在超过 idle 窗口时**删除**该 entry。删除后下一轮
// 同一条流仍在 conntrack 里，于是被当成「首次见到」重新插入并判定为「有流量」
// —— 空闲连接因此永远不会真正离线，ipIdle/udpIdle 形同虚设。
// 现在保留 entry、只按 LastChange 判活，并由「本轮是否在 conntrack 中出现」
// 驱动 GC，两个问题一起消除。
type flowState struct {
	Bytes      int64
	LastChange time.Time
	LastSeen   time.Time
}

// quotaSource 提供配额实时判定所需的「已落库累计 + 未落库基线」。
// 由 traffic.Collector 实现；测试可注入。
type quotaSource func() traffic.LiveDelta

// Service 是策略编排服务。
type Service struct {
	db      *sql.DB
	store   *forward.Store
	runner  nft.Runner
	nftConf string
	ctPath  string

	ipIdle         time.Duration
	udpIdle        time.Duration
	rejectedTTL    time.Duration
	provisionalTTL time.Duration
	now            func() time.Time
	nftApply       func(ctx context.Context, runner nft.Runner, path, script string) error
	nftReadState   func(ctx context.Context, runner nft.Runner) (*nft.State, error)
	conntrack      func(path string) connection.Result
	localIPs       func() (map[string]bool, error)
	live           quotaSource

	runMu sync.Mutex
	mu    sync.RWMutex

	ipStates map[int64]*NodeIPState
	flows    map[string]*flowState // "ruleID\x00proto\x00ip:sport" -> 流状态
	states   map[int64]*RuleState
	ready    bool
	lastErr  string

	lastApplyOK     int64
	lastApplyErr    string
	lastReconcileOK int64
	ctInactive      bool
	ctOK            bool
	ctNote          string
	ipFrozen        bool
	lastHealOK      int64
	lastHealMissing string

	selfIPs   map[string]bool
	selfIPsAt time.Time

	// lastStructSig 是最近成功应用的结构签名。
	// 结构未变时只做元素增量同步，绝不重写链 —— 这是 counter 不被清零的保证。
	lastStructSig string
}

// New 构造策略服务。
func New(db *sql.DB, store *forward.Store, runner nft.Runner, nftConf, ctPath string) *Service {
	if runner == nil {
		runner = nft.ExecRunner{}
	}
	return &Service{
		db:             db,
		store:          store,
		runner:         runner,
		nftConf:        nftConf,
		ctPath:         ctPath,
		ipIdle:         defaultIPIdle,
		udpIdle:        defaultUDPIdle,
		rejectedTTL:    defaultRejectedTTL,
		provisionalTTL: defaultProvisionalTTL,
		now:            time.Now,
		nftApply:       nft.Apply,
		nftReadState:   nft.ReadState,
		conntrack:      connection.ReadConntrack,
		localIPs:       connection.LocalIPs,
		live:           func() traffic.LiveDelta { return traffic.LiveDelta{} },
		ipStates:       map[int64]*NodeIPState{},
		flows:          map[string]*flowState{},
		states:         map[int64]*RuleState{},
	}
}

// SetClock / setter 用于测试。
func (s *Service) SetClock(fn func() time.Time) { s.now = fn }
func (s *Service) SetNFTApply(fn func(ctx context.Context, r nft.Runner, p, script string) error) {
	s.nftApply = fn
}

// SetNFTReadState 注入 nft 状态读取（测试用）。
func (s *Service) SetNFTReadState(fn func(ctx context.Context, r nft.Runner) (*nft.State, error)) {
	s.nftReadState = fn
}
func (s *Service) SetConntrack(fn func(path string) connection.Result) { s.conntrack = fn }

// SetLocalIPs 注入本机地址集合（测试用）。
func (s *Service) SetLocalIPs(fn func() (map[string]bool, error)) { s.localIPs = fn }

// SetQuotaSource 注入配额实时快照来源（生产环境是 traffic.Collector）。
//
// 为什么需要：SQLite 里的 totals 每 interval（默认 2s）才刷一次，高带宽下
// 仅凭它判配额会明显超额。这里让 policy 直接拿到「已落库累计 + 未落库基线」，
// 再配合本轮 nft 读数即可算出实时用量，且不额外发起任何 nft 系统调用。
func (s *Service) SetQuotaSource(fn func() traffic.LiveDelta) {
	if fn != nil {
		s.live = fn
	}
}

func (s *Service) SetIPIdle(d time.Duration)         { s.ipIdle = d }
func (s *Service) SetUDPIdle(d time.Duration)        { s.udpIdle = d }
func (s *Service) SetRejectedTTL(d time.Duration)    { s.rejectedTTL = d }
func (s *Service) SetProvisionalTTL(d time.Duration) { s.provisionalTTL = d }

// Ready 报告是否完成首次 reconcile。
func (s *Service) Ready() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.ready
}

// LastError 返回最近错误。
func (s *Service) LastError() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastErr
}

// HealthSnapshot 返回健康快照。
func (s *Service) HealthSnapshot() Health {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return Health{
		Ready:           s.ready,
		LastError:       s.lastErr,
		LastApplyOK:     s.lastApplyOK,
		LastApplyError:  s.lastApplyErr,
		LastReconcileOK: s.lastReconcileOK,
		ConntrackOK:     s.ctOK,
		ConntrackNote:   s.ctNote,
		IPStateFrozen:   s.ipFrozen,
		LastHealOK:      s.lastHealOK,
		LastHealMissing: s.lastHealMissing,
	}
}

// States 返回所有规则的状态快照。
func (s *Service) States() map[int64]*RuleState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[int64]*RuleState, len(s.states))
	for k, v := range s.states {
		out[k] = v
	}
	return out
}

// StateOf 返回单条规则状态。
func (s *Service) StateOf(ruleID int64) *RuleState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.states[ruleID]
}

// Lifetime 返回某规则累计流量（上传+下载），供配额重置。
func (s *Service) Lifetime(ctx context.Context, ruleID int64) (int64, error) {
	return s.lifetimeBytes(ctx, ruleID)
}

// lifetimeBytes 读某规则的累计流量（上传+下载）。
func (s *Service) lifetimeBytes(ctx context.Context, ruleID int64) (int64, error) {
	var up, down sql.NullInt64
	err := s.db.QueryRowContext(ctx,
		"SELECT upload_bytes,download_bytes FROM traffic_totals WHERE rule_id=?", ruleID).
		Scan(&up, &down)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return up.Int64 + down.Int64, nil
}

// ---- Enforcer 接口（供 rulesvc 调用）----

// Hold 获取 enforcement 互斥并返回释放函数。
//
// rulesvc 在一次变更的**全过程**（nft apply + DB commit）持有它，
// 保证周期 reconcile 不会在「nft 已改、DB 未提交」的窗口里把变更冲掉。
func (s *Service) Hold() func() {
	s.runMu.Lock()
	return s.runMu.Unlock
}

// ApplyRules 用给定规则集同步 nft。必须在 Hold 期间调用。
//
// 与周期 reconcile 共用同一条 sync 路径，因此「结构未变只走元素增量」
// 的 counter 保护同样生效；conntrack 是否可用不会影响它是否执行。
func (s *Service) ApplyRules(ctx context.Context, rules []*forward.Rule) error {
	return s.sync(ctx, rules)
}

// Reconcile 执行一轮：读规则 → 观测 → slot 准入 → 配额判定 → nft 强制 → 落库状态。
func (s *Service) Reconcile(ctx context.Context) error {
	s.runMu.Lock()
	defer s.runMu.Unlock()
	rules, err := s.store.ListActive(ctx)
	if err != nil {
		s.setErr(err.Error())
		return err
	}
	return s.sync(ctx, rules)
}

// ---- 核心同步 ----

// sync 是唯一的 enforcement 路径（调用方必须持有 runMu）。
//
// 结构（A 层）与 IP Slot（B 层）在此彻底分离：
//   - conntrack 可用 → 正常做 slot 准入/释放；
//   - conntrack 不可用/不完整 → 冻结上一轮 slot（沿用旧 allow set 元素），
//     但 DNAT / counter / quota / 自愈 **照常同步**。
//
// 因此 conntrack 异常期间用户依然可以正常增删改规则，且「API 返回成功」
// 严格等价于「DB 与 nft 一致」。
func (s *Service) sync(ctx context.Context, rules []*forward.Rule) error {
	enabled := make([]*forward.Rule, 0, len(rules))
	for _, r := range rules {
		if r != nil && !r.Deleted && r.Enabled {
			enabled = append(enabled, r)
		}
	}

	cr := s.conntrack(s.ctPath)
	now := s.now()
	ctUsable := cr.Usable()
	s.noteConntrack(cr, !ctUsable)

	// B 层输入：conntrack 可用才建索引；否则本轮完全不碰 slot 状态。
	var idx connection.Index
	if ctUsable {
		// 一次扫描建立 (proto, dport) → flows 索引：复杂度 O(F)。
		// 之后每条规则 O(1) 取出属于自己的流，总体 O(R + F)，
		// 取代旧实现「每条规则遍历全部 flows」的 O(R × F)。
		idx = connection.BuildIndex(cr.Flows)
	}
	selfIPs := map[string]bool{}
	if ctUsable {
		selfIPs = s.selfIPSet(now)
	}

	// 配额实时判定所需的两份数据：
	//   live  = 已落库累计 + 已落库 counter 基线（collector 提供，纯内存）
	//   curSt = 本轮 nft 现状（下面 applyNFT 也要用，读一次共享）
	live := s.live()
	// collector 尚未完成首轮采集时退回 SQLite 口径。此时一次性批量读全部
	// 累计流量（一条 SQL），而不是每条规则各发一次 QueryRow。
	var fallbackTotals map[int64]int64
	if !live.Ready {
		var terr error
		if fallbackTotals, terr = s.allLifetimeBytes(ctx); terr != nil {
			s.setErr(terr.Error())
			return terr
		}
	}
	curSt, err := s.nftReadState(ctx, s.runner)
	if err != nil {
		msg := "读取 nft 状态失败: " + err.Error()
		s.setErr(msg)
		s.mu.Lock()
		s.lastApplyErr = err.Error()
		s.mu.Unlock()
		return err
	}
	counterBytes := map[string]int64{}
	if curSt != nil && curSt.CounterBytes != nil {
		counterBytes = curSt.CounterBytes
	}

	// 本轮见到的 flow key 集合（用于 GC，见 gcFlows）。
	seenFlowKeys := make(map[string]struct{}, len(cr.Flows))

	nftStates := map[int64]*nft.RuleState{}
	newStates := map[int64]*RuleState{}
	quotaBlocked := make([]int64, 0, len(enabled))

	for _, r := range enabled {
		rs := &RuleState{RuleID: r.ID}

		// ---- 配额（A 层：不依赖 conntrack）----
		used, qerr := s.quotaUsed(r, live, counterBytes, fallbackTotals)
		if qerr != nil {
			s.setErr(qerr.Error())
			return qerr
		}
		rs.Quota = RuleQuotaState{RuleID: r.ID, Enabled: r.QuotaEnabled,
			LimitBytes: r.QuotaLimitBytes, UsedBytes: used, State: "unlimited"}
		quotaExceeded := false
		if r.QuotaEnabled {
			rs.Quota.State = "ok"
			if r.QuotaLimitBytes > 0 && used >= r.QuotaLimitBytes {
				rs.Quota.State = "exceeded"
				quotaExceeded = true
				quotaBlocked = append(quotaBlocked, r.ID)
			}
		}

		// ---- IP Slot（B 层：依赖 conntrack）----
		ipState := s.ipStates[r.ID]
		if ipState == nil {
			ipState = newIPState()
			s.ipStates[r.ID] = ipState
		}
		var allowSet map[string]bool
		if ctUsable {
			active, candidates := s.buildActiveCandidates(r, idx, now, selfIPs, seenFlowKeys)
			maxIPs := 0
			if r.IPLimitEnabled {
				maxIPs = r.IPLimitMax
			}
			allowSet, _ = ipState.Reconcile(active, candidates, maxIPs, now,
				s.ipIdle, s.udpIdle, s.rejectedTTL, s.provisionalTTL)
			rs.IPs = s.snapshotIPs(r.ID, ipState)
		} else {
			// 冻结：allow set 用上一轮 slot 原样重放，绝不清空。
			allowSet = ipState.AllowSet()
			rs.IPs = s.snapshotIPs(r.ID, ipState)
			rs.IPs.Frozen = true
		}
		rs.ConnTCP, rs.ConnUDP = countSessions(ipState)

		nftStates[r.ID] = &nft.RuleState{
			QuotaExceeded:  quotaExceeded,
			IPLimitEnabled: r.IPLimitEnabled,
			AllowV4:        splitV4(allowSet),
			AllowV6:        splitV6(allowSet),
		}
		newStates[r.ID] = rs
	}

	// 清理已删除/停用规则的内存状态（与 conntrack 可用性无关）。
	live4 := make(map[int64]bool, len(enabled))
	for _, r := range enabled {
		live4[r.ID] = true
	}
	for id := range s.ipStates {
		if !live4[id] {
			delete(s.ipStates, id)
			delete(s.states, id)
			s.dropFlowsOf(id)
		}
	}
	// flow GC：只有 conntrack 本轮可信时才据「本轮未见到」回收，
	// 否则读取不完整会把仍活跃的流误删（下一轮又被当成新流，判活失效）。
	if ctUsable {
		s.gcFlows(seenFlowKeys, live4)
	}

	// ---- A 层：结构 + 元素同步（无论 conntrack 如何都必须执行）----
	gi := &nft.GenInput{Rules: enabled, States: nftStates}
	if err := s.applyNFT(ctx, gi, quotaBlocked, curSt); err != nil {
		msg := "nft 应用失败: " + err.Error()
		s.setErr(msg)
		s.mu.Lock()
		s.lastApplyErr = err.Error()
		s.mu.Unlock()
		return err
	}

	nowSec := now.Unix()
	s.mu.Lock()
	s.states = newStates
	s.ready = true
	s.lastApplyErr = ""
	s.lastApplyOK = nowSec
	s.lastReconcileOK = nowSec
	if ctUsable {
		s.lastErr = ""
	} else {
		// 结构同步成功但在线 IP 冻结：如实反映，不假装一切正常。
		s.lastErr = cr.Note()
	}
	s.mu.Unlock()
	return nil
}

// quotaUsed 计算某规则的**实时**已用流量。
//
//	used = (已落库累计 + 未落库增量) - 配额重置基线
//
// 未落库增量来自「本轮 nft counter 读数 - collector 已落库的 counter 基线」，
// 因此高带宽下不会因为 SQLite 刷盘间隔（默认 2s）而严重超额。
// collector 尚未完成首轮采集（live.Ready==false）时退回 SQLite 口径，
// 用调用方一次性批量读出的 fallbackTotals（不做 per-rule 查询）。
func (s *Service) quotaUsed(r *forward.Rule, live traffic.LiveDelta,
	counterBytes map[string]int64, fallbackTotals map[int64]int64) (int64, error) {
	var total int64
	if live.Ready {
		total = live.Used(r.ID, counterBytes)
	} else {
		total = fallbackTotals[r.ID]
	}
	used := total - r.QuotaResetBaseline
	if used < 0 {
		used = 0
	}
	return used, nil
}

// allLifetimeBytes 一次读出所有规则的累计流量（upload+download）。
//
// 只在 collector 首轮采集完成之前使用；正常运行期配额走 traffic.LiveDelta，
// 完全不查库。
func (s *Service) allLifetimeBytes(ctx context.Context) (map[int64]int64, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT rule_id,upload_bytes,download_bytes FROM traffic_totals")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]int64{}
	for rows.Next() {
		var id int64
		var up, down sql.NullInt64
		if err := rows.Scan(&id, &up, &down); err != nil {
			return nil, err
		}
		out[id] = up.Int64 + down.Int64
	}
	return out, rows.Err()
}

// noteConntrack 记录 conntrack 可用性，并在状态翻转时提示一次（避免每秒刷屏）。
func (s *Service) noteConntrack(cr connection.Result, frozen bool) {
	if cr.Inactive != s.ctInactive {
		if cr.Inactive {
			slog.Warn("conntrack 已加载但未跟踪任何连接（缺少引用 ct 的 netfilter 规则），" +
				"在线 IP 判活暂不可用；应用一次转发规则即可激活")
		} else {
			slog.Info("conntrack 已恢复跟踪，在线 IP 判活回到 conntrack 口径")
		}
		s.ctInactive = cr.Inactive
	}
	s.mu.Lock()
	wasFrozen := s.ipFrozen
	s.ctOK = cr.Usable()
	s.ctNote = cr.Note()
	s.ipFrozen = frozen
	s.mu.Unlock()
	if frozen != wasFrozen {
		if frozen {
			slog.Warn("conntrack 不可用，已冻结在线 IP 状态（不新增、不释放 slot）；" +
				"规则/配额/nft 结构同步照常执行")
		} else {
			slog.Info("conntrack 恢复，在线 IP 状态解除冻结")
		}
	}
}

// selfIPSet 返回本机地址集合（带 TTL 缓存）。
func (s *Service) selfIPSet(now time.Time) map[string]bool {
	if s.selfIPs != nil && now.Sub(s.selfIPsAt) < selfIPsTTL {
		return s.selfIPs
	}
	if s.localIPs == nil {
		return map[string]bool{}
	}
	ips, err := s.localIPs()
	if err != nil {
		slog.Debug("读取本机地址失败，保留上次快照", "err", err)
		if s.selfIPs != nil {
			return s.selfIPs
		}
		return map[string]bool{}
	}
	s.selfIPs = ips
	s.selfIPsAt = now
	return ips
}

// buildActiveCandidates 从索引里取出属于某规则的流，拆成 active（判活）与 candidate。
//
// 复杂度：只取自己 (proto, listenPort) 的分桶 —— 不再遍历全部 conntrack。
// 规则的协议决定查哪几个桶：tcp / udp / tcp+udp。
//
// 判活规则（按协议区分，因为 UDP 没有连接状态）：
//   - TCP ESTABLISHED：字节有增量=活跃；字节不变但在 ipIdle 内=仍在线（半开）；
//     超窗无流量=死连接，剔除。conntrack 里流消失则立即离线。
//   - TCP SYN_SENT/SYN_RECV：candidate（握手中，尚未建立）。
//   - UDP：无状态，只能按 udpIdle 空闲窗口判活（无流量超窗即离线）。
//
// selfIPs 里的源地址一律跳过：那是服务器自身发起的出站连接，
// 目的端口可能恰好等于某规则监听端口（443/80 极常见），不能算客户端。
//
// seenFlowKeys 收集本轮出现过的流键，供 flow GC 使用（同一次扫描内完成，
// 不需要为 GC 再遍历一遍 conntrack）。
func (s *Service) buildActiveCandidates(r *forward.Rule, idx connection.Index,
	now time.Time, selfIPs map[string]bool, seenFlowKeys map[string]struct{}) (
	active, candidates map[string]IPActivity) {
	active = map[string]IPActivity{}
	candidates = map[string]IPActivity{}

	protos := make([]string, 0, 2)
	if r.HasTCP() {
		protos = append(protos, "tcp")
	}
	if r.HasUDP() {
		protos = append(protos, "udp")
	}

	for _, proto := range protos {
		for _, f := range idx.Get(proto, r.ListenPort) {
			if selfIPs[f.SrcIP] {
				continue // 服务器自己发起的连接，不是客户端
			}
			fkey := flowKey(r.ID, f)
			seenFlowKeys[fkey] = struct{}{}
			switch {
			case f.Proto == "tcp" && (f.State == "SYN_SENT" || f.State == "SYN_RECV"):
				a := candidates[f.SrcIP]
				a.IP = f.SrcIP
				a.TCPSessions++
				candidates[f.SrcIP] = a
			case f.Proto == "tcp" && f.State == "ESTABLISHED", f.Proto == "udp":
				idle := s.ipIdle
				if f.Proto == "udp" {
					idle = s.udpIdle
				}
				hasTraffic, alive := s.touchFlow(fkey, f, now, idle)
				if !alive {
					continue
				}
				a := active[f.SrcIP]
				a.IP = f.SrcIP
				if f.Proto == "tcp" {
					a.TCPSessions++
				} else {
					a.UDPSessions++
				}
				if hasTraffic {
					a.Traffic = true
				}
				active[f.SrcIP] = a
			}
		}
	}
	return active, candidates
}

// flowKey 是单条流在 flows map 中的键。
func flowKey(ruleID int64, f connection.Flow) string {
	return strconv.FormatInt(ruleID, 10) + "\x00" + f.Proto + "\x00" + f.SrcIP + ":" + strconv.Itoa(f.SrcPort)
}

// touchFlow 更新单条流的字节水位，返回「本轮是否有流量」与「是否仍判活」。
//
// 与旧实现的关键差别：超窗时**不删除** entry（删除会让下一轮把同一条流当成
// 首次见到，从而误判为有流量、永远不离线）。entry 的回收统一交给 gcFlows。
func (s *Service) touchFlow(fkey string, f connection.Flow, now time.Time, idle time.Duration) (hasTraffic, alive bool) {
	prev := s.flows[fkey]
	if prev == nil {
		s.flows[fkey] = &flowState{Bytes: f.Bytes, LastChange: now, LastSeen: now}
		return true, true
	}
	prev.LastSeen = now
	if f.Bytes != prev.Bytes {
		// 字节变化即活跃（可能因四元组复用而变小，故用 != 而非 >）。
		prev.Bytes = f.Bytes
		prev.LastChange = now
		return true, true
	}
	if now.Sub(prev.LastChange) <= idle {
		return false, true // 静默但在窗口内
	}
	return false, false // 超窗无流量 → 视为死连接（entry 由 GC 统一回收）
}

// gcFlows 回收「本轮 conntrack 中已不存在」的流状态。
//
// 这是 flowState 不再无界增长的保证：短连接结束后其 conntrack 条目消失，
// 本轮 seenFlowKeys 里就没有它，立即删除。规则被删的流由 dropFlowsOf 处理，
// 这里再兜一层（防止残留 rule 前缀）。
func (s *Service) gcFlows(seen map[string]struct{}, liveRules map[int64]bool) {
	for k := range s.flows {
		if _, ok := seen[k]; ok {
			continue
		}
		delete(s.flows, k)
	}
	// 兜底：规则已消失但键仍在（正常路径下 dropFlowsOf 已处理）。
	for k := range s.flows {
		id, ok := ruleIDOfFlowKey(k)
		if !ok || !liveRules[id] {
			delete(s.flows, k)
		}
	}
}

// ruleIDOfFlowKey 从流键里解析规则 ID。
func ruleIDOfFlowKey(k string) (int64, bool) {
	i := strings.IndexByte(k, 0)
	if i <= 0 {
		return 0, false
	}
	id, err := strconv.ParseInt(k[:i], 10, 64)
	if err != nil {
		return 0, false
	}
	return id, true
}

// FlowStateLen 返回当前流跟踪表大小（仅供测试与诊断）。
func (s *Service) FlowStateLen() int {
	s.runMu.Lock()
	defer s.runMu.Unlock()
	return len(s.flows)
}

// dropFlowsOf 清理某规则的流跟踪状态（规则删除后避免内存泄漏）。
func (s *Service) dropFlowsOf(ruleID int64) {
	prefix := strconv.FormatInt(ruleID, 10) + "\x00"
	for k := range s.flows {
		if strings.HasPrefix(k, prefix) {
			delete(s.flows, k)
		}
	}
}

// applyNFT 是 nft 同步的核心：结构变化或自有对象缺失才重写链，否则只做元素增量。
//
// 这是流量统计正确性的关键：named counter 是表级对象，重写结构（哪怕只是
// flush chain）本身不清零 counter，但 **重建表** 会。因此：
//   - 结构签名未变且期望对象齐全 → 只 `add/delete element`，完全不碰表、链、counter；
//   - 结构签名变化或有对象缺失   → 幂等 add 表/链/counter/set + flush chain 重建规则，
//     已存在的 counter 保留累计值。
//
// ★ 自愈判定（v0.3.1 收口）：不再只看 FilterTableExists + up counter + v4 set，
// 而是与 nft.DesiredObjects 做完整比对 —— 表（含 nff_nat4/nff_nat6/nff_filter）、
// 链、marks/qblock/allow set、每条规则的 up+down counter、各链最小规则条数。
// 任何一项缺失都触发重建，因此「人为删表/删链/删 counter/删 set」都能自动恢复。
//
// cur 由调用方传入（sync 已读过一次），避免同一轮重复执行 `nft -j list ruleset`。
func (s *Service) applyNFT(ctx context.Context, gi *nft.GenInput, quotaBlocked []int64, cur *nft.State) error {
	var err error
	if cur == nil {
		if cur, err = s.nftReadState(ctx, s.runner); err != nil {
			return err
		}
	}

	sig := nft.StructSig(gi)
	desired := nft.DesiredObjects(gi)
	missing := nft.MissingObjects(cur, desired)

	if sig != s.lastStructSig || len(missing) > 0 {
		if len(missing) > 0 && sig == s.lastStructSig {
			// 结构签名没变却缺对象 = 被外部删除，属于真正的自愈事件，记一条日志。
			desc := nft.DescribeMissing(missing)
			slog.Warn("检测到自有 nft 对象缺失，正在自动重建", "missing", desc)
			s.mu.Lock()
			s.lastHealMissing = desc
			s.mu.Unlock()
		}
		script := nft.GenStructScript(gi, cur.Existing())
		if err := s.nftApply(ctx, s.runner, s.nftConf, script); err != nil {
			return err
		}
		s.lastStructSig = sig
		if len(missing) > 0 {
			s.mu.Lock()
			s.lastHealOK = s.now().Unix()
			s.mu.Unlock()
		}
		// 结构重建后 set 元素可能被清空（新表），重新读一次现状
		// 以便下面的增量以真实状态为基准。
		if cur, err = s.nftReadState(ctx, s.runner); err != nil {
			return err
		}
	}

	// 元素增量：配额阻断 + 每规则 allow set。
	diffs := []nft.ElementDiff{nft.QuotaBlockDiff(cur.QuotaBlocked, quotaBlocked)}
	for _, r := range gi.Rules {
		if r.Deleted || !r.Enabled {
			continue
		}
		st := gi.States[r.ID]
		if st == nil || !st.IPLimitEnabled {
			continue
		}
		diffs = append(diffs,
			nft.AllowDiff(r.ID, false, cur.ElementsOf(nft.AllowSetV4(r.ID)), st.AllowV4),
			nft.AllowDiff(r.ID, true, cur.ElementsOf(nft.AllowSetV6(r.ID)), st.AllowV6),
		)
	}
	// 无变化时脚本为空 → 完全不调用 nft。
	elemScript := nft.GenElementScript(diffs)
	if elemScript == "" {
		return nil
	}
	return s.nftApply(ctx, s.runner, s.nftConf+".elem", elemScript)
}

// countSessions 统计某规则当前的 TCP 连接数与 UDP 会话数（仅已授权 IP）。
func countSessions(st *NodeIPState) (tcp, udp int) {
	for ip, slot := range st.Slots {
		if slot.Provisional {
			continue
		}
		if o, ok := st.Observed[ip]; ok {
			tcp += o.TCPSessions
			udp += o.UDPSessions
		}
	}
	return tcp, udp
}

func (s *Service) snapshotIPs(ruleID int64, st *NodeIPState) RuleIPSnapshot {
	snap := RuleIPSnapshot{
		RuleID:       ruleID,
		Limited:      st.MaxIPs > 0,
		MaxIPs:       st.MaxIPs,
		GrantedCount: st.activeGrantedCount(),
		IPs:          []IPEntry{},
		Rejected:     []IPEntry{},
	}
	for ip, slot := range st.Slots {
		if slot.Provisional {
			continue
		}
		e := IPEntry{IP: ip, Granted: true}
		if o, ok := st.Observed[ip]; ok {
			e.TCP = o.TCPSessions
			e.UDP = o.UDPSessions
		}
		snap.IPs = append(snap.IPs, e)
	}
	for ip := range st.Rejected {
		e := IPEntry{IP: ip, Granted: false}
		if o, ok := st.Observed[ip]; ok {
			e.TCP = o.TCPSessions
			e.UDP = o.UDPSessions
		}
		snap.Rejected = append(snap.Rejected, e)
	}
	return snap
}

func (s *Service) setErr(msg string) {
	s.mu.Lock()
	s.lastErr = msg
	s.mu.Unlock()
}

func splitV4(set map[string]bool) []string {
	var out []string
	for ip := range set {
		if isV4(ip) {
			out = append(out, ip)
		}
	}
	return out
}

func splitV6(set map[string]bool) []string {
	var out []string
	for ip := range set {
		if !isV4(ip) {
			out = append(out, ip)
		}
	}
	return out
}

func isV4(ip string) bool {
	for i := 0; i < len(ip); i++ {
		if ip[i] == ':' {
			return false
		}
	}
	return true
}
