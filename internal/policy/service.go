// Package policy 编排「连接观测 → IP Slot 准入 → 配额判定 → nft 强制」。
//
// 设计原则：
//   - 在线 IP 以真实连接生命周期为依据（conntrack 主、/proc 仅在不可用时回退）；
//   - allow set 的权威来源只能是 Granted slot，绝不让「观察到」直接进 allow set；
//   - nft 应用事务化（先 -c -f 检查，通过后 -f 应用），失败不落库成成功状态。
package policy

import (
	"context"
	"database/sql"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/k6nfmm7dbr-commits/nft-forward/internal/connection"
	"github.com/k6nfmm7dbr-commits/nft-forward/internal/forward"
	"github.com/k6nfmm7dbr-commits/nft-forward/internal/nft"
)

// 默认超时（可由 setter 覆盖，测试用）。
const (
	defaultIPIdle         = 60 * time.Second // 半开连接无流量判活窗口
	defaultUDPIdle        = 120 * time.Second
	defaultRejectedTTL    = 60 * time.Second
	defaultProvisionalTTL = 10 * time.Second
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

// flowState 跟踪单条流的字节（判活用）。
type flowState struct {
	Bytes    int64
	LastSeen time.Time
}

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

	runMu sync.Mutex
	mu    sync.RWMutex

	ipStates map[int64]*NodeIPState
	flows    map[string]*flowState // "ruleID\x00ip:sport" -> 字节
	states   map[int64]*RuleState
	ready    bool
	lastErr  string

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
func (s *Service) SetIPIdle(d time.Duration)                           { s.ipIdle = d }
func (s *Service) SetUDPIdle(d time.Duration)                          { s.udpIdle = d }
func (s *Service) SetRejectedTTL(d time.Duration)                      { s.rejectedTTL = d }
func (s *Service) SetProvisionalTTL(d time.Duration)                   { s.provisionalTTL = d }

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

// buildActiveCandidates 从 conntrack 流里拆出某规则的 active（判活）与 candidate。
//
// 判活规则（按协议区分，因为 UDP 没有连接状态）：
//   - TCP ESTABLISHED：字节有增量=活跃；字节不变但在 ipIdle 内=仍在线（半开）；
//     超窗无流量=死连接，剔除。conntrack 里流消失则立即离线。
//   - TCP SYN_SENT/SYN_RECV：candidate（握手中，尚未建立）。
//   - UDP：无状态，只能按 udpIdle 空闲窗口判活（无流量超窗即离线）。
func (s *Service) buildActiveCandidates(ruleID int64, flows []connection.Flow, listenPort int, now time.Time) (map[string]IPActivity, map[string]IPActivity) {
	active := map[string]IPActivity{}
	candidates := map[string]IPActivity{}
	for _, f := range flows {
		if f.OrigDstPort != listenPort {
			continue
		}
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
			traffic, alive := s.touchFlow(ruleID, f, now, idle)
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
			if traffic {
				a.Traffic = true
			}
			active[f.SrcIP] = a
		}
	}
	return active, candidates
}

// touchFlow 更新单条流的字节水位，返回「本轮是否有流量」与「是否仍判活」。
func (s *Service) touchFlow(ruleID int64, f connection.Flow, now time.Time, idle time.Duration) (traffic, alive bool) {
	fkey := strconv.FormatInt(ruleID, 10) + "\x00" + f.Proto + "\x00" + f.SrcIP + ":" + strconv.Itoa(f.SrcPort)
	prev := s.flows[fkey]
	switch {
	case prev == nil:
		s.flows[fkey] = &flowState{Bytes: f.Bytes, LastSeen: now}
		return true, true
	case f.Bytes != prev.Bytes:
		// 字节变化即活跃（可能因四元组复用而变小，故用 != 而非 >）。
		s.flows[fkey] = &flowState{Bytes: f.Bytes, LastSeen: now}
		return true, true
	case now.Sub(prev.LastSeen) <= idle:
		return false, true // 静默但在窗口内
	default:
		delete(s.flows, fkey) // 超窗无流量 → 死连接
		return false, false
	}
}

// Reconcile 执行一轮：观测 → slot 准入 → 配额判定 → nft 强制 → 落库状态。
func (s *Service) Reconcile(ctx context.Context) error { return s.reconcile(ctx) }

func (s *Service) reconcile(ctx context.Context) error {
	s.runMu.Lock()
	defer s.runMu.Unlock()

	rules, err := s.store.ListActive(ctx)
	if err != nil {
		s.setErr(err.Error())
		return err
	}
	enabled := make([]*forward.Rule, 0, len(rules))
	for _, r := range rules {
		if r.Enabled {
			enabled = append(enabled, r)
		}
	}

	cr := s.conntrack(s.ctPath)
	now := s.now()

	// conntrack 读取不完整时进入 fail-safe：沿用上一轮 slot，不释放、不新授、
	// 不改动 nft。宁可短暂放行也不误踢在线用户（SBX 的教训）。
	if cr.Partial || (cr.Err != nil && !cr.Available) {
		s.setErr("conntrack 读取不完整，本轮跳过准入（fail-safe）")
		return nil
	}

	nftStates := map[int64]*nft.RuleState{}
	newStates := map[int64]*RuleState{}
	quotaBlocked := make([]int64, 0, len(enabled))

	for _, r := range enabled {
		rs := &RuleState{RuleID: r.ID}

		// 配额
		life, err := s.lifetimeBytes(ctx, r.ID)
		if err != nil {
			s.setErr(err.Error())
			return err
		}
		used := life - r.QuotaResetBaseline
		if used < 0 {
			used = 0
		}
		rs.Quota = RuleQuotaState{RuleID: r.ID, Enabled: r.QuotaEnabled, LimitBytes: r.QuotaLimitBytes, UsedBytes: used, State: "unlimited"}
		quotaExceeded := false
		if r.QuotaEnabled {
			rs.Quota.State = "ok"
			if r.QuotaLimitBytes > 0 && used >= r.QuotaLimitBytes {
				rs.Quota.State = "exceeded"
				quotaExceeded = true
				quotaBlocked = append(quotaBlocked, r.ID)
			}
		}

		// IP 状态
		ipState := s.ipStates[r.ID]
		if ipState == nil {
			ipState = newIPState()
			s.ipStates[r.ID] = ipState
		}
		var active, candidates map[string]IPActivity
		if cr.Available {
			active, candidates = s.buildActiveCandidates(r.ID, cr.Flows, r.ListenPort, now)
		} else {
			active, candidates = map[string]IPActivity{}, map[string]IPActivity{}
		}

		maxIPs := 0
		if r.IPLimitEnabled {
			maxIPs = r.IPLimitMax
		}
		allowSet, _ := ipState.Reconcile(active, candidates, maxIPs, now, s.ipIdle, s.udpIdle, s.rejectedTTL, s.provisionalTTL)

		rs.IPs = s.snapshotIPs(r.ID, ipState)
		rs.ConnTCP, rs.ConnUDP = countSessions(ipState)

		nftStates[r.ID] = &nft.RuleState{
			QuotaExceeded:  quotaExceeded,
			IPLimitEnabled: r.IPLimitEnabled,
			AllowV4:        splitV4(allowSet),
			AllowV6:        splitV6(allowSet),
		}
		newStates[r.ID] = rs
	}

	// 清理已删除规则的内存状态。
	for id := range s.ipStates {
		found := false
		for _, r := range enabled {
			if r.ID == id {
				found = true
				break
			}
		}
		if !found {
			delete(s.ipStates, id)
			delete(s.states, id)
			s.dropFlowsOf(id)
		}
	}

	gi := &nft.GenInput{Rules: enabled, States: nftStates}
	if err := s.applyNFT(ctx, gi, quotaBlocked); err != nil {
		s.setErr("nft 应用失败: " + err.Error())
		return err
	}

	s.mu.Lock()
	s.states = newStates
	s.ready = true
	s.lastErr = ""
	s.mu.Unlock()
	return nil
}

// applyNFT 是 nft 同步的核心：结构变化才重写链，否则只做元素增量。
//
// 这是流量统计正确性的关键：named counter 是表级对象，重写结构（哪怕只是
// flush chain）本身不清零 counter，但 **重建表** 会。因此：
//   - 结构签名未变 → 只 `add/delete element`，完全不碰表、链、counter；
//   - 结构签名变化 → 幂等 add 表/counter/set + flush chain 重建规则，
//     已存在的 counter 保留累计值。
func (s *Service) applyNFT(ctx context.Context, gi *nft.GenInput, quotaBlocked []int64) error {
	cur, err := s.nftReadState(ctx, s.runner)
	if err != nil {
		return err
	}

	sig := nft.StructSig(gi)
	structMissing := !cur.FilterTableExists
	if !structMissing {
		// counter / allow set 被外部删掉时也必须重建。
		for _, want := range wantedObjects(gi) {
			if !contains(cur.Counters, want.counter) && want.counter != "" {
				structMissing = true
				break
			}
			if want.setV4 != "" && !contains(cur.Sets, want.setV4) {
				structMissing = true
				break
			}
		}
	}

	if sig != s.lastStructSig || structMissing {
		script := nft.GenStructScript(gi, cur.Existing())
		if err := s.nftApply(ctx, s.runner, s.nftConf, script); err != nil {
			return err
		}
		s.lastStructSig = sig
		// 结构重建后 set 元素被清空（qblock/allow 都是新表），重新读一次现状
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

type wantedObj struct {
	counter string
	setV4   string
}

func wantedObjects(gi *nft.GenInput) []wantedObj {
	var out []wantedObj
	for _, r := range gi.Rules {
		if r.Deleted || !r.Enabled {
			continue
		}
		w := wantedObj{counter: nft.CounterUp(r.ID)}
		if st := gi.States[r.ID]; st != nil && st.IPLimitEnabled {
			w.setV4 = nft.AllowSetV4(r.ID)
		}
		out = append(out, w)
	}
	return out
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
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
