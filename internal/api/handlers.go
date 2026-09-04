package api

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/k6nfmm7dbr-commits/nft-forward/internal/forward"
	"github.com/k6nfmm7dbr-commits/nft-forward/internal/nft"
	"github.com/k6nfmm7dbr-commits/nft-forward/internal/policy"
	"github.com/k6nfmm7dbr-commits/nft-forward/internal/traffic"
	"github.com/k6nfmm7dbr-commits/nft-forward/internal/version"
)

// RuleView 是规则的完整视图（供列表/详情）。
//
// 内嵌 forward.Rule 后自动获得 target_address / listen_port / resolve_* 等字段；
// 转发规则已无监听地址字段，因此响应里不会出现 listen_address。
// ListenAddr 为展示用字段：所有规则均由 fib daddr type local 限定，
// 实际监听本机所有本地地址，展示为 0.0.0.0。
type RuleView struct {
	forward.Rule
	Status     string                 `json:"status"` // normal/disabled/quota_exceeded/ip_limited/dns_failed
	TargetTxt  string                 `json:"target_text"`
	ListenAddr string                 `json:"listen_addr"` // 展示用：0.0.0.0
	Rate       traffic.Rate           `json:"rate"`
	TotalUp    int64                  `json:"total_up"`
	TotalDown  int64                  `json:"total_down"`
	TodayUp    int64                  `json:"today_up"`
	TodayDown  int64                  `json:"today_down"`
	ActiveIPs  int                    `json:"active_ip_count"`
	ConnTCP    int                    `json:"conn_tcp"`
	ConnUDP    int                    `json:"conn_udp"`
	Quota      *policy.RuleQuotaState `json:"quota,omitempty"`
	IPs        *policy.RuleIPSnapshot `json:"ips,omitempty"`
}

// FullSnapshot 是 SSE 首包 / summary 的完整快照。
type FullSnapshot struct {
	Now       int64        `json:"now"`
	TotalUp   int64        `json:"total_up"`
	TotalDown int64        `json:"total_down"`
	TodayUp   int64        `json:"today_up"`
	TodayDown int64        `json:"today_down"`
	Rate      traffic.Rate `json:"rate"`
	ConnTCP   int          `json:"conn_tcp"`
	ConnUDP   int          `json:"conn_udp"`
	Rules     []RuleView   `json:"rules"`
}

// buildFullSnapshot 构建全量快照。
func (s *Server) buildFullSnapshot() FullSnapshot {
	ctx := context.Background()
	rules, _ := s.store.ListActive(ctx)
	polStates := s.policy.States()
	collectStatus := s.collect.Snapshot()

	snap := FullSnapshot{Now: collectStatus.LastOK, Rules: []RuleView{}}
	today := ""
	if collectStatus.LastOK > 0 {
		today = time.Unix(collectStatus.LastOK, 0).In(s.collect.Location()).Format("2006-01-02")
	}

	for _, r := range rules {
		v := RuleView{Rule: *r}
		v.Status = ruleStatus(r, polStates[r.ID])
		v.TargetTxt = forward.FormatHostPort(r.TargetAddress, r.TargetPort)
		v.ListenAddr = "0.0.0.0"
		if rate, ok := collectStatus.Rates[r.ID]; ok {
			v.Rate = rate
		}
		v.TotalUp, v.TotalDown = s.totals(ctx, r.ID)
		v.TodayUp, v.TodayDown = s.dailyFor(ctx, r.ID, today)
		if ps, ok := polStates[r.ID]; ok {
			v.ActiveIPs = ps.IPs.GrantedCount
			v.ConnTCP = ps.ConnTCP
			v.ConnUDP = ps.ConnUDP
			q := ps.Quota
			v.Quota = &q
			ip := ps.IPs
			v.IPs = &ip
		}
		snap.TotalUp += v.TotalUp
		snap.TotalDown += v.TotalDown
		snap.TodayUp += v.TodayUp
		snap.TodayDown += v.TodayDown
		snap.Rate.Upload += v.Rate.Upload
		snap.Rate.Download += v.Rate.Download
		snap.ConnTCP += v.ConnTCP
		snap.ConnUDP += v.ConnUDP
		snap.Rules = append(snap.Rules, v)
	}
	return snap
}

func ruleStatus(r *forward.Rule, ps *policy.RuleState) string {
	if !r.Enabled {
		return "disabled"
	}
	// 域名解析彻底失败（连历史地址都没有）→ 规则当前无数据面，必须显式暴露。
	if r.IsDomainTarget() && !r.Resolvable() {
		return "dns_failed"
	}
	if ps == nil {
		return "normal"
	}
	if ps.Quota.State == "exceeded" {
		return "quota_exceeded"
	}
	if r.IPLimitEnabled && len(ps.IPs.Rejected) > 0 {
		return "ip_limited"
	}
	// DNS 临时失败但仍在用上次有效地址：转发正常，单独标记以便 UI 提示。
	if r.IsDomainTarget() && r.ResolveStatus == forward.ResolveStale {
		return "dns_stale"
	}
	return "normal"
}

func (s *Server) totals(ctx context.Context, ruleID int64) (int64, int64) {
	var up, down int64
	_ = s.db.QueryRowContext(ctx, "SELECT upload_bytes,download_bytes FROM traffic_totals WHERE rule_id=?", ruleID).Scan(&up, &down)
	return up, down
}

func (s *Server) dailyFor(ctx context.Context, ruleID int64, day string) (int64, int64) {
	if day == "" {
		return 0, 0
	}
	var up, down int64
	_ = s.db.QueryRowContext(ctx, "SELECT upload_bytes,download_bytes FROM traffic_daily WHERE rule_id=? AND day=?", ruleID, day).Scan(&up, &down)
	return up, down
}

// ---- 健康检查 ----

// HealthView 是 /api/health 的响应。刻意不含 token、监听地址、文件路径等
// 敏感配置，只反映各子系统的存活与最近成功时间。
type HealthView struct {
	OK        bool   `json:"ok"`
	Version   string `json:"version"`
	UptimeSec int64  `json:"uptime_sec"`

	DBOK    bool   `json:"db_ok"`
	DBError string `json:"db_error,omitempty"`

	NftOK    bool   `json:"nft_ok"`
	NftError string `json:"nft_error,omitempty"`

	CollectorLastOK int64  `json:"collector_last_ok,omitempty"`
	CollectorError  string `json:"collector_error,omitempty"`

	PolicyReady        bool   `json:"policy_ready"`
	PolicyLastOK       int64  `json:"policy_last_ok,omitempty"`
	PolicyError        string `json:"policy_error,omitempty"`
	NftLastApplyOK     int64  `json:"nft_last_apply_ok,omitempty"`
	NftLastApplyError  string `json:"nft_last_apply_error,omitempty"`
	ConntrackOK        bool   `json:"conntrack_ok"`
	ConntrackNote      string `json:"conntrack_note,omitempty"`
	DNSLastOK          int64  `json:"dns_last_ok,omitempty"`
	DNSError           string `json:"dns_error,omitempty"`
	DNSDomainRules     int    `json:"dns_domain_rules"`
	DNSUnresolvedRules int    `json:"dns_unresolved_rules"`

	Rules        int `json:"rules"`
	RulesEnabled int `json:"rules_enabled"`
}

// DNSHealth 由 service 层注入（DNS worker 的最近状态）。
type DNSHealth struct {
	LastOK int64
	Err    string
}

// SetDNSHealth 更新 DNS worker 健康状态。
func (s *Server) SetDNSHealth(h DNSHealth) {
	s.dnsMu.Lock()
	s.dnsHealth = h
	s.dnsMu.Unlock()
}

func (s *Server) buildHealth() HealthView {
	ctx := context.Background()
	hv := HealthView{
		Version:   version.Version,
		UptimeSec: int64(time.Since(s.started).Seconds()),
	}
	// SQLite：一次极轻量查询确认可读写。
	if err := s.db.PingContext(ctx); err != nil {
		hv.DBError = err.Error()
	} else if _, err := s.db.ExecContext(ctx,
		"INSERT INTO meta(k,v) VALUES('health_probe',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
		strconv.FormatInt(time.Now().Unix(), 10)); err != nil {
		hv.DBError = err.Error()
	} else {
		hv.DBOK = true
	}

	// nft 命令可用性（只读探测，不改任何规则）。
	if _, _, stderr, err := (nft.ExecRunner{}).Run(ctx, "nft", "list", "tables"); err != nil {
		hv.NftError = err.Error()
	} else if strings.TrimSpace(stderr) != "" {
		hv.NftError = strings.TrimSpace(stderr)
	} else {
		hv.NftOK = true
	}

	cs := s.collect.Snapshot()
	hv.CollectorLastOK = cs.LastOK
	hv.CollectorError = cs.Error

	ph := s.policy.HealthSnapshot()
	hv.PolicyReady = ph.Ready
	hv.PolicyLastOK = ph.LastReconcileOK
	hv.PolicyError = ph.LastError
	hv.NftLastApplyOK = ph.LastApplyOK
	hv.NftLastApplyError = ph.LastApplyError
	hv.ConntrackOK = ph.ConntrackOK
	hv.ConntrackNote = ph.ConntrackNote

	s.dnsMu.Lock()
	hv.DNSLastOK = s.dnsHealth.LastOK
	hv.DNSError = s.dnsHealth.Err
	s.dnsMu.Unlock()

	rules, err := s.store.ListActive(ctx)
	if err == nil {
		hv.Rules = len(rules)
		for _, r := range rules {
			if r.Enabled {
				hv.RulesEnabled++
			}
			if r.IsDomainTarget() {
				hv.DNSDomainRules++
				if !r.Resolvable() {
					hv.DNSUnresolvedRules++
				}
			}
		}
	}
	hv.OK = hv.DBOK && hv.NftOK && hv.PolicyReady && hv.NftLastApplyError == ""
	return hv
}

// ---- GET ----

func (s *Server) handleAPIGet(w http.ResponseWriter, r *http.Request, route string) {
	if !s.authorized(r) {
		s.sendJSON(w, r, http.StatusUnauthorized, M{"error": "unauthorized"})
		return
	}
	switch {
	case route == "/api/healthz":
		s.sendJSON(w, r, http.StatusOK, M{"ok": true})
	case route == "/api/health":
		s.sendJSON(w, r, http.StatusOK, s.buildHealth())
	case route == "/api/events":
		s.handleEvents(w, r)
	case route == "/api/summary":
		s.sendJSON(w, r, http.StatusOK, s.buildFullSnapshot())
	case route == "/api/live":
		s.sendJSON(w, r, http.StatusOK, s.buildLive())
	case route == "/api/daily":
		s.handleDaily(w, r, 0)
	case route == "/api/rules":
		s.sendJSON(w, r, http.StatusOK, s.buildFullSnapshot().Rules)
	default:
		s.handleRuleSubGet(w, r, route)
	}
}

// LiveView 是轻量实时视图（2s 刷新）。
type LiveView struct {
	Now      int64      `json:"now"`
	RateUp   float64    `json:"rate_up"`
	RateDown float64    `json:"rate_down"`
	ConnTCP  int        `json:"conn_tcp"`
	ConnUDP  int        `json:"conn_udp"`
	Rules    []LiveRule `json:"rules"`
}

type LiveRule struct {
	ID        int64   `json:"id"`
	RateUp    float64 `json:"rate_up"`
	RateDown  float64 `json:"rate_down"`
	ActiveIPs int     `json:"active_ip_count"`
	MaxIPs    int     `json:"max_ips"`
	Limited   bool    `json:"ip_limited"`
	ConnTCP   int     `json:"conn_tcp"`
	ConnUDP   int     `json:"conn_udp"`
	Status    string  `json:"status"`
}

func (s *Server) buildLive() LiveView {
	ctx := context.Background()
	rules, _ := s.store.ListActive(ctx)
	polStates := s.policy.States()
	cs := s.collect.Snapshot()
	lv := LiveView{Now: cs.LastOK, Rules: []LiveRule{}}
	for _, r := range rules {
		lr := LiveRule{ID: r.ID, Status: ruleStatus(r, polStates[r.ID])}
		if rate, ok := cs.Rates[r.ID]; ok {
			lr.RateUp = rate.Upload
			lr.RateDown = rate.Download
		}
		if ps, ok := polStates[r.ID]; ok {
			lr.ActiveIPs = ps.IPs.GrantedCount
			lr.MaxIPs = ps.IPs.MaxIPs
			lr.Limited = ps.IPs.Limited
			lr.ConnTCP = ps.ConnTCP
			lr.ConnUDP = ps.ConnUDP
		}
		lv.RateUp += lr.RateUp
		lv.RateDown += lr.RateDown
		lv.ConnTCP += lr.ConnTCP
		lv.ConnUDP += lr.ConnUDP
		lv.Rules = append(lv.Rules, lr)
	}
	return lv
}

// handleRuleSubGet 处理 /api/rules/{id}、/api/rules/{id}/daily、/api/rules/{id}/ips。
func (s *Server) handleRuleSubGet(w http.ResponseWriter, r *http.Request, route string) {
	rest := strings.TrimPrefix(route, "/api/rules/")
	parts := strings.SplitN(rest, "/", 2)
	id, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		s.sendJSON(w, r, http.StatusBadRequest, M{"error": "invalid rule id"})
		return
	}
	sub := ""
	if len(parts) == 2 {
		sub = parts[1]
	}
	ctx := r.Context()
	switch sub {
	case "":
		rv, err := s.ruleView(ctx, id)
		if err != nil {
			s.sendJSON(w, r, http.StatusNotFound, M{"error": "not found"})
			return
		}
		s.sendJSON(w, r, http.StatusOK, rv)
	case "daily":
		s.handleDaily(w, r, id)
	case "ips":
		ps := s.policy.StateOf(id)
		if ps == nil {
			s.sendJSON(w, r, http.StatusOK, M{"ips": []policy.IPEntry{}, "rejected": []policy.IPEntry{}})
			return
		}
		s.sendJSON(w, r, http.StatusOK, M{"ips": ps.IPs.IPs, "rejected": ps.IPs.Rejected})
	default:
		s.sendJSON(w, r, http.StatusNotFound, M{"error": "not found"})
	}
}

func (s *Server) ruleView(ctx context.Context, id int64) (*RuleView, error) {
	r, err := s.store.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	v := RuleView{Rule: *r}
	polStates := s.policy.States()
	v.Status = ruleStatus(r, polStates[id])
	v.TargetTxt = forward.FormatHostPort(r.TargetAddress, r.TargetPort)
	v.ListenAddr = "0.0.0.0"
	if rate, ok := s.collect.Snapshot().Rates[id]; ok {
		v.Rate = rate
	}
	v.TotalUp, v.TotalDown = s.totals(ctx, id)
	today := ""
	if cs := s.collect.Snapshot(); cs.LastOK > 0 {
		today = time.Unix(cs.LastOK, 0).In(s.collect.Location()).Format("2006-01-02")
	}
	v.TodayUp, v.TodayDown = s.dailyFor(ctx, id, today)
	if ps, ok := polStates[id]; ok {
		v.ActiveIPs = ps.IPs.GrantedCount
		v.ConnTCP = ps.ConnTCP
		v.ConnUDP = ps.ConnUDP
		q := ps.Quota
		v.Quota = &q
		ip := ps.IPs
		v.IPs = &ip
	}
	return &v, nil
}

func (s *Server) handleDaily(w http.ResponseWriter, r *http.Request, ruleID int64) {
	days := 60
	if d := r.URL.Query().Get("days"); d != "" {
		if n, err := strconv.Atoi(d); err == nil && n > 0 && n <= 365 {
			days = n
		}
	}
	ctx := r.Context()
	var rows *queryRows
	var err error
	if ruleID > 0 {
		rows, err = queryDaily(ctx, s.db.DB, ruleID, days)
	} else {
		rows, err = queryDailyAll(ctx, s.db.DB, days)
	}
	if err != nil {
		s.sendJSON(w, r, http.StatusInternalServerError, M{"error": "internal error"})
		return
	}
	s.sendJSON(w, r, http.StatusOK, M{"days": rows.Rows})
}

type queryRows struct {
	Rows []DailyRow `json:"days"`
}

// DailyRow 是每日流量行。
type DailyRow struct {
	Day  string `json:"day"`
	Up   int64  `json:"up"`
	Down int64  `json:"down"`
}

// ---- POST ----

func (s *Server) handleAPIPost(w http.ResponseWriter, r *http.Request, route string) {
	if !s.authorized(r) {
		s.sendJSON(w, r, http.StatusUnauthorized, M{"error": "unauthorized"})
		return
	}
	if route == "/api/rules" {
		s.createRule(w, r)
		return
	}
	rest := strings.TrimPrefix(route, "/api/rules/")
	parts := strings.SplitN(rest, "/", 2)
	id, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || len(parts) < 2 {
		s.sendJSON(w, r, http.StatusBadRequest, M{"error": "bad request"})
		return
	}
	switch parts[1] {
	case "enable":
		s.setEnabled(w, r, id, true)
	case "disable":
		s.setEnabled(w, r, id, false)
	case "quota/reset":
		s.resetQuota(w, r, id)
	default:
		s.sendJSON(w, r, http.StatusNotFound, M{"error": "not found"})
	}
}

// ---- PUT/DELETE ----

func (s *Server) handleAPIMut(w http.ResponseWriter, r *http.Request, route string) {
	if !s.authorized(r) {
		s.sendJSON(w, r, http.StatusUnauthorized, M{"error": "unauthorized"})
		return
	}
	rest := strings.TrimPrefix(route, "/api/rules/")
	parts := strings.SplitN(rest, "/", 2)
	id, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		s.sendJSON(w, r, http.StatusBadRequest, M{"error": "invalid rule id"})
		return
	}
	sub := ""
	if len(parts) == 2 {
		sub = parts[1]
	}
	switch {
	case r.Method == http.MethodDelete && sub == "":
		s.deleteRule(w, r, id)
	case r.Method == http.MethodPut && sub == "":
		s.updateRule(w, r, id)
	case r.Method == http.MethodPut && sub == "policy":
		s.updatePolicy(w, r, id)
	default:
		s.sendJSON(w, r, http.StatusNotFound, M{"error": "not found"})
	}
}
