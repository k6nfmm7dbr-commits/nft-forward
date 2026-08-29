package api

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/k6nfmm7dbr-commits/nft-forward/internal/forward"
	"github.com/k6nfmm7dbr-commits/nft-forward/internal/policy"
	"github.com/k6nfmm7dbr-commits/nft-forward/internal/traffic"
)

// RuleView 是规则的完整视图（供列表/详情）。
type RuleView struct {
	forward.Rule
	Status    string                 `json:"status"` // normal/disabled/quota_exceeded/ip_limited/error
	Rate      traffic.Rate           `json:"rate"`
	TotalUp   int64                  `json:"total_up"`
	TotalDown int64                  `json:"total_down"`
	TodayUp   int64                  `json:"today_up"`
	TodayDown int64                  `json:"today_down"`
	ActiveIPs int                    `json:"active_ip_count"`
	ConnTCP   int                    `json:"conn_tcp"`
	ConnUDP   int                    `json:"conn_udp"`
	Quota     *policy.RuleQuotaState `json:"quota,omitempty"`
	IPs       *policy.RuleIPSnapshot `json:"ips,omitempty"`
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
	if ps == nil {
		return "normal"
	}
	if ps.Quota.State == "exceeded" {
		return "quota_exceeded"
	}
	if r.IPLimitEnabled && len(ps.IPs.Rejected) > 0 {
		return "ip_limited"
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

// ---- GET ----

func (s *Server) handleAPIGet(w http.ResponseWriter, r *http.Request, route string) {
	if !s.authorized(r) {
		s.sendJSON(w, r, http.StatusUnauthorized, M{"error": "unauthorized"})
		return
	}
	switch {
	case route == "/api/healthz":
		s.sendJSON(w, r, http.StatusOK, M{"ok": true})
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
	if rate, ok := s.collect.Snapshot().Rates[id]; ok {
		v.Rate = rate
	}
	v.TotalUp, v.TotalDown = s.totals(ctx, id)
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
	switch route {
	case "/api/login":
		s.handleLogin(w, r)
		return
	case "/api/logout":
		s.handleLogout(w, r)
		return
	}
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
