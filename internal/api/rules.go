package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/k6nfmm7dbr-commits/nft-forward/internal/forward"
)

// decodeRuleReq 严格解码规则请求（不允许未知字段，body 大小限制）。
func decodeRuleReq(r *http.Request, v any) error {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))
	if err != nil {
		return err
	}
	dec := json.NewDecoder(newReader(body))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func newReader(b []byte) io.Reader { return &byteReader{b: b} }

type byteReader struct {
	b []byte
	i int
}

func (r *byteReader) Read(p []byte) (int, error) {
	if r.i >= len(r.b) {
		return 0, io.EOF
	}
	n := copy(p, r.b[r.i:])
	r.i += n
	return n, nil
}

// guardPorts 返回转发规则不能占用的保留端口。
func (s *Server) guardPorts() forward.GuardPorts {
	g := forward.GuardPorts{}
	if s.cfg.Port > 0 {
		g[s.cfg.Port] = "面板端口"
	}
	if s.cfg.SSHGuard > 0 {
		g[s.cfg.SSHGuard] = "SSH 端口"
	}
	return g
}

// ruleReq 是创建/更新规则的请求体。
type ruleReq struct {
	Name          string `json:"name"`
	Enabled       *bool  `json:"enabled"`
	Protocol      string `json:"protocol"`
	ListenAddress string `json:"listen_address"`
	ListenPort    int    `json:"listen_port"`
	TargetAddress string `json:"target_address"`
	TargetPort    int    `json:"target_port"`
}

func (s *Server) createRule(w http.ResponseWriter, r *http.Request) {
	var req ruleReq
	if err := decodeRuleReq(r, &req); err != nil {
		s.sendJSON(w, r, http.StatusBadRequest, M{"error": "invalid request"})
		return
	}
	ctx := r.Context()
	rule := &forward.Rule{
		Name:          req.Name,
		Enabled:       req.Enabled == nil || *req.Enabled,
		Protocol:      req.Protocol,
		ListenAddress: req.ListenAddress,
		ListenPort:    req.ListenPort,
		TargetAddress: req.TargetAddress,
		TargetPort:    req.TargetPort,
	}
	existing, err := s.store.ListActive(ctx)
	if err != nil {
		s.sendJSON(w, r, http.StatusInternalServerError, M{"error": "internal error"})
		return
	}
	if err := forward.CheckConflicts(rule, existing, s.guardPorts()); err != nil {
		s.sendJSON(w, r, http.StatusBadRequest, M{"error": err.Error()})
		return
	}
	id, err := s.store.Create(ctx, rule)
	if err != nil {
		s.sendJSON(w, r, http.StatusInternalServerError, M{"error": "创建失败"})
		return
	}
	// 应用变更（事务化）。
	if err := s.policy.Reconcile(ctx); err != nil {
		s.sendJSON(w, r, http.StatusInternalServerError, M{"error": "规则已创建但应用失败: " + err.Error()})
		return
	}
	s.publishSnapshot()
	rv, _ := s.ruleView(ctx, id)
	s.sendJSON(w, r, http.StatusOK, rv)
}

func (s *Server) updateRule(w http.ResponseWriter, r *http.Request, id int64) {
	var req ruleReq
	if err := decodeRuleReq(r, &req); err != nil {
		s.sendJSON(w, r, http.StatusBadRequest, M{"error": "invalid request"})
		return
	}
	ctx := r.Context()
	rule, err := s.store.Get(ctx, id)
	if err != nil {
		s.sendJSON(w, r, http.StatusNotFound, M{"error": "not found"})
		return
	}
	if req.Name != "" {
		rule.Name = req.Name
	}
	if req.Enabled != nil {
		rule.Enabled = *req.Enabled
	}
	if req.Protocol != "" {
		rule.Protocol = req.Protocol
	}
	if req.ListenAddress != "" {
		rule.ListenAddress = req.ListenAddress
	}
	if req.ListenPort > 0 {
		rule.ListenPort = req.ListenPort
	}
	if req.TargetAddress != "" {
		rule.TargetAddress = req.TargetAddress
	}
	if req.TargetPort > 0 {
		rule.TargetPort = req.TargetPort
	}
	existing, err := s.store.ListActive(ctx)
	if err != nil {
		s.sendJSON(w, r, http.StatusInternalServerError, M{"error": "internal error"})
		return
	}
	if err := forward.CheckConflicts(rule, existing, s.guardPorts()); err != nil {
		s.sendJSON(w, r, http.StatusBadRequest, M{"error": err.Error()})
		return
	}
	if err := s.store.Update(ctx, rule); err != nil {
		s.sendJSON(w, r, http.StatusInternalServerError, M{"error": "更新失败"})
		return
	}
	if err := s.policy.Reconcile(ctx); err != nil {
		s.sendJSON(w, r, http.StatusInternalServerError, M{"error": "规则已更新但应用失败: " + err.Error()})
		return
	}
	s.publishSnapshot()
	rv, _ := s.ruleView(ctx, id)
	s.sendJSON(w, r, http.StatusOK, rv)
}

func (s *Server) setEnabled(w http.ResponseWriter, r *http.Request, id int64, enabled bool) {
	ctx := r.Context()
	rule, err := s.store.Get(ctx, id)
	if err != nil {
		s.sendJSON(w, r, http.StatusNotFound, M{"error": "not found"})
		return
	}
	rule.Enabled = enabled
	if err := s.store.Update(ctx, rule); err != nil {
		s.sendJSON(w, r, http.StatusInternalServerError, M{"error": "internal error"})
		return
	}
	if err := s.policy.Reconcile(ctx); err != nil {
		s.sendJSON(w, r, http.StatusInternalServerError, M{"error": "应用失败: " + err.Error()})
		return
	}
	s.publishSnapshot()
	s.sendJSON(w, r, http.StatusOK, M{"ok": true, "enabled": enabled})
}

func (s *Server) deleteRule(w http.ResponseWriter, r *http.Request, id int64) {
	ctx := r.Context()
	if err := s.store.SoftDelete(ctx, id); err != nil {
		s.sendJSON(w, r, http.StatusNotFound, M{"error": "规则不存在或已删除"})
		return
	}
	// 软删除：保留历史流量；nft 规则由 reconcile 清除（软删规则不再生成）。
	if err := s.policy.Reconcile(ctx); err != nil {
		s.sendJSON(w, r, http.StatusInternalServerError, M{"error": "应用失败: " + err.Error()})
		return
	}
	s.publishSnapshot()
	s.sendJSON(w, r, http.StatusOK, M{"ok": true})
}

// policyReq 是配额 / IP 限制策略请求。
type policyReq struct {
	QuotaEnabled    *bool  `json:"quota_enabled"`
	QuotaLimitBytes *int64 `json:"quota_limit_bytes"`
	IPLimitEnabled  *bool  `json:"ip_limit_enabled"`
	IPLimitMax      *int   `json:"ip_limit_max"`
	QuotaReset      *bool  `json:"quota_reset"` // true=只重置已用，不删历史
}

func (s *Server) updatePolicy(w http.ResponseWriter, r *http.Request, id int64) {
	var req policyReq
	if err := decodeRuleReq(r, &req); err != nil {
		s.sendJSON(w, r, http.StatusBadRequest, M{"error": "invalid request"})
		return
	}
	ctx := r.Context()
	rule, err := s.store.Get(ctx, id)
	if err != nil {
		s.sendJSON(w, r, http.StatusNotFound, M{"error": "not found"})
		return
	}
	if req.QuotaEnabled != nil {
		rule.QuotaEnabled = *req.QuotaEnabled
	}
	if req.QuotaLimitBytes != nil {
		rule.QuotaLimitBytes = *req.QuotaLimitBytes
	}
	if req.IPLimitEnabled != nil {
		rule.IPLimitEnabled = *req.IPLimitEnabled
	}
	if req.IPLimitMax != nil {
		if *req.IPLimitMax < 1 {
			s.sendJSON(w, r, http.StatusBadRequest, M{"error": "最大同时在线数必须 >= 1"})
			return
		}
		rule.IPLimitMax = *req.IPLimitMax
	}
	if req.QuotaReset != nil && *req.QuotaReset {
		life, lerr := s.policy.Lifetime(ctx, id)
		if lerr != nil {
			s.sendJSON(w, r, http.StatusInternalServerError, M{"error": "internal error"})
			return
		}
		rule.QuotaResetBaseline = life // 只重置已用，不删历史
	}
	if rule.QuotaEnabled && rule.QuotaLimitBytes <= 0 {
		s.sendJSON(w, r, http.StatusBadRequest, M{"error": "启用配额时必须设置额度 > 0"})
		return
	}
	if err := s.store.Update(ctx, rule); err != nil {
		s.sendJSON(w, r, http.StatusInternalServerError, M{"error": "更新失败"})
		return
	}
	if err := s.policy.Reconcile(ctx); err != nil {
		s.sendJSON(w, r, http.StatusInternalServerError, M{"error": "策略已保存但应用失败: " + err.Error()})
		return
	}
	s.publishSnapshot()
	rv, _ := s.ruleView(ctx, id)
	s.sendJSON(w, r, http.StatusOK, rv)
}

func (s *Server) resetQuota(w http.ResponseWriter, r *http.Request, id int64) {
	ctx := r.Context()
	life, err := s.policy.Lifetime(ctx, id)
	if err != nil {
		s.sendJSON(w, r, http.StatusInternalServerError, M{"error": "internal error"})
		return
	}
	rule, err := s.store.Get(ctx, id)
	if err != nil {
		s.sendJSON(w, r, http.StatusNotFound, M{"error": "not found"})
		return
	}
	rule.QuotaResetBaseline = life // 只重置已用，保留历史累计/每日
	if err := s.store.Update(ctx, rule); err != nil {
		s.sendJSON(w, r, http.StatusInternalServerError, M{"error": "internal error"})
		return
	}
	if err := s.policy.Reconcile(ctx); err != nil {
		s.sendJSON(w, r, http.StatusInternalServerError, M{"error": "应用失败: " + err.Error()})
		return
	}
	s.publishSnapshot()
	s.sendJSON(w, r, http.StatusOK, M{"ok": true})
}

// publishSnapshot 向所有 SSE 订阅者广播最新全量快照。
func (s *Server) publishSnapshot() {
	s.PublishSSE("snapshot", s.buildFullSnapshot())
}

// Lifetime 暴露累计流量读取（配额重置用）。
func (s *Server) lifetimeUnused() {}

var _ = context.Background
var _ = time.Now
