package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/k6nfmm7dbr-commits/nft-forward/internal/forward"
	"github.com/k6nfmm7dbr-commits/nft-forward/internal/rulesvc"
)

// decodeRuleReq 严格解码规则请求（body 大小限制）。
//
// 刻意 **不用** DisallowUnknownFields：老客户端可能仍发送已废弃的
// listen_address 字段，为升级兼容需要接受并忽略它（见 ruleReq.ListenAddress）。
// 其它未知字段同样忽略——它们不会改变任何行为。
func decodeRuleReq(r *http.Request, v any) error {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
	if err != nil {
		return err
	}
	if len(body) > maxBodyBytes {
		return errors.New("请求体过大")
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	return dec.Decode(v)
}

// guardPorts 返回转发规则不能占用的保留端口（与 rulesvc 共用 config 的同一份表）。
func (s *Server) guardPorts() forward.GuardPorts {
	return forward.GuardPorts(s.cfg.GuardPorts())
}

// ruleReq 是创建/更新规则的请求体。
//
// ListenAddress 是**已废弃**字段：转发规则不再有监听地址概念（规则自动作用于
// 本机所有本地地址，由 nft 的 fib daddr type local 保证）。这里仍然声明它，
// 只为让老客户端的请求不至于解析失败——收到后一律忽略，用户无法通过它改变
// 任何实际监听行为。
type ruleReq struct {
	Name          string  `json:"name"`
	Enabled       *bool   `json:"enabled"`
	Protocol      string  `json:"protocol"`
	ListenPort    *int    `json:"listen_port"`
	TargetAddress string  `json:"target_address"`
	TargetPort    *int    `json:"target_port"`
	ListenAddress *string `json:"listen_address,omitempty"` // deprecated: 接受但忽略
}

func (s *Server) createRule(w http.ResponseWriter, r *http.Request) {
	var req ruleReq
	if err := decodeRuleReq(r, &req); err != nil {
		s.sendJSON(w, r, http.StatusBadRequest, M{"error": "请求格式不正确"})
		return
	}
	if req.ListenAddress != nil {
		s.logDeprecated("listen_address")
	}
	in := rulesvc.CreateInput{
		Name:          req.Name,
		Protocol:      req.Protocol,
		TargetAddress: req.TargetAddress,
		Enabled:       req.Enabled,
	}
	if req.ListenPort != nil {
		in.ListenPort = *req.ListenPort // 0 = 留空，由后端安全随机分配
	}
	if req.TargetPort != nil {
		in.TargetPort = *req.TargetPort
	}
	rule, err := s.rules.Create(r.Context(), in)
	if err != nil {
		s.sendRuleErr(w, r, err)
		return
	}
	rv, _ := s.ruleView(r.Context(), rule.ID)
	if rv == nil {
		s.sendJSON(w, r, http.StatusOK, RuleView{Rule: *rule})
		return
	}
	s.sendJSON(w, r, http.StatusOK, rv)
}

func (s *Server) updateRule(w http.ResponseWriter, r *http.Request, id int64) {
	var req ruleReq
	if err := decodeRuleReq(r, &req); err != nil {
		s.sendJSON(w, r, http.StatusBadRequest, M{"error": "请求格式不正确"})
		return
	}
	if req.ListenAddress != nil {
		s.logDeprecated("listen_address")
	}
	var in rulesvc.UpdateInput
	if strings.TrimSpace(req.Name) != "" {
		in.Name = &req.Name
	}
	if req.Protocol != "" {
		in.Protocol = &req.Protocol
	}
	if req.ListenPort != nil {
		in.ListenPort = req.ListenPort
	}
	if req.TargetAddress != "" {
		in.TargetAddress = &req.TargetAddress
	}
	if req.TargetPort != nil {
		in.TargetPort = req.TargetPort
	}
	if req.Enabled != nil {
		in.Enabled = req.Enabled
	}
	rule, err := s.rules.Update(r.Context(), id, in)
	if err != nil {
		s.sendRuleErr(w, r, err)
		return
	}
	rv, _ := s.ruleView(r.Context(), rule.ID)
	if rv == nil {
		s.sendJSON(w, r, http.StatusOK, RuleView{Rule: *rule})
		return
	}
	s.sendJSON(w, r, http.StatusOK, rv)
}

func (s *Server) setEnabled(w http.ResponseWriter, r *http.Request, id int64, enabled bool) {
	if _, err := s.rules.SetEnabled(r.Context(), id, enabled); err != nil {
		s.sendRuleErr(w, r, err)
		return
	}
	s.sendJSON(w, r, http.StatusOK, M{"ok": true, "enabled": enabled})
}

func (s *Server) deleteRule(w http.ResponseWriter, r *http.Request, id int64) {
	if err := s.rules.Delete(r.Context(), id); err != nil {
		s.sendRuleErr(w, r, err)
		return
	}
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
		s.sendJSON(w, r, http.StatusBadRequest, M{"error": "请求格式不正确"})
		return
	}
	ctx := r.Context()
	in := rulesvc.PolicyInput{
		QuotaEnabled:    req.QuotaEnabled,
		QuotaLimitBytes: req.QuotaLimitBytes,
		IPLimitEnabled:  req.IPLimitEnabled,
		IPLimitMax:      req.IPLimitMax,
	}
	if req.QuotaReset != nil && *req.QuotaReset {
		life, lerr := s.policy.Lifetime(ctx, id)
		if lerr != nil {
			s.sendJSON(w, r, http.StatusInternalServerError, M{"error": "读取累计流量失败"})
			return
		}
		in.QuotaResetTo = &life // 只重置已用，不删历史
	}
	rule, err := s.rules.UpdatePolicy(ctx, id, in)
	if err != nil {
		s.sendRuleErr(w, r, err)
		return
	}
	rv, _ := s.ruleView(ctx, rule.ID)
	if rv == nil {
		s.sendJSON(w, r, http.StatusOK, RuleView{Rule: *rule})
		return
	}
	s.sendJSON(w, r, http.StatusOK, rv)
}

func (s *Server) resetQuota(w http.ResponseWriter, r *http.Request, id int64) {
	ctx := r.Context()
	life, err := s.policy.Lifetime(ctx, id)
	if err != nil {
		s.sendJSON(w, r, http.StatusInternalServerError, M{"error": "读取累计流量失败"})
		return
	}
	rule, err := s.rules.UpdatePolicy(ctx, id, rulesvc.PolicyInput{QuotaResetTo: &life})
	if err != nil {
		s.sendRuleErr(w, r, err)
		return
	}
	var used int64
	if ps := s.policy.StateOf(rule.ID); ps != nil {
		used = ps.Quota.UsedBytes
	}
	s.sendJSON(w, r, http.StatusOK, M{"ok": true, "quota_used_bytes": used})
}

// sendRuleErr 把变更服务的错误映射成合适的 HTTP 状态与用户可读文案。
//
// 底层细节（exit status 1 / SQLITE_BUSY 之类）只进日志，不回给用户。
func (s *Server) sendRuleErr(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, rulesvc.ErrNotFound) {
		s.sendJSON(w, r, http.StatusNotFound, M{"error": "规则不存在或已删除"})
		return
	}
	msg := err.Error()
	code := http.StatusBadRequest
	switch {
	case strings.Contains(msg, "无法应用 nftables 规则"):
		code = http.StatusInternalServerError
		msg = "无法应用 nftables 规则，请检查系统 nftables 状态"
	case strings.Contains(msg, "数据库写入失败"):
		code = http.StatusInternalServerError
		msg = "数据库写入失败，变更未生效"
	case strings.Contains(msg, "读取规则列表失败") || strings.Contains(msg, "读取累计流量失败"):
		code = http.StatusInternalServerError
		msg = "读取规则数据失败"
	}
	if code == http.StatusInternalServerError {
		s.logError("规则变更失败", err)
	}
	s.sendJSON(w, r, code, M{"error": msg})
}

// publishSnapshot 向所有 SSE 订阅者广播最新全量快照。
//
// 顺带刷新 lastSnapKey：否则「变更后立即广播」与「2s 周期广播」会各自算 key，
// 周期广播会因为 key 未更新而重复发一遍同样的快照。
func (s *Server) publishSnapshot() {
	snap := s.buildFullSnapshot()
	key := snapshotStructKey(snap)
	s.lastSnapMu.Lock()
	s.lastSnapKey = key
	s.lastSnapMu.Unlock()
	s.PublishSSE("snapshot", snap)
}

// PublishSnapshotNow 立即广播全量快照（供规则变更服务在提交成功后调用）。
func (s *Server) PublishSnapshotNow() { s.publishSnapshot() }
