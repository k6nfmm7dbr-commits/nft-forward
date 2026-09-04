// Package api 实现 Web API + SSE + 认证。
//
// 认证参考 SBX：随机高熵 panel token + HttpOnly Cookie（SameSite=Lax），
// mutation 走 POST/PUT/DELETE 依赖 SameSite 防 CSRF，严格 body 大小限制。
// 登录失败按来源 IP 节流（连续失败达阈值后每次尝试延迟 2s），
// 来源只取 RemoteAddr，不信任 X-Forwarded-For（可伪造）。
package api

import (
	"crypto/subtle"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/k6nfmm7dbr-commits/nft-forward/internal/config"
	"github.com/k6nfmm7dbr-commits/nft-forward/internal/database"
	"github.com/k6nfmm7dbr-commits/nft-forward/internal/forward"
	"github.com/k6nfmm7dbr-commits/nft-forward/internal/policy"
	"github.com/k6nfmm7dbr-commits/nft-forward/internal/rulesvc"
	"github.com/k6nfmm7dbr-commits/nft-forward/internal/traffic"
	"github.com/k6nfmm7dbr-commits/nft-forward/internal/webui"
)

const (
	cookieName   = "nff_token"
	maxBodyBytes = 1 << 20 // 1 MiB

	// 登录失败节流：同一来源 IP 连续失败达 loginFailBurst 次后，
	// 每次失败尝试强制等待 loginFailDelay，窗口内累计。
	// 32 hex token 暴破本不现实，节流用于挡凭据喷洒与日志刷屏。
	loginFailBurst  = 5
	loginFailWindow = 5 * time.Minute
	loginFailDelay  = 2 * time.Second
	loginFailMaxLen = 4096 // 追踪表上限，防伪造源 IP 撑爆内存
)

// Server 是面板 HTTP 服务。
type Server struct {
	cfg     *config.Config
	db      *database.DB
	store   *forward.Store
	policy  *policy.Service
	rules   *rulesvc.Service
	collect *traffic.Collector

	// SSE 订阅。
	subsMu sync.Mutex
	subs   map[chan []byte]struct{}

	// SSE 结构快照去重。
	lastSnapMu  sync.Mutex
	lastSnapKey string

	// 登录失败节流。
	loginMu    sync.Mutex
	loginFails map[string]*loginFailState

	// 废弃字段告警去重。
	deprecatedMu sync.Mutex
	deprecated   map[string]time.Time

	// DNS worker 健康状态。
	dnsMu     sync.Mutex
	dnsHealth DNSHealth

	started time.Time
}

type loginFailState struct {
	count int
	last  time.Time
}

// New 构造 Server 与 http.Server。
func New(cfg *config.Config, db *database.DB, store *forward.Store, pol *policy.Service,
	rules *rulesvc.Service, collect *traffic.Collector) (*Server, *http.Server) {
	s := &Server{
		cfg:        cfg,
		db:         db,
		store:      store,
		policy:     pol,
		rules:      rules,
		collect:    collect,
		subs:       map[chan []byte]struct{}{},
		loginFails: map[string]*loginFailState{},
		deprecated: map[string]time.Time{},
		started:    time.Now(),
	}
	hs := &http.Server{
		Addr:              net.JoinHostPort(cfg.Listen, strconv.Itoa(cfg.Port)),
		Handler:           s.recover(s),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}
	return s, hs
}

func (s *Server) recover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				slog.Error("HTTP 处理器异常", "err", rec, "path", r.URL.Path)
				http.Error(w, "internal error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// ServeHTTP 路由分发。
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	route := strings.TrimRight(r.URL.Path, "/")
	if route == "" {
		route = "/"
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		if strings.HasPrefix(route, "/api/") {
			s.handleAPIGet(w, r, route)
			return
		}
		s.handleStatic(w, r, route)
	case http.MethodPost:
		if strings.HasPrefix(route, "/api/") {
			s.handleAPIPost(w, r, route)
			return
		}
		if route == "/login" {
			s.handleFormLogin(w, r)
			return
		}
		s.sendJSON(w, r, http.StatusNotFound, M{"error": "not found"})
	case http.MethodPut, http.MethodDelete:
		if strings.HasPrefix(route, "/api/") {
			s.handleAPIMut(w, r, route)
			return
		}
		s.sendJSON(w, r, http.StatusNotFound, M{"error": "not found"})
	default:
		s.sendJSON(w, r, http.StatusMethodNotAllowed, M{"error": "method not allowed"})
	}
}

// M 是 JSON 对象简写。
type M map[string]any

func (s *Server) sendJSON(w http.ResponseWriter, r *http.Request, code int, v any) {
	data, err := json.Marshal(v)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	if r.Method != http.MethodHead {
		_, _ = w.Write(data)
	}
}

// logError 记录内部错误（细节只进日志，不回给用户）。
func (s *Server) logError(msg string, err error) { slog.Error(msg, "err", err) }

// logDeprecated 对废弃字段每 10 分钟最多告警一次。
func (s *Server) logDeprecated(field string) {
	now := time.Now()
	s.deprecatedMu.Lock()
	last := s.deprecated[field]
	due := now.Sub(last) > 10*time.Minute
	if due {
		s.deprecated[field] = now
	}
	s.deprecatedMu.Unlock()
	if due {
		slog.Warn("请求包含已废弃字段，已忽略", "field", field)
	}
}

// ---- 认证 ----

func (s *Server) token() string { return s.cfg.Token }

// authorized 校验：Cookie 或 Authorization Bearer。
func (s *Server) authorized(r *http.Request) bool {
	tok := s.token()
	if tok == "" {
		return true // 未配置 token 则开放（仅本机监听场景）
	}
	given := ""
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		given = auth[len("Bearer "):]
	}
	if given == "" {
		given = cookieToken(r)
	}
	return tokenEqual(given, tok)
}

func cookieToken(r *http.Request) string {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return ""
	}
	return c.Value
}

func tokenEqual(given, token string) bool {
	if len(given) != len(token) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(given), []byte(token)) == 1
}

// loginClientKey 取来源标识。刻意只用 RemoteAddr 的 IP 部分，不信任
// X-Forwarded-For / X-Real-IP（可伪造，会让攻击者绕过节流并污染追踪表）。
func loginClientKey(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// loginThrottle 返回本次失败尝试应额外等待的时长。
func (s *Server) loginThrottle(key string, now time.Time) time.Duration {
	s.loginMu.Lock()
	defer s.loginMu.Unlock()
	s.gcLoginFailsLocked(now)
	st, ok := s.loginFails[key]
	if !ok || now.Sub(st.last) > loginFailWindow || st.count < loginFailBurst {
		return 0
	}
	return loginFailDelay
}

func (s *Server) loginRecordFail(key string, now time.Time) {
	s.loginMu.Lock()
	defer s.loginMu.Unlock()
	s.gcLoginFailsLocked(now)
	st, ok := s.loginFails[key]
	if !ok || now.Sub(st.last) > loginFailWindow {
		if len(s.loginFails) >= loginFailMaxLen {
			return // 表已满：放弃记录而不是无界增长（失败仍会被拒绝）
		}
		s.loginFails[key] = &loginFailState{count: 1, last: now}
		return
	}
	st.count++
	st.last = now
}

func (s *Server) loginRecordSuccess(key string) {
	s.loginMu.Lock()
	defer s.loginMu.Unlock()
	delete(s.loginFails, key)
}

func (s *Server) gcLoginFailsLocked(now time.Time) {
	for k, st := range s.loginFails {
		if now.Sub(st.last) > loginFailWindow {
			delete(s.loginFails, k)
		}
	}
}

// setSession 下发会话 Cookie。
func (s *Server) setSession(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   7 * 24 * 3600,
		HttpOnly: true,
		// Lax 而非 Strict：从外部链接/书签打开面板时 Strict 会让 Cookie 不随
		// 顶级导航发送，表现就像"没记住登录"。Lax 仍能阻止跨站 POST 携带 Cookie。
		SameSite: http.SameSiteLaxMode,
		// 仅当用户显式配置 secure_cookie（前面套了 HTTPS 反代）才加 Secure，
		// 否则纯 HTTP 直连登录会失效。
		Secure: s.cfg.SecureCookie,
	})
}

// handleLogin 是 JSON 登录：POST /api/login {token}。
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
	if err != nil || len(body) > maxBodyBytes {
		s.sendJSON(w, r, http.StatusBadRequest, M{"error": "请求格式不正确"})
		return
	}
	var req struct {
		Token string `json:"token"`
	}
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		s.sendJSON(w, r, http.StatusBadRequest, M{"error": "请求格式不正确"})
		return
	}
	key := loginClientKey(r)
	now := time.Now()
	if tokenEqual(req.Token, s.token()) {
		// 成功路径绝不延迟：节流只惩罚失败尝试。
		s.loginRecordSuccess(key)
		s.setSession(w, req.Token)
		s.sendJSON(w, r, http.StatusOK, M{"ok": true})
		return
	}
	s.loginRecordFail(key, now)
	if d := s.loginThrottle(key, now); d > 0 {
		select {
		case <-time.After(d):
		case <-r.Context().Done():
			return
		}
	}
	s.sendJSON(w, r, http.StatusUnauthorized, M{"error": "令牌错误"})
}

// handleFormLogin 是表单登录（登录页 POST /login），成功后 302 到首页。
func (s *Server) handleFormLogin(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
	if err != nil {
		s.redirect(w, "/login?error=1")
		return
	}
	if len(body) > maxBodyBytes {
		// 超限必须拒绝，不得截断后继续解析（避免构造部分令牌绕过）。
		s.sendJSON(w, r, http.StatusRequestEntityTooLarge, M{"error": "请求体过大"})
		return
	}
	vals, perr := parseForm(string(body))
	given := ""
	if perr == nil {
		given = vals["token"]
	}
	key := loginClientKey(r)
	now := time.Now()
	if tokenEqual(given, s.token()) {
		s.loginRecordSuccess(key)
		s.setSession(w, given)
		s.redirect(w, "/")
		return
	}
	s.loginRecordFail(key, now)
	if d := s.loginThrottle(key, now); d > 0 {
		select {
		case <-time.After(d):
		case <-r.Context().Done():
			return
		}
	}
	s.redirect(w, "/login?error=1")
}

func (s *Server) redirect(w http.ResponseWriter, location string) {
	w.Header().Set("Location", location)
	w.WriteHeader(http.StatusFound)
}

// parseForm 解析 application/x-www-form-urlencoded（只取首个非空值）。
func parseForm(body string) (map[string]string, error) {
	vals, err := url.ParseQuery(body)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for k, list := range vals {
		for _, v := range list {
			if v != "" {
				out[k] = v
				break
			}
		}
		if _, ok := out[k]; !ok {
			out[k] = ""
		}
	}
	return out, nil
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	s.sendJSON(w, r, http.StatusOK, M{"ok": true})
}

// ---- 静态资源 ----

func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request, route string) {
	// healthz 无需认证（监控探针），只返回存活标记，不含任何配置信息。
	if route == "/healthz" {
		s.sendJSON(w, r, http.StatusOK, M{"ok": true})
		return
	}
	switch route {
	case "/login":
		s.serveAsset(w, "login.html", "text/html; charset=utf-8")
		return
	case "/login.js":
		s.serveAsset(w, "login.js", "application/javascript; charset=utf-8")
		return
	case "/style.css":
		s.serveAsset(w, "style.css", "text/css; charset=utf-8")
		return
	}
	if !s.authorized(r) {
		s.serveAsset(w, "login.html", "text/html; charset=utf-8")
		return
	}
	switch route {
	case "/", "/index.html":
		s.serveAsset(w, "index.html", "text/html; charset=utf-8")
	case "/app.js":
		s.serveAsset(w, "app.js", "application/javascript; charset=utf-8")
	default:
		s.sendJSON(w, r, http.StatusNotFound, M{"error": "not found"})
	}
}

func (s *Server) serveAsset(w http.ResponseWriter, name, ctype string) {
	data, err := webui.FS().Open(strings.TrimLeft(name, "/"))
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	defer data.Close()
	b, _ := io.ReadAll(data)
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(b)
}

// PublishSSE 向所有 SSE 订阅者广播一条事件（payload 已含 event/data）。
func (s *Server) PublishSSE(event string, payload any) {
	data, err := json.Marshal(payload)
	if err != nil {
		return
	}
	msg := append([]byte("event: "+event+"\ndata: "), data...)
	msg = append(msg, '\n', '\n')
	s.subsMu.Lock()
	defer s.subsMu.Unlock()
	for ch := range s.subs {
		select {
		case ch <- msg:
		default:
		}
	}
}

// snapshotStructKey 计算快照的结构哈希（清零时间与速率，只比较规则结构 / 在线 IP / 配额）。
// 速率和采集时间每个周期都在变，但不应触发 SSE 重播；只有结构性变化
// （IP 上下线、配额状态、规则增删改、DNS 目标变化）才推送。
func (s *Server) snapshotStructKey() string {
	snap := s.buildFullSnapshot()
	snap.Now = 0
	snap.Rate = traffic.Rate{}
	for i := range snap.Rules {
		snap.Rules[i].Rate = traffic.Rate{}
	}
	b, _ := json.Marshal(snap)
	return string(b)
}

// PublishSnapshotTick 周期兜底广播：仅在有订阅者且结构发生变化时推送。
func (s *Server) PublishSnapshotTick() {
	s.subsMu.Lock()
	n := len(s.subs)
	s.subsMu.Unlock()
	if n == 0 {
		return
	}
	key := s.snapshotStructKey()
	s.lastSnapMu.Lock()
	changed := key != s.lastSnapKey
	if changed {
		s.lastSnapKey = key
	}
	s.lastSnapMu.Unlock()
	if !changed {
		return
	}
	s.PublishSSE("snapshot", s.buildFullSnapshot())
}

// handleEvents 是 SSE 端点：首包完整 snapshot，之后按变化推送。
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(r) {
		s.sendJSON(w, r, http.StatusUnauthorized, M{"error": "unauthorized"})
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		s.sendJSON(w, r, http.StatusInternalServerError, M{"error": "streaming unsupported"})
		return
	}
	// 清除 write deadline：http.Server.WriteTimeout 会在 60s 后切断 SSE 长连接
	// （SBX 踩过同一个坑）。ResponseController 是 Go 1.20+ 的标准做法。
	rc := http.NewResponseController(w)
	if err := rc.SetWriteDeadline(time.Time{}); err != nil {
		slog.Debug("清除 SSE write deadline 失败", "err", err)
	}
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	// 首包：完整 snapshot。
	snap := s.buildFullSnapshot()
	data, _ := json.Marshal(snap)
	if _, err := w.Write([]byte("event: snapshot\ndata: ")); err != nil {
		return
	}
	if _, err := w.Write(data); err != nil {
		return
	}
	if _, err := w.Write([]byte("\n\n")); err != nil {
		return
	}
	flusher.Flush()

	// 订阅。
	ch := make(chan []byte, 32)
	s.subsMu.Lock()
	s.subs[ch] = struct{}{}
	s.subsMu.Unlock()
	defer func() {
		s.subsMu.Lock()
		delete(s.subs, ch)
		s.subsMu.Unlock()
	}()

	// 心跳，保活代理/浏览器长连接。
	hb := time.NewTicker(15 * time.Second)
	defer hb.Stop()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case <-hb.C:
			if _, err := w.Write([]byte(": ping\n\n")); err != nil {
				return
			}
			flusher.Flush()
		case msg := <-ch:
			if _, err := w.Write(msg); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}
