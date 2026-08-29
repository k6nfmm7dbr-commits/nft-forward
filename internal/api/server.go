// Package api 实现 Web API + SSE + 认证。
// 认证参考 SBX：随机高熵 panel token + HttpOnly Cookie（SameSite=Lax），
// mutation 走 POST 依赖 SameSite 防 CSRF，严格 JSON 解码、body 大小限制。
package api

import (
	"crypto/subtle"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/k6nfmm7dbr-commits/nft-forward/internal/config"
	"github.com/k6nfmm7dbr-commits/nft-forward/internal/database"
	"github.com/k6nfmm7dbr-commits/nft-forward/internal/forward"
	"github.com/k6nfmm7dbr-commits/nft-forward/internal/policy"
	"github.com/k6nfmm7dbr-commits/nft-forward/internal/traffic"
	"github.com/k6nfmm7dbr-commits/nft-forward/internal/webui"
)

const (
	cookieName    = "nff_token"
	maxBodyBytes  = 1 << 20 // 1 MiB
	rateLimitRate = 10      // 登录限速：每分钟
)

// Server 是面板 HTTP 服务。
type Server struct {
	cfg     *config.Config
	db      *database.DB
	store   *forward.Store
	policy  *policy.Service
	collect *traffic.Collector

	// SSE 订阅。
	subsMu sync.Mutex
	subs   map[chan []byte]struct{}

	// SSE 结构快照去重。
	lastSnapMu  sync.Mutex
	lastSnapKey string

	// 登录限速。
	loginMu    sync.Mutex
	loginCount int
	loginReset time.Time
}

// New 构造 Server 与 http.Server。
func New(cfg *config.Config, db *database.DB, store *forward.Store, pol *policy.Service, collect *traffic.Collector) (*Server, *http.Server) {
	s := &Server{
		cfg:     cfg,
		db:      db,
		store:   store,
		policy:  pol,
		collect: collect,
		subs:    map[chan []byte]struct{}{},
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

// handleLogin 登录：POST /api/login {token}。限速 + 设置 HttpOnly Cookie。
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	// 登录限速。
	s.loginMu.Lock()
	now := time.Now()
	if now.Sub(s.loginReset) > time.Minute {
		s.loginCount = 0
		s.loginReset = now
	}
	if s.loginCount >= rateLimitRate {
		s.loginMu.Unlock()
		s.sendJSON(w, r, http.StatusTooManyRequests, M{"error": "尝试过于频繁，请稍后再试"})
		return
	}
	s.loginCount++
	s.loginMu.Unlock()

	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))
	if err != nil {
		s.sendJSON(w, r, http.StatusBadRequest, M{"error": "bad request"})
		return
	}
	var req struct {
		Token string `json:"token"`
	}
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		s.sendJSON(w, r, http.StatusBadRequest, M{"error": "invalid json"})
		return
	}
	if !tokenEqual(req.Token, s.token()) {
		s.sendJSON(w, r, http.StatusUnauthorized, M{"error": "令牌错误"})
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    req.Token,
		Path:     "/",
		MaxAge:   7 * 24 * 3600,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   s.cfg.SecureCookie,
	})
	s.sendJSON(w, r, http.StatusOK, M{"ok": true})
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
	// healthz 无需认证（监控探针）。
	if route == "/healthz" {
		s.sendJSON(w, r, http.StatusOK, M{"ok": true})
		return
	}
	if !s.authorized(r) {
		s.serveAsset(w, "login.html", "text/html; charset=utf-8")
		return
	}
	switch route {
	case "/", "/index.html":
		s.serveAsset(w, "index.html", "text/html; charset=utf-8")
	case "/login":
		s.serveAsset(w, "login.html", "text/html; charset=utf-8")
	case "/app.js":
		s.serveAsset(w, "app.js", "application/javascript; charset=utf-8")
	case "/style.css":
		s.serveAsset(w, "style.css", "text/css; charset=utf-8")
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
// （IP 上下线、配额状态、规则增删改）才推送。
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
