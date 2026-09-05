// Package api 实现 Web API + SSE。
//
// 路由结构（v0.3.1 起）：
//
//	<entry>/                面板首页（未登录 → 登录页）
//	<entry>/login           登录页（GET）/ 提交令牌（POST）
//	<entry>/logout          清除会话
//	<entry>/app.js …        前端静态资源（需认证）
//	<entry>/api/…           JSON API + SSE（需认证）
//	/healthz                健康检查（仅 loopback）
//	其它一切                极简 404，无任何面板特征
//
// <entry> 是首次安装生成的随机入口路径（96 bit，crypto/rand），与令牌完全
// 独立、不可互相推导。随机路径 **不是** 身份认证：进入正确入口后仍必须通过
// Token 登录，二者同时满足才能访问面板。
//
// 认证机制与 SBX 对齐：Authorization: Bearer 或 HttpOnly Cookie，
// 常量时间比较，登录失败节流，登录体 64 KiB 上限。绝不接受 ?token=。
package api

import (
	"encoding/json"
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
	"github.com/k6nfmm7dbr-commits/nft-forward/internal/rulesvc"
	"github.com/k6nfmm7dbr-commits/nft-forward/internal/traffic"
)

const (
	maxBodyBytes = 1 << 20 // 1 MiB
)

// Server 是面板 HTTP 服务。
type Server struct {
	cfg     *config.Config
	db      *database.DB
	store   *forward.Store
	policy  *policy.Service
	rules   *rulesvc.Service
	collect *traffic.Collector

	// entry 是随机入口路径（形如 "/3e4f65a8c24d2bd5b9e80147"，无尾斜杠）。
	entry string

	// SSE 订阅。
	subsMu sync.Mutex
	subs   map[chan []byte]struct{}

	// SSE 结构快照去重。
	lastSnapMu  sync.Mutex
	lastSnapKey string

	// 废弃字段告警去重。
	deprecatedMu sync.Mutex
	deprecated   map[string]time.Time

	// DNS worker 健康状态。
	dnsMu     sync.Mutex
	dnsHealth DNSHealth

	started time.Time
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
		entry:      cfg.EntryRoute(),
		subs:       map[chan []byte]struct{}{},
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
//
// 第一道闸门是随机入口路径：不以 <entry> 开头的请求（除 loopback /healthz）
// 一律极简 404，不泄漏任何面板存在的线索。
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	route := strings.TrimRight(r.URL.Path, "/")
	if route == "" {
		route = "/"
	}

	// healthz：仅 loopback 可见。外部访问与其它未知路径同样得到极简 404 ——
	// 公网扫描器无法通过裸 /healthz 确认这是一个真实管理服务。
	//
	// ★ 语义（v0.3.2）：200 不再只代表「Go HTTP 线程活着」，而是
	// 「进程已完成首轮 nft 数据面 enforcement」。数据面未就绪时返回 503，
	// 这样安装器/升级器的健康确认不会把「HTTP 活着但转发没加载」当成成功。
	if route == "/healthz" {
		if !isLoopback(r) {
			notFound(w, r)
			return
		}
		if !s.dataPlaneReady() {
			s.send(w, r, http.StatusServiceUnavailable,
				"application/json; charset=utf-8", []byte(`{"ok":false,"reason":"data plane not ready"}`))
			return
		}
		s.send(w, r, http.StatusOK, "application/json; charset=utf-8", []byte(`{"ok":true}`))
		return
	}

	sub, ok := s.stripEntry(route)
	if !ok {
		notFound(w, r)
		return
	}
	// 入口根必须带尾斜杠：前端所有资源与 API 都用相对路径拼接
	// （BASE = pathname 去掉最后一段）。/entry 不重定向的话，
	// style.css 会被解析成站点根下的 /style.css → 404。
	if sub == "/" && !strings.HasSuffix(r.URL.Path, "/") &&
		(r.Method == http.MethodGet || r.Method == http.MethodHead) {
		s.redirect(w, s.entry+"/")
		return
	}
	s.serveEntry(w, r, sub)
}

// stripEntry 剥掉随机入口前缀，返回入口内的相对路由（形如 "/"、"/api/rules"）。
//
// 未初始化入口路径（entry == ""）时一律不匹配：宁可 404 也不退化成
// 「整站可达」。serve 启动前已强校验入口存在，这里只是二重保险。
func (s *Server) stripEntry(route string) (string, bool) {
	if s.entry == "" {
		return "", false
	}
	if route == s.entry {
		return "/", true
	}
	if strings.HasPrefix(route, s.entry+"/") {
		rest := route[len(s.entry):]
		if rest == "" {
			return "/", true
		}
		return rest, true
	}
	return "", false
}

// serveEntry 处理入口内的请求。
func (s *Server) serveEntry(w http.ResponseWriter, r *http.Request, route string) {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		if strings.HasPrefix(route, "/api/") {
			if !s.authorized(r) {
				logAuthFailure(r, route)
				s.sendJSON(w, r, http.StatusUnauthorized, M{"error": "unauthorized"})
				return
			}
			s.handleAPIGet(w, r, route)
			return
		}
		s.handleStatic(w, r, route)
	case http.MethodPost:
		switch route {
		case "/login":
			s.handleLogin(w, r)
			return
		case "/logout":
			s.handleLogout(w, r)
			return
		}
		if strings.HasPrefix(route, "/api/") {
			if !s.authorized(r) {
				logAuthFailure(r, route)
				s.sendJSON(w, r, http.StatusUnauthorized, M{"error": "unauthorized"})
				return
			}
			s.handleAPIPost(w, r, route)
			return
		}
		notFound(w, r)
	case http.MethodPut, http.MethodDelete:
		if strings.HasPrefix(route, "/api/") {
			if !s.authorized(r) {
				logAuthFailure(r, route)
				s.sendJSON(w, r, http.StatusUnauthorized, M{"error": "unauthorized"})
				return
			}
			s.handleAPIMut(w, r, route)
			return
		}
		notFound(w, r)
	default:
		// 其它方法（OPTIONS/PATCH/TRACE…）与未知路径同样处理：极简 404。
		// 返回 405 会告诉探测者「这个路径确实存在」，属于不必要的信息泄漏。
		notFound(w, r)
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
	s.send(w, r, code, "application/json; charset=utf-8", data)
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

// dataPlaneReady 报告 nft 数据面是否已完成首轮 enforcement。
//
// 判据取自 policy 层的 Ready()（首轮 reconcile 成功即置位），
// 而不是「HTTP goroutine 是否活着」。
//
// 刻意**不**把运行期偶发的 reconcile 失败算作未就绪：那属于 degraded，
// 不该让 systemd 反复重启整个服务。安装/升级关心的是「首轮是否成功」。
func (s *Server) dataPlaneReady() bool {
	if s.policy == nil {
		return false
	}
	return s.policy.Ready()
}

// ---- 静态资源 ----

// handleStatic 处理入口内的静态资源。
//
// 未登录时只允许拿到登录页与它依赖的样式/脚本；面板本体（index.html、app.js）
// 必须认证后才返回，避免未认证者拿到完整前端从而确认这是 NFT Forward 面板。
func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request, route string) {
	switch route {
	case "/", "/index.html":
		if !s.authorized(r) {
			s.serveAsset(w, r, "login.html", "text/html; charset=utf-8")
			return
		}
		s.serveAsset(w, r, "index.html", "text/html; charset=utf-8")
	case "/login":
		if s.authorized(r) {
			s.redirect(w, s.entry+"/")
			return
		}
		s.serveAsset(w, r, "login.html", "text/html; charset=utf-8")
	case "/login.js":
		s.serveAsset(w, r, "login.js", "application/javascript; charset=utf-8")
	case "/style.css":
		s.serveAsset(w, r, "style.css", "text/css; charset=utf-8")
	case "/app.js":
		if !s.authorized(r) {
			notFound(w, r)
			return
		}
		s.serveAsset(w, r, "app.js", "application/javascript; charset=utf-8")
	default:
		notFound(w, r)
	}
}

func (s *Server) serveAsset(w http.ResponseWriter, r *http.Request, name, ctype string) {
	b, err := assetBytes(name)
	if err != nil {
		notFound(w, r)
		return
	}
	s.send(w, r, http.StatusOK, ctype, b)
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
//
// 传入已构建好的快照，避免为了算 key 再查一次库。
func snapshotStructKey(snap FullSnapshot) string {
	snap.Now = 0
	snap.Rate = traffic.Rate{}
	// Rules 是切片，需要深拷贝一层再清零速率，否则会改到调用方要发布的那份。
	rules := make([]RuleView, len(snap.Rules))
	copy(rules, snap.Rules)
	for i := range rules {
		rules[i].Rate = traffic.Rate{}
	}
	snap.Rules = rules
	b, _ := json.Marshal(snap)
	return string(b)
}

// PublishSnapshotTick 周期兜底广播：仅在有订阅者且结构发生变化时推送。
//
// 快照只构建一次（含两条批量 SQL）：先用它算结构 key，变化时直接发布同一份。
// 旧实现调用 buildFullSnapshot 两次，等于每 2s 白查一遍库。
func (s *Server) PublishSnapshotTick() {
	s.subsMu.Lock()
	n := len(s.subs)
	s.subsMu.Unlock()
	if n == 0 {
		return
	}
	snap := s.buildFullSnapshot()
	key := snapshotStructKey(snap)
	s.lastSnapMu.Lock()
	changed := key != s.lastSnapKey
	if changed {
		s.lastSnapKey = key
	}
	s.lastSnapMu.Unlock()
	if !changed {
		return
	}
	s.PublishSSE("snapshot", snap)
}

// handleEvents 是 SSE 端点：首包完整 snapshot，之后按变化推送。
//
// 认证已在 serveEntry 的 /api/ 分支统一完成 —— SSE 与其它 API 走同一道闸门，
// 不存在「SSE 绕过认证」的旁路。
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
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
	securityHeaders(w.Header())
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store")
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
