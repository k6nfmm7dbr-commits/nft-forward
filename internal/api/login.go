package api

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// maxLoginBody 限制登录表单体大小（64 KiB，与 SBX 一致）。
const maxLoginBody = 64 << 10

// 登录失败节流参数：同一来源 IP 连续失败达 loginFailBurst 次后，
// 每次尝试强制等待 loginFailDelay，并在 loginFailWindow 内累计。
// 32 hex token 暴破本不现实，但节流能挡住日志刷屏与凭据喷洒。
const (
	loginFailBurst  = 5
	loginFailWindow = 5 * time.Minute
	loginFailDelay  = 2 * time.Second
	loginFailMaxLen = 4096 // 追踪表上限，防内存被大量伪造源 IP 撑大
)

type loginFailState struct {
	count int
	last  time.Time
}

var (
	loginFailMu sync.Mutex
	loginFails  = map[string]*loginFailState{}
)

// loginClientKey 取来源标识。刻意只用 RemoteAddr 的 IP 部分，不信任
// X-Forwarded-For（可伪造：攻击者每次换头即可绕过节流，并把追踪表撑大）。
func loginClientKey(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// loginThrottle 返回本次请求应额外等待的时长。
func loginThrottle(key string, now time.Time) time.Duration {
	loginFailMu.Lock()
	defer loginFailMu.Unlock()
	gcLoginFailsLocked(now)
	st, ok := loginFails[key]
	if !ok || now.Sub(st.last) > loginFailWindow {
		return 0
	}
	if st.count < loginFailBurst {
		return 0
	}
	return loginFailDelay
}

func loginRecordFail(key string, now time.Time) {
	loginFailMu.Lock()
	defer loginFailMu.Unlock()
	gcLoginFailsLocked(now)
	st, ok := loginFails[key]
	if !ok || now.Sub(st.last) > loginFailWindow {
		if len(loginFails) >= loginFailMaxLen {
			return // 表已满：放弃记录而不是无界增长（失败仍会被拒绝）
		}
		loginFails[key] = &loginFailState{count: 1, last: now}
		return
	}
	st.count++
	st.last = now
}

func loginRecordSuccess(key string) {
	loginFailMu.Lock()
	defer loginFailMu.Unlock()
	delete(loginFails, key)
}

// gcLoginFailsLocked 清理过期条目（调用方持锁）。
func gcLoginFailsLocked(now time.Time) {
	for k, st := range loginFails {
		if now.Sub(st.last) > loginFailWindow {
			delete(loginFails, k)
		}
	}
}

// handleLogin 处理 <entry>/login 的 POST：提交令牌，成功后下发 HttpOnly
// 会话 Cookie 并重定向到面板首页。令牌绝不出现在 URL 里。
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxLoginBody+1))
	if err != nil {
		s.redirect(w, s.entry+"/login?error=1")
		return
	}
	// 超限必须 413 拒绝，不得截断后继续解析（否则可能构造部分令牌绕过）。
	if len(body) > maxLoginBody {
		s.sendText(w, r, http.StatusRequestEntityTooLarge, "request body too large")
		return
	}
	given := parseLoginToken(r.Header.Get("Content-Type"), body)
	key := loginClientKey(r)
	now := time.Now()

	if token := s.token(); token != "" && tokenEqual(given, token) {
		// 成功路径绝不延迟：节流只惩罚失败尝试。
		// （SBX 早期把 sleep 放在校验之前，导致手滑几次后即使输对也要等 2s。
		//  对攻击者的限速效果两种写法等价 —— 失败请求同样会占住连接 2s。）
		loginRecordSuccess(key)
		http.SetCookie(w, s.sessionCookie(token))
		s.redirect(w, s.entry+"/")
		return
	}
	// 失败：先记账，再按累计失败次数施加延迟（挡凭据喷洒与日志刷屏）。
	loginRecordFail(key, now)
	if d := loginThrottle(key, now); d > 0 {
		select {
		case <-time.After(d):
		case <-r.Context().Done():
			return
		}
	}
	s.redirect(w, s.entry+"/login?error=1")
}

// parseLoginToken 从请求体里取出令牌，兼容表单与 JSON 两种提交方式。
func parseLoginToken(contentType string, body []byte) string {
	if strings.Contains(strings.ToLower(contentType), "application/json") {
		var payload struct {
			Token string `json:"token"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			return ""
		}
		return payload.Token
	}
	vals, err := url.ParseQuery(string(body))
	if err != nil {
		return ""
	}
	for _, v := range vals["token"] {
		if v != "" {
			return v
		}
	}
	return ""
}

// handleLogout 清除会话 Cookie 并回到登录页。
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, s.clearCookie())
	s.redirect(w, s.entry+"/login")
}

func (s *Server) redirect(w http.ResponseWriter, location string) {
	securityHeaders(w.Header())
	w.Header().Set("Location", location)
	w.WriteHeader(http.StatusFound)
}
