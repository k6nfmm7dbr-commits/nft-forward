package api

import (
	"crypto/subtle"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"github.com/k6nfmm7dbr-commits/nft-forward/internal/webui"
)

// cookieName 是会话 Cookie 名（HttpOnly，登录成功后下发）。
const cookieName = "nff_token"

// cookieMaxAge 是会话有效期（秒）：7 天，与 SBX 对齐。
const cookieMaxAge = 604800

// ---- 静态资源读取 ----

// assetBytes 从内嵌前端读取文件。
func assetBytes(name string) ([]byte, error) {
	f, err := webui.FS().Open(strings.TrimLeft(name, "/"))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

// ---- 响应输出 ----

// securityHeaders 写入面板资源的统一安全响应头。
//
// CSP 严格到 default-src 'self'：前端无内联脚本 / 内联样式 / 外部字体 /
// data: 图片，因此不需要任何放宽。base-uri 'none' 防止注入 <base> 改写相对
// 路径（本面板的 API 全部走相对路径，base 被改写等于接口被劫持）。
//
// 刻意不设置 Server / X-Powered-By —— 不主动暴露技术栈（Go 的 net/http
// 默认也不发送 Server 头）。
func securityHeaders(h http.Header) {
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Content-Security-Policy",
		"default-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
}

func (s *Server) send(w http.ResponseWriter, r *http.Request, code int, ctype string, body []byte) {
	securityHeaders(w.Header())
	w.Header().Set("Content-Type", ctype)
	w.WriteHeader(code)
	if r.Method != http.MethodHead && len(body) > 0 {
		_, _ = w.Write(body)
	}
}

func (s *Server) sendText(w http.ResponseWriter, r *http.Request, code int, text string) {
	s.send(w, r, code, "text/plain; charset=utf-8", []byte(text))
}

// notFound 返回极简 404。
//
// 这是「降低公网批量扫描命中与面板指纹暴露面」的核心：未命中随机入口路径的
// 请求（/、/admin、/wp-login.php、/favicon.ico、未知 API…）一律得到同一个
// 无特征响应 —— 不跳转登录页、不含品牌样式、不含版本号、不含程序名、
// 不暴露入口路径或令牌，也不设置任何自证身份的响应头。
func notFound(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	if r.Method != http.MethodHead {
		_, _ = w.Write([]byte("404 page not found\n"))
	}
}

// ---- 鉴权 ----

func (s *Server) token() string { return s.cfg.Token }

// authorized 判定请求是否已认证。
//
// 仅接受两种凭据来源（与 SBX 一致）：
//   - Authorization: Bearer <token>
//   - HttpOnly Cookie nff_token
//
// 刻意 **不接受** `?token=xxx`：URL 里的令牌会进浏览器历史、HTTP access log、
// 反向代理日志与 Referer，是明确的泄漏渠道。
//
// 未配置令牌时返回 false（fail-closed）。serve 启动前已强校验令牌存在，
// 因此正常运行不会走到这里；万一配置被人为清空，宁可全部拒绝也不能全部放行。
func (s *Server) authorized(r *http.Request) bool {
	token := s.token()
	if token == "" {
		return false
	}
	given := bearerToken(r)
	if given == "" {
		given = cookieToken(r)
	}
	return tokenEqual(given, token)
}

// bearerToken 提取 Authorization: Bearer <token>。
func bearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	const p = "Bearer "
	if len(auth) > len(p) && strings.EqualFold(auth[:len(p)], p) {
		return strings.TrimSpace(auth[len(p):])
	}
	return ""
}

// cookieToken 提取会话 Cookie 中的令牌。
func cookieToken(r *http.Request) string {
	c, err := r.Cookie(cookieName)
	if err != nil || c == nil {
		return ""
	}
	return c.Value
}

// tokenEqual 等长度 secret 内容比较（常量时间）。
//
// 长度本身不是保密信息，长度不等直接返回 false；等长内容用
// crypto/subtle.ConstantTimeCompare，避免「首个不同字符的位置」产生
// 可测量的时间差。绝不使用 given == token。
func tokenEqual(given, token string) bool {
	if len(given) != len(token) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(given), []byte(token)) == 1
}

// ---- 会话 Cookie ----

// sessionCookie 构造登录成功后下发的会话 Cookie。
func (s *Server) sessionCookie(token string) *http.Cookie {
	c := &http.Cookie{
		Name:  cookieName,
		Value: token,
		// Path 覆盖整个随机入口（面板所有资源与 API 都在它之下）。
		Path:     s.cookiePath(),
		MaxAge:   cookieMaxAge,
		HttpOnly: true,
		// Lax 而非 Strict：iOS Safari 从书签/外部链接/回访直接打开面板时，
		// Strict 会让 Cookie 不随顶级导航发送，表现就像「没记住登录」。
		// Lax 仍阻止跨站 POST 与隐式子请求携带 Cookie（防 CSRF）。
		SameSite: http.SameSiteLaxMode,
	}
	// 仅当用户显式配置 secure_cookie（前置 HTTPS 反代）时才加 Secure；
	// 不能无条件 Secure=true，否则纯 HTTP 直连登录会失效。
	if s.cfg.SecureCookie {
		c.Secure = true
	}
	return c
}

// cookiePath 返回 Cookie 的 Path：随机入口路径（带前后斜杠）。
func (s *Server) cookiePath() string {
	if s.entry == "" {
		return "/"
	}
	return s.entry + "/"
}

// clearCookie 构造登出用的过期 Cookie。
func (s *Server) clearCookie() *http.Cookie {
	c := s.sessionCookie("")
	c.MaxAge = -1
	return c
}

// ---- 本机判定 ----

// isLoopback 报告请求是否来自本机。
//
// 只看 RemoteAddr —— 绝不信任 X-Forwarded-For / X-Real-IP：那些头可由任意
// 外部客户端伪造，一旦采信，公网扫描器就能把自己伪装成本机拿到健康信息。
func isLoopback(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil {
		return false
	}
	return ip.IsLoopback()
}

// logAuthFailure 记录一次鉴权失败（只记来源与路径，绝不记令牌内容）。
func logAuthFailure(r *http.Request, route string) {
	slog.Debug("拒绝未认证请求", "remote", r.RemoteAddr, "route", route)
}
