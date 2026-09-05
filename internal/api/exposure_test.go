package api

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

// ---- 随机入口路径与 404 语义 ----

// 未命中随机入口的一切请求都必须返回极简 404：
// 不跳登录页、不含品牌/版本/技术栈、不泄漏入口路径或令牌。
func TestNonEntryPathsReturnPlain404(t *testing.T) {
	ts, _ := newTestServer(t)
	paths := []string{
		"/", "/index.html", "/app.js", "/style.css", "/login", "/logout",
		"/admin", "/wp-login.php", "/favicon.ico", "/robots.txt",
		"/api/summary", "/api/health", "/api/events",
		"/phpmyadmin/", "/.env", "/.git/config", "/actuator/health",
		"/" + strings.Repeat("a", 24) + "/", // 错误的随机路径
		"/" + testEntry + "x/",              // 前缀相似但不相等
		"/x" + testEntry + "/",
	}
	for _, p := range paths {
		resp := get(t, ts, p, nil)
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("%s 应返回 404，实际 %d", p, resp.StatusCode)
		}
		text := string(body)
		for _, leak := range []string{
			"NFF", "nff", "NFT Forward", "nft-forward", "nftables",
			"访问令牌", "登录", "面板", testToken, testEntry,
		} {
			if strings.Contains(text, leak) {
				t.Fatalf("404 响应泄漏了 %q（路径 %s）:\n%s", leak, p, text)
			}
		}
		// 不得自证身份的响应头
		for _, h := range []string{"Server", "X-Powered-By"} {
			if v := resp.Header.Get(h); v != "" {
				t.Fatalf("404 不应设置 %s 头（实际 %q）", h, v)
			}
		}
		if loc := resp.Header.Get("Location"); loc != "" {
			t.Fatalf("404 不得跳转（Location=%q）", loc)
		}
	}
}

// 带正确令牌访问错误路径同样是 404（路径未命中优先于认证）。
func TestWrongPathWithValidTokenStill404(t *testing.T) {
	ts, _ := newTestServer(t)
	for _, p := range []string{"/", "/api/summary", "/admin"} {
		resp := get(t, ts, p, map[string]string{"Authorization": "Bearer " + testToken})
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("%s 带正确令牌也应 404，实际 %d", p, resp.StatusCode)
		}
	}
}

// 正确随机入口 → 显示登录页（这才是唯一的入口）。
func TestCorrectEntryShowsLoginPage(t *testing.T) {
	ts, _ := newTestServer(t)
	resp := get(t, ts, entry("/"), nil)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("正确入口应 200，实际 %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), "访问令牌") {
		t.Fatal("应返回登录页")
	}
	// 登录页也不应暴露产品名/版本。
	for _, leak := range []string{"NFT Forward", "nft-forward", "nftables", "v0.3"} {
		if strings.Contains(string(body), leak) {
			t.Fatalf("登录页泄漏了 %q", leak)
		}
	}
}

// 入口无尾斜杠时重定向到带斜杠版本（前端相对路径依赖它）。
func TestEntryWithoutTrailingSlashRedirects(t *testing.T) {
	ts, _ := newTestServer(t)
	resp := get(t, ts, "/"+testEntry, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("无尾斜杠应 302，实际 %d", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != entry("/") {
		t.Fatalf("应重定向到 %s，实际 %q", entry("/"), loc)
	}
}

// 随机入口 ≠ 认证：知道入口但没有令牌，API 一律 401。
func TestEntryPathIsNotAuthentication(t *testing.T) {
	ts, _ := newTestServer(t)
	resp := get(t, ts, entry("/api/summary"), nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("入口路径不能替代认证，应 401，实际 %d", resp.StatusCode)
	}
}

// 入口路径与令牌完全独立：不能用令牌当入口，也不能用入口当令牌。
func TestEntryAndTokenIndependent(t *testing.T) {
	ts, _ := newTestServer(t)
	// 用令牌当路径 → 404
	resp := get(t, ts, "/"+testToken+"/", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("令牌不得作为入口路径，应 404，实际 %d", resp.StatusCode)
	}
	// 用入口路径当令牌 → 401
	resp2 := get(t, ts, entry("/api/healthz"), map[string]string{"Authorization": "Bearer " + testEntry})
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("入口路径不得作为令牌，应 401，实际 %d", resp2.StatusCode)
	}
}

// ---- /healthz 只允许 loopback ----

// httptest 的客户端来自 127.0.0.1，因此裸 /healthz 应可用。
func TestHealthzAllowedFromLoopback(t *testing.T) {
	ts, _ := newTestServer(t)
	resp := get(t, ts, "/healthz", nil)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("loopback 访问 /healthz 应 200，实际 %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), `"ok":true`) {
		t.Fatalf("healthz 响应异常: %s", body)
	}
	// 即便是 loopback，也只返回存活标记，不含版本/路径/令牌等信息。
	for _, leak := range []string{"NFT", "nft", "version", testToken, testEntry} {
		if strings.Contains(string(body), leak) {
			t.Fatalf("healthz 泄漏了 %q: %s", leak, body)
		}
	}
}

// 非 loopback 来源的 /healthz 必须与未知路径一样得到普通 404。
func TestHealthzHiddenFromNonLoopback(t *testing.T) {
	_, s := newTestServer(t)
	for _, remote := range []string{"203.0.113.9:1234", "8.8.8.8:443", "[2001:db8::1]:80"} {
		req, err := http.NewRequest(http.MethodGet, "http://example.invalid/healthz", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.RemoteAddr = remote
		rr := newRecorder()
		s.ServeHTTP(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("来自 %s 的 /healthz 应 404，实际 %d", remote, rr.Code)
		}
		if strings.Contains(rr.Body.String(), "ok") {
			t.Fatalf("非本机不得看到健康信息: %s", rr.Body.String())
		}
	}
}

// 伪造 X-Forwarded-For 不能把自己变成 loopback。
func TestHealthzIgnoresForwardedFor(t *testing.T) {
	_, s := newTestServer(t)
	req, err := http.NewRequest(http.MethodGet, "http://example.invalid/healthz", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.RemoteAddr = "203.0.113.9:1234"
	req.Header.Set("X-Forwarded-For", "127.0.0.1")
	req.Header.Set("X-Real-IP", "127.0.0.1")
	rr := newRecorder()
	s.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("伪造 XFF 不得绕过 loopback 限制，应 404，实际 %d", rr.Code)
	}
}

// ---- 安全响应头 ----

func TestSecurityHeadersOnPanelResponses(t *testing.T) {
	ts, _ := newTestServer(t)
	for _, p := range []string{"/", "/login", "/style.css"} {
		resp := get(t, ts, entry(p), nil)
		resp.Body.Close()
		h := resp.Header
		if h.Get("Cache-Control") != "no-store" {
			t.Fatalf("%s 缺少 Cache-Control: no-store（实际 %q）", p, h.Get("Cache-Control"))
		}
		if h.Get("X-Content-Type-Options") != "nosniff" {
			t.Fatalf("%s 缺少 nosniff", p)
		}
		if h.Get("Referrer-Policy") != "no-referrer" {
			t.Fatalf("%s 缺少 Referrer-Policy: no-referrer", p)
		}
		if h.Get("X-Frame-Options") != "DENY" {
			t.Fatalf("%s 缺少 X-Frame-Options: DENY", p)
		}
		csp := h.Get("Content-Security-Policy")
		if !strings.Contains(csp, "default-src 'self'") {
			t.Fatalf("%s CSP 应为 default-src 'self'，实际 %q", p, csp)
		}
		for _, bad := range []string{"unsafe-eval", "unsafe-inline", "*"} {
			if strings.Contains(csp, bad) {
				t.Fatalf("CSP 不得包含 %q：%s", bad, csp)
			}
		}
		if h.Get("Server") != "" || h.Get("X-Powered-By") != "" {
			t.Fatal("不得暴露 Server / X-Powered-By")
		}
	}
}

// 认证后的 API 响应同样带安全头。
func TestSecurityHeadersOnAPI(t *testing.T) {
	ts, _ := newTestServer(t)
	resp := get(t, ts, entry("/api/healthz"), map[string]string{"Authorization": "Bearer " + testToken})
	resp.Body.Close()
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("API 响应缺少 Cache-Control: no-store")
	}
	if resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("API 响应缺少 nosniff")
	}
}
