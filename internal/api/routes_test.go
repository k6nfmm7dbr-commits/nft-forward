package api

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// ---- 未授权者不得触达任何 API（含所有方法与子路径）----

// 逐一枚举全部 API 路由，确认未认证时统一 401，且响应体不含业务数据。
func TestAllAPIRoutesRequireAuth(t *testing.T) {
	ts, _ := newTestServer(t)
	type req struct{ method, path string }
	routes := []req{
		{http.MethodGet, "/api/healthz"},
		{http.MethodGet, "/api/health"},
		{http.MethodGet, "/api/summary"},
		{http.MethodGet, "/api/live"},
		{http.MethodGet, "/api/daily"},
		{http.MethodGet, "/api/rules"},
		{http.MethodGet, "/api/rules/1"},
		{http.MethodGet, "/api/rules/1/daily"},
		{http.MethodGet, "/api/rules/1/ips"},
		{http.MethodGet, "/api/events"},
		{http.MethodPost, "/api/rules"},
		{http.MethodPost, "/api/rules/1/enable"},
		{http.MethodPost, "/api/rules/1/disable"},
		{http.MethodPost, "/api/rules/1/quota/reset"},
		{http.MethodPut, "/api/rules/1"},
		{http.MethodPut, "/api/rules/1/policy"},
		{http.MethodDelete, "/api/rules/1"},
	}
	client := noRedirectClient()
	for _, rt := range routes {
		r, err := http.NewRequest(rt.method, ts.URL+entry(rt.path), strings.NewReader("{}"))
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%s %s 未认证应 401，实际 %d", rt.method, rt.path, resp.StatusCode)
		}
		if strings.Contains(string(body), "rules") && !strings.Contains(string(body), "unauthorized") {
			t.Fatalf("%s %s 401 响应泄漏了业务数据: %s", rt.method, rt.path, body)
		}
	}
}

// 认证后 API 可用（同一组路由的正向验证，确保 401 不是因为路由本身坏了）。
func TestAPIRoutesWorkWithAuth(t *testing.T) {
	ts, _ := newTestServer(t)
	hdr := map[string]string{"Authorization": "Bearer " + testToken}
	for _, p := range []string{"/api/healthz", "/api/health", "/api/summary", "/api/live", "/api/daily", "/api/rules"} {
		resp := get(t, ts, entry(p), hdr)
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s 认证后应 200，实际 %d（%s）", p, resp.StatusCode, body)
		}
	}
}

// /api/health 不得泄漏令牌、入口路径、文件路径。
func TestHealthViewHasNoSecrets(t *testing.T) {
	ts, _ := newTestServer(t)
	resp := get(t, ts, entry("/api/health"), map[string]string{"Authorization": "Bearer " + testToken})
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	text := string(body)
	for _, leak := range []string{testToken, testEntry, "panel.json", "traffic.db", "/etc/"} {
		if strings.Contains(text, leak) {
			t.Fatalf("/api/health 泄漏了 %q: %s", leak, text)
		}
	}
	var hv map[string]any
	if err := json.Unmarshal(body, &hv); err != nil {
		t.Fatalf("health 响应不是合法 JSON: %v", err)
	}
	for _, k := range []string{"token", "entry_path", "listen", "db"} {
		if _, ok := hv[k]; ok {
			t.Fatalf("/api/health 不应包含字段 %q", k)
		}
	}
}

// 未知方法与未知路径都返回极简 404（不返回 405 —— 那会确认路径存在）。
func TestUnknownMethodReturns404(t *testing.T) {
	ts, _ := newTestServer(t)
	client := noRedirectClient()
	for _, m := range []string{http.MethodOptions, http.MethodPatch, "TRACE"} {
		r, err := http.NewRequest(m, ts.URL+entry("/"), nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("%s 应返回 404，实际 %d", m, resp.StatusCode)
		}
		if strings.Contains(string(body), "method not allowed") {
			t.Fatalf("%s 不应回复 method not allowed（会确认路径存在）", m)
		}
	}
}

// HEAD 请求不得返回响应体（但状态码与头要正确）。
func TestHeadReturnsNoBody(t *testing.T) {
	ts, _ := newTestServer(t)
	r, err := http.NewRequest(http.MethodHead, ts.URL+entry("/"), nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := noRedirectClient().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("HEAD 入口应 200，实际 %d", resp.StatusCode)
	}
	if len(body) != 0 {
		t.Fatalf("HEAD 不应有响应体，实际 %d 字节", len(body))
	}
	if resp.Header.Get("Content-Security-Policy") == "" {
		t.Fatal("HEAD 响应也应带安全头")
	}
}

// SSE 端点在认证后可用，且首包是 snapshot。
func TestSSERequiresAuthAndSendsSnapshot(t *testing.T) {
	ts, _ := newTestServer(t)
	// 未认证
	resp := get(t, ts, entry("/api/events"), nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("SSE 未认证应 401，实际 %d", resp.StatusCode)
	}
	// 认证后读首包
	req, err := http.NewRequest(http.MethodGet, ts.URL+entry("/api/events"), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+testToken)
	resp2, err := noRedirectClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("SSE 认证后应 200，实际 %d", resp2.StatusCode)
	}
	if ct := resp2.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("SSE Content-Type 错误: %q", ct)
	}
	buf := make([]byte, 64)
	n, _ := resp2.Body.Read(buf)
	if !strings.Contains(string(buf[:n]), "event: snapshot") {
		t.Fatalf("SSE 首包应为 snapshot，实际 %q", buf[:n])
	}
}
