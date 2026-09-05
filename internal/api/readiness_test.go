package api

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

// ---- 数据面 readiness（v0.3.2）----
//
// 旧行为：/healthz 只要 Go HTTP 线程活着就返回 200。于是
// 「HTTP 正常 + systemd active + healthz 200，但首轮 policy.Reconcile 失败」
// 会被安装器/升级器当成健康 —— 转发数据面其实根本没加载。
//
// 现在 /healthz 的 200 严格代表「已完成首轮 nft 数据面 enforcement」。

// 首轮 enforcement 未完成 → 503，且响应体明确说明原因。
func TestHealthzReturns503BeforeDataPlaneReady(t *testing.T) {
	ts, s := newNotReadyServer(t)
	if s.dataPlaneReady() {
		t.Fatal("前置条件失败：本应处于未就绪状态")
	}
	resp := get(t, ts, "/healthz", nil)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("数据面未就绪时 /healthz 应 503，实际 %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), `"ok":false`) {
		t.Fatalf("503 响应应含 ok:false，实际 %s", body)
	}
	// 即便是 503，也不得泄漏产品名 / 版本 / 入口 / 令牌。
	for _, leak := range []string{"NFT", "nft-forward", "nftables", testToken, testEntry} {
		if strings.Contains(string(body), leak) {
			t.Fatalf("503 响应泄漏了 %q: %s", leak, body)
		}
	}
	// 安全头照旧。
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("503 响应也应带 Cache-Control: no-store")
	}
}

// 首轮 enforcement 成功后 → 200。
func TestHealthzReturns200AfterDataPlaneReady(t *testing.T) {
	ts, s := newTestServer(t) // 构造函数内部已跑过一次成功 reconcile
	if !s.dataPlaneReady() {
		t.Fatal("前置条件失败：应已就绪")
	}
	resp := get(t, ts, "/healthz", nil)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("就绪后 /healthz 应 200，实际 %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), `"ok":true`) {
		t.Fatalf("200 响应应含 ok:true，实际 %s", body)
	}
}

// 未就绪状态下，非 loopback 仍然是 404（不得因 503 泄漏服务存在）。
func TestHealthzNotReadyStillHiddenFromNonLoopback(t *testing.T) {
	_, s := newNotReadyServer(t)
	req, err := http.NewRequest(http.MethodGet, "http://example.invalid/healthz", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.RemoteAddr = "203.0.113.9:1234"
	rr := newRecorder()
	s.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("非 loopback 访问应 404（不论就绪状态），实际 %d", rr.Code)
	}
}

// 未就绪不影响认证与入口语义：面板本身仍按原规则工作
// （安装器据 healthz 判断健康，用户可正常登录排查）。
func TestNotReadyStillEnforcesAuthAndEntry(t *testing.T) {
	ts, _ := newNotReadyServer(t)
	// 根路径仍 404
	r1 := get(t, ts, "/", nil)
	r1.Body.Close()
	if r1.StatusCode != http.StatusNotFound {
		t.Fatalf("根路径应 404，实际 %d", r1.StatusCode)
	}
	// 未认证 API 仍 401
	r2 := get(t, ts, entry("/api/summary"), nil)
	r2.Body.Close()
	if r2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("未认证 API 应 401，实际 %d", r2.StatusCode)
	}
	// 入口根仍返回登录页
	r3 := get(t, ts, entry("/"), nil)
	r3.Body.Close()
	if r3.StatusCode != http.StatusOK {
		t.Fatalf("入口根应 200（登录页），实际 %d", r3.StatusCode)
	}
}

// /api/health 应反映 policy_ready（供面板 UI 与人工排查）。
func TestAPIHealthReflectsReadiness(t *testing.T) {
	ts, _ := newNotReadyServer(t)
	resp := get(t, ts, entry("/api/health"), map[string]string{"Authorization": "Bearer " + testToken})
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/api/health 本身应可访问，实际 %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), `"policy_ready":false`) {
		t.Fatalf("未就绪时 policy_ready 应为 false，实际 %s", body)
	}
	if strings.Contains(string(body), `"ok":true`) {
		t.Fatalf("未就绪时整体 ok 不应为 true，实际 %s", body)
	}
}
