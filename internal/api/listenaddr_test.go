package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/k6nfmm7dbr-commits/nft-forward/internal/forward"
)

// ---- 规则模型/API/UI 里不得再有「监听地址」（v0.3.2）----
//
// 之前为了「让用户知道连哪个 IP」加过一个只读 listen_addr（启动期探测的本机
// 对外 IP）。那是主机属性而非规则属性：多网卡/多 IP 时必然是错的，
// 还会让人误以为规则只监听那一个地址。现在彻底移除。

// seedRuleFor 在测试服务器的库里插一条规则。
func seedRuleFor(t *testing.T, s *Server) int64 {
	t.Helper()
	id, err := s.store.Create(context.Background(), &forward.Rule{
		Name: "r1", Enabled: true, Protocol: forward.ProtoTCPUDP,
		ListenPort: 20000, TargetAddress: "10.0.0.2", TargetPort: 80,
	})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// API 的规则视图里不得出现 listen_addr 之类字段。
func TestRuleViewHasNoListenAddr(t *testing.T) {
	ts, s := newTestServer(t)
	seedRuleFor(t, s)
	hdr := map[string]string{"Authorization": "Bearer " + testToken}

	for _, path := range []string{"/api/rules", "/api/summary"} {
		resp := get(t, ts, entry(path), hdr)
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s 应 200，实际 %d", path, resp.StatusCode)
		}
		text := string(body)
		for _, bad := range []string{"listen_addr", "listenAddr", "listen_address"} {
			if strings.Contains(text, bad) {
				t.Fatalf("%s 响应仍含 %q: %s", path, bad, text)
			}
		}
		// 监听端口必须保留（那是真实的规则属性）。
		if !strings.Contains(text, "listen_port") {
			t.Fatalf("%s 响应应含 listen_port: %s", path, text)
		}
	}
}

// 单规则详情同样不得有 listen_addr。
func TestRuleDetailHasNoListenAddr(t *testing.T) {
	ts, s := newTestServer(t)
	id := seedRuleFor(t, s)
	hdr := map[string]string{"Authorization": "Bearer " + testToken}

	resp := get(t, ts, entry("/api/rules/"+itoa64(id)), hdr)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("详情应 200，实际 %d", resp.StatusCode)
	}
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("响应不是合法 JSON: %v", err)
	}
	for _, bad := range []string{"listen_addr", "listenAddr", "listen_address"} {
		if _, ok := m[bad]; ok {
			t.Fatalf("详情仍含字段 %q", bad)
		}
	}
	if _, ok := m["listen_port"]; !ok {
		t.Fatal("详情应含 listen_port")
	}
}

// SSE 首包快照同样不得有 listen_addr。
func TestSSESnapshotHasNoListenAddr(t *testing.T) {
	ts, s := newTestServer(t)
	seedRuleFor(t, s)

	req, err := http.NewRequest(http.MethodGet, ts.URL+entry("/api/events"), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+testToken)
	resp, err := noRedirectClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	buf := make([]byte, 8192)
	n, _ := resp.Body.Read(buf)
	first := string(buf[:n])
	if !strings.Contains(first, "event: snapshot") {
		t.Fatalf("首包应是 snapshot，实际 %q", first)
	}
	for _, bad := range []string{"listen_addr", "listenAddr", "listen_address"} {
		if strings.Contains(first, bad) {
			t.Fatalf("SSE 快照仍含 %q: %s", bad, first)
		}
	}
}

// 前端资源里不得再有监听地址相关的 DOM/逻辑。
func TestFrontendHasNoListenAddr(t *testing.T) {
	for _, name := range []string{"index.html", "app.js", "login.html", "login.js", "style.css"} {
		b, err := assetBytes(name)
		if err != nil {
			t.Fatalf("读取 %s 失败: %v", name, err)
		}
		text := string(b)
		for _, bad := range []string{"listen_addr", "listenAddr", "pol-listen-ip", "监听 IP", "监听地址"} {
			if strings.Contains(text, bad) {
				t.Fatalf("%s 仍含 %q", name, bad)
			}
		}
	}
	// 监听端口相关的 UI 必须保留。
	idx, err := assetBytes("index.html")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(idx), "监听端口") {
		t.Fatal("index.html 应保留「监听端口」字段")
	}
}

// 老客户端仍可发送 listen_address（被接受并忽略），不得因此报错。
func TestCreateRuleStillAcceptsLegacyListenAddress(t *testing.T) {
	ts, _ := newTestServer(t)
	body := `{"name":"legacy","protocol":"tcp","listen_port":20777,` +
		`"target_address":"10.0.0.5","target_port":80,"listen_address":"0.0.0.0"}`
	req, err := http.NewRequest(http.MethodPost, ts.URL+entry("/api/rules"), strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := noRedirectClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	// rulesvc 的 enforcer 为 nil（测试配置），因此这里只要求「不是 400 参数错误」。
	if resp.StatusCode == http.StatusBadRequest {
		t.Fatalf("含 listen_address 的老请求不应被拒绝: %s", out)
	}
	// 响应里也不能回显 listen_addr。
	if strings.Contains(string(out), "listen_addr") {
		t.Fatalf("响应不应含 listen_addr: %s", out)
	}
}

func itoa64(v int64) string {
	if v == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	neg := v < 0
	if neg {
		v = -v
	}
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
