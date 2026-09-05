package api

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/k6nfmm7dbr-commits/nft-forward/internal/config"
	"github.com/k6nfmm7dbr-commits/nft-forward/internal/database"
	"github.com/k6nfmm7dbr-commits/nft-forward/internal/forward"
	"github.com/k6nfmm7dbr-commits/nft-forward/internal/policy"
	"github.com/k6nfmm7dbr-commits/nft-forward/internal/rulesvc"
	"github.com/k6nfmm7dbr-commits/nft-forward/internal/traffic"
)

// 测试用固定值（都是 32 位十六进制 / 24 位十六进制，形态与真实生成一致）。
const (
	testToken = "0123456789abcdef0123456789abcdef"
	testEntry = "3e4f65a8c24d2bd5b9e80147"
)

// newTestServer 构造一台完整的面板（真实 DB / store / policy / collector）。
//
// 刻意不 mock Server：认证、随机入口、404 语义都是路由层行为，
// 必须用真正的 http.Handler 跑真实请求才有意义。
func newTestServer(t *testing.T) (*httptest.Server, *Server) {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "traffic.db")
	db, err := database.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		DB:        dbPath,
		NftConf:   filepath.Join(dir, "nft.conf"),
		Listen:    "127.0.0.1",
		Port:      10001,
		Interval:  2,
		TZ:        "UTC",
		Token:     testToken,
		EntryPath: testEntry,
	}
	store := forward.NewStore(db.DB)
	pol := policy.New(db.DB, store, nil, cfg.NftConf, "")
	collect := traffic.NewCollector(db, nil, cfg.TZ)
	rules := rulesvc.New(store, nil, nil, func() forward.GuardPorts { return forward.GuardPorts{} })
	s, _ := New(cfg, db, store, pol, rules, collect)
	ts := httptest.NewServer(s.recover(s))
	t.Cleanup(func() { ts.Close(); db.Close() })
	return ts, s
}

// noRedirectClient 返回不自动跟随重定向的客户端（要断言 302 与 Set-Cookie）。
func noRedirectClient() *http.Client {
	return &http.Client{
		Timeout:       5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func get(t *testing.T, ts *httptest.Server, path string, hdr map[string]string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, ts.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := noRedirectClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func entry(path string) string { return "/" + testEntry + path }

// newRecorder 返回一个 httptest.ResponseRecorder（用于直接调 ServeHTTP，
// 以便自定义 RemoteAddr 测试 loopback 判定）。
func newRecorder() *httptest.ResponseRecorder { return httptest.NewRecorder() }
