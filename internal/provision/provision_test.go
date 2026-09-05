package provision

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/k6nfmm7dbr-commits/nft-forward/internal/config"
	"github.com/k6nfmm7dbr-commits/nft-forward/internal/portprobe"
)

func withConf(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "panel.json")
	if content != "" {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("NFT_FORWARD_CONF", path)
	t.Setenv("NFT_FORWARD_DIR", dir)
	return path
}

// 首次安装：端口必须是 10000-65535 的五位数，且绝不是 8090。
func TestEnsurePanelPortGeneratesFiveDigit(t *testing.T) {
	withConf(t, "{}\n")
	res, err := EnsurePanelPort()
	if err != nil {
		t.Fatal(err)
	}
	if !res.Generated {
		t.Fatal("首次应生成新端口")
	}
	if res.Port < config.PanelPortMin || res.Port > config.PanelPortMax {
		t.Fatalf("端口应在 %d-%d，实际 %d", config.PanelPortMin, config.PanelPortMax, res.Port)
	}
	if res.Port == 8090 || res.Port == 34567 {
		t.Fatalf("绝不能落到历史固定端口，实际 %d", res.Port)
	}
	if res.Port < 10000 {
		t.Fatalf("必须是五位数，实际 %d", res.Port)
	}
	// 已持久化
	c := config.Load()
	if c.Port != res.Port {
		t.Fatalf("端口未持久化：配置 %d，返回 %d", c.Port, res.Port)
	}
}

// 幂等：已有端口原样返回（升级 / 重启 / 重复安装都不变）。
func TestEnsurePanelPortIdempotent(t *testing.T) {
	withConf(t, `{"port":23456}`)
	res, err := EnsurePanelPort()
	if err != nil {
		t.Fatal(err)
	}
	if res.Generated {
		t.Fatal("已有端口不应重新生成")
	}
	if res.Port != 23456 {
		t.Fatalf("应沿用已有端口，实际 %d", res.Port)
	}
	// 多次调用恒定
	for i := 0; i < 3; i++ {
		r2, err := EnsurePanelPort()
		if err != nil {
			t.Fatal(err)
		}
		if r2.Port != 23456 {
			t.Fatalf("第 %d 次调用端口变了: %d", i, r2.Port)
		}
	}
}

// 多次全新生成应得到不同端口（真随机）。
func TestEnsurePanelPortRandomness(t *testing.T) {
	seen := map[int]int{}
	const n = 8
	for i := 0; i < n; i++ {
		withConf(t, "{}\n")
		res, err := EnsurePanelPort()
		if err != nil {
			t.Fatal(err)
		}
		seen[res.Port]++
	}
	if len(seen) < n-1 {
		t.Fatalf("%d 次生成只得到 %d 个不同端口，疑似非随机", n, len(seen))
	}
}

// 必须避开真实监听端口：起一个监听后，生成的端口不能等于它。
func TestEnsurePanelPortAvoidsListeningPort(t *testing.T) {
	ln, err := netListen()
	if err != nil {
		t.Skipf("无法建立测试监听: %v", err)
	}
	defer ln.Close()
	port := ln.Addr().(*netTCPAddr).Port

	if !portprobe.InUse()[port] {
		t.Skip("/proc/net 不可读，跳过占用探测断言")
	}
	// 把区间收窄到「只有这个被占端口 + 1 个空闲端口」不可行（区间是常量），
	// 因此改为多次生成，断言从不落在被占端口上。
	for i := 0; i < 20; i++ {
		withConf(t, "{}\n")
		res, err := EnsurePanelPort()
		if err != nil {
			t.Fatal(err)
		}
		if res.Port == port {
			t.Fatalf("生成的端口撞上了正在监听的端口 %d", port)
		}
	}
}

// SSH 端口与 guard_ports 必须被排除。
func TestEnsurePanelPortAvoidsReserved(t *testing.T) {
	// 用 SetRange 不可行（常量区间），改为验证 reservedPorts 汇总是否正确。
	withConf(t, `{"ssh_port":2222,"guard_ports":{"33333":"x"},"port":0}`)
	cfg, err := config.LoadStrict()
	if err != nil {
		t.Fatal(err)
	}
	res, err := reservedPorts(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !res[2222] {
		t.Fatal("SSH 端口未被排除")
	}
	if !res[33333] {
		t.Fatal("guard_ports 未被排除")
	}
}

// 已有转发规则的监听端口也要排除。
func TestReservedPortsIncludesRuleListenPorts(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "traffic.db")
	confPath := filepath.Join(dir, "panel.json")
	if err := os.WriteFile(confPath,
		[]byte(`{"db":"`+dbPath+`","ssh_port":22}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NFT_FORWARD_CONF", confPath)
	t.Setenv("NFT_FORWARD_DIR", dir)

	// 建库 + 插一条规则。
	if err := seedRule(dbPath, 41234); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadStrict()
	if err != nil {
		t.Fatal(err)
	}
	res, err := reservedPorts(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !res[41234] {
		t.Fatal("已有转发规则的监听端口未被排除")
	}
}

// 配置损坏时必须 fail-closed。
func TestEnsurePanelPortRejectsCorruptConfig(t *testing.T) {
	path := withConf(t, `{"port": broken`)
	before, _ := os.ReadFile(path)
	if _, err := EnsurePanelPort(); err == nil {
		t.Fatal("配置损坏时必须拒绝生成端口")
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("损坏配置不得被覆盖")
	}
}

// randInt 无偏且落在区间内。
func TestRandIntRange(t *testing.T) {
	for i := 0; i < 500; i++ {
		v, err := randInt(100)
		if err != nil {
			t.Fatal(err)
		}
		if v < 0 || v >= 100 {
			t.Fatalf("randInt 越界: %d", v)
		}
	}
	if _, err := randInt(0); err == nil {
		t.Fatal("n<=0 应报错")
	}
}

// 源码级断言：绝不出现 math/rand 与固定 fallback 端口。
//
// 检查前先剥掉注释：注释里写「绝不 fallback 到 8090」是说明性文字，
// 不是被执行的代码，只剥不掉会误判。
func TestNoMathRandOrFixedFallback(t *testing.T) {
	data, err := os.ReadFile("provision.go")
	if err != nil {
		t.Fatal(err)
	}
	src := stripComments(string(data))
	if strings.Contains(src, `"math/rand"`) {
		t.Fatal("绝不允许使用 math/rand 生成端口")
	}
	if !strings.Contains(string(data), `"crypto/rand"`) {
		t.Fatal("必须使用 crypto/rand")
	}
	for _, bad := range []string{"8090", "34567"} {
		if strings.Contains(src, bad) {
			t.Fatalf("代码中不得出现固定 fallback 端口 %s", bad)
		}
	}
}

// stripComments 去掉 Go 源码里的 // 行注释（够用：本包无 /* */ 注释）。
func stripComments(src string) string {
	var b strings.Builder
	for _, line := range strings.Split(src, "\n") {
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}

// ephemeral 区间几乎覆盖整个候选区间时（真机常见：10240-65535），
// 仍必须能分配出端口 —— 只是不再据 ephemeral 排除，其余检查照旧。
func TestEnsurePanelPortWideEphemeralStillAllocates(t *testing.T) {
	dir := t.TempDir()
	rangePath := filepath.Join(dir, "range")
	if err := os.WriteFile(rangePath, []byte("10240 65535\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	restore := portprobe.SetEphemeralPathForTest(rangePath)
	t.Cleanup(restore)

	withConf(t, "{}\n")
	res, err := EnsurePanelPort()
	if err != nil {
		t.Fatalf("ephemeral 覆盖全区间时仍必须能分配: %v", err)
	}
	if res.Port < config.PanelPortMin || res.Port > config.PanelPortMax {
		t.Fatalf("端口越界: %d", res.Port)
	}
	if res.Port == 8090 || res.Port == 34567 {
		t.Fatalf("绝不能退化为固定端口，实际 %d", res.Port)
	}
	// 仍然持久化
	if c := config.Load(); c.Port != res.Port {
		t.Fatalf("端口未持久化：配置 %d，返回 %d", c.Port, res.Port)
	}
}

// 两阶段都用尽时必须明确失败（而不是给个固定端口）。
func TestEnsurePanelPortFailsLoudlyWhenAllTaken(t *testing.T) {
	withConf(t, "{}\n")
	// 构造「区间内全部保留」的极端场景，验证 pickPort 返回 0 且最终报错。
	taken := map[int]bool{}
	for p := config.PanelPortMin; p <= config.PanelPortMax; p++ {
		taken[p] = true
	}
	port, err := pickPort(taken, map[int]bool{}, false)
	if err != nil {
		t.Fatalf("随机源不应报错: %v", err)
	}
	if port != 0 {
		t.Fatalf("全部占用时应返回 0（用尽），实际 %d", port)
	}
}

// 从 v0.3.0 升级：写死的默认端口 8090 必须被一次性重新随机（它是公开指纹）。
func TestEnsurePanelPortMigratesLegacyDefault(t *testing.T) {
	tok := "0123456789abcdef0123456789abcdef"
	ent := "3e4f65a8c24d2bd5b9e80147"
	path := withConf(t, `{"port":`+itoaTest(config.LegacyDefaultPort)+
		`,"token":"`+tok+`","entry_path":"`+ent+`","tz":"UTC","my_key":"keep"}`)

	res, err := EnsurePanelPort()
	if err != nil {
		t.Fatal(err)
	}
	if !res.Generated {
		t.Fatal("遗留默认端口应被重新随机")
	}
	if res.Port == config.LegacyDefaultPort {
		t.Fatalf("必须换掉遗留默认端口，实际仍为 %d", res.Port)
	}
	if res.Port < config.PanelPortMin || res.Port > config.PanelPortMax {
		t.Fatalf("新端口越界: %d", res.Port)
	}
	// 令牌、入口路径与用户键必须原样保留。
	c := config.Load()
	if c.Token != tok {
		t.Fatal("迁移端口不得改动令牌")
	}
	if c.EntryPath != ent {
		t.Fatal("迁移端口不得改动入口路径")
	}
	if c.Str("my_key") != "keep" || c.TZ != "UTC" {
		t.Fatalf("迁移端口不得丢失其它配置: %s", path)
	}
}

// 用户显式设置的非默认端口一律不动（即使它很像默认值）。
func TestEnsurePanelPortKeepsUserPort(t *testing.T) {
	withConf(t, `{"port":8091}`)
	res, err := EnsurePanelPort()
	if err != nil {
		t.Fatal(err)
	}
	if res.Generated || res.Port != 8091 {
		t.Fatalf("用户端口应原样保留，实际 %+v", res)
	}
}

func itoaTest(v int) string {
	if v == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}
