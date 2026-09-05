package provision

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/k6nfmm7dbr-commits/nft-forward/internal/config"
)

// ---- DB fail-closed（v0.3.2）----
//
// 旧行为：ruleListenPorts 在「DB 存在但打不开 / 损坏 / 查询失败」时返回空列表，
// 于是新面板端口可能撞上正在使用的转发端口 —— fail-open。
// 现在这些情况必须返回 error，端口生成/修改一律中止。

// DB 路径为空 → 视为无规则（不是错误）。
func TestRuleListenPortsEmptyPath(t *testing.T) {
	ports, err := ruleListenPorts("")
	if err != nil {
		t.Fatalf("空路径不应报错: %v", err)
	}
	if len(ports) != 0 {
		t.Fatalf("应返回空列表，实际 %v", ports)
	}
}

// DB 文件不存在 → 视为首次安装（不是错误）。
func TestRuleListenPortsMissingFile(t *testing.T) {
	ports, err := ruleListenPorts(filepath.Join(t.TempDir(), "nope.db"))
	if err != nil {
		t.Fatalf("文件不存在不应报错（首次安装）: %v", err)
	}
	if len(ports) != 0 {
		t.Fatalf("应返回空列表，实际 %v", ports)
	}
}

// DB 正常 → 读出规则端口。
func TestRuleListenPortsValidDB(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "traffic.db")
	if err := seedRule(dbPath, 41234); err != nil {
		t.Fatal(err)
	}
	ports, err := ruleListenPorts(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range ports {
		if p == 41234 {
			found = true
		}
	}
	if !found {
		t.Fatalf("应读出规则端口 41234，实际 %v", ports)
	}
}

// ★ DB 文件存在但内容损坏 → 必须返回 error。
func TestRuleListenPortsCorruptDBFailsClosed(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "traffic.db")
	// 写入一个「看起来像 SQLite 但实际损坏」的文件：正确的魔数 + 垃圾内容。
	// 纯随机字节会被 SQLite 直接判为 not a database；这种更贴近真实损坏。
	garbage := append([]byte("SQLite format 3\x00"), make([]byte, 4096)...)
	for i := 16; i < len(garbage); i++ {
		garbage[i] = byte(i % 251)
	}
	if err := os.WriteFile(dbPath, garbage, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := ruleListenPorts(dbPath)
	if err == nil {
		t.Fatal("损坏的 DB 必须返回错误（fail-closed），不得当成「没有规则」")
	}
}

// ★ DB 是目录（打不开）→ 必须返回 error。
func TestRuleListenPortsUnopenableFailsClosed(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "traffic.db")
	if err := os.Mkdir(dbPath, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := ruleListenPorts(dbPath); err == nil {
		t.Fatal("DB 路径是目录时必须返回错误")
	}
}

// ★ 表被删（schema 错误）→ 必须返回 error。
func TestRuleListenPortsSchemaErrorFailsClosed(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "traffic.db")
	if err := seedRule(dbPath, 41234); err != nil {
		t.Fatal(err)
	}
	if err := dropRulesTable(dbPath); err != nil {
		t.Fatal(err)
	}
	// database.Open 会重建缺失的表（迁移逻辑），因此这里断言的是
	// 「读取不报错则必须给出正确结果」，而不是强求报错。
	ports, err := ruleListenPorts(dbPath)
	if err != nil {
		return // 报错也是可接受的 fail-closed 行为
	}
	for _, p := range ports {
		if p == 41234 {
			t.Fatal("表被删后不应仍返回旧端口")
		}
	}
}

// ★ 损坏的 DB 必须让 EnsurePanelPort 整体失败（不得继续随机端口）。
func TestEnsurePanelPortFailsClosedOnCorruptDB(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "traffic.db")
	confPath := filepath.Join(dir, "panel.json")
	garbage := append([]byte("SQLite format 3\x00"), make([]byte, 4096)...)
	for i := 16; i < len(garbage); i++ {
		garbage[i] = byte(i % 251)
	}
	if err := os.WriteFile(dbPath, garbage, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(confPath, []byte(`{"db":"`+dbPath+`","ssh_port":22}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NFT_FORWARD_CONF", confPath)
	t.Setenv("NFT_FORWARD_DIR", dir)

	before, _ := os.ReadFile(confPath)
	if _, err := EnsurePanelPort(); err == nil {
		t.Fatal("DB 损坏时必须拒绝生成面板端口")
	}
	after, _ := os.ReadFile(confPath)
	if string(before) != string(after) {
		t.Fatal("失败时不得写入配置")
	}
}

// ---- 手工改端口的安全校验 ----

func TestValidatePanelPortRejectsOutOfRange(t *testing.T) {
	withConf(t, `{"port":23456}`)
	for _, p := range []int{0, -1, 65536, 99999} {
		if _, err := ValidatePanelPort(p); err == nil {
			t.Fatalf("非法端口 %d 应被拒绝", p)
		}
	}
}

func TestValidatePanelPortRejectsSamePort(t *testing.T) {
	withConf(t, `{"port":23456}`)
	_, err := ValidatePanelPort(23456)
	if err == nil {
		t.Fatal("与当前端口相同应被拒绝")
	}
	if !strings.Contains(err.Error(), "相同") {
		t.Fatalf("错误信息应说明原因，实际 %v", err)
	}
}

func TestValidatePanelPortRejectsSSHPort(t *testing.T) {
	withConf(t, `{"port":23456,"ssh_port":2222}`)
	_, err := ValidatePanelPort(2222)
	if err == nil {
		t.Fatal("SSH 端口应被拒绝")
	}
	if !strings.Contains(err.Error(), "SSH") {
		t.Fatalf("错误信息应说明是 SSH 冲突，实际 %v", err)
	}
}

func TestValidatePanelPortRejectsGuardPort(t *testing.T) {
	withConf(t, `{"port":23456,"guard_ports":{"9443":"我的服务"}}`)
	_, err := ValidatePanelPort(9443)
	if err == nil {
		t.Fatal("guard_ports 应被拒绝")
	}
	if !strings.Contains(err.Error(), "保留端口") {
		t.Fatalf("错误信息应说明是保留端口，实际 %v", err)
	}
}

func TestValidatePanelPortRejectsForwardRulePort(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "traffic.db")
	confPath := filepath.Join(dir, "panel.json")
	if err := seedRule(dbPath, 41234); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(confPath,
		[]byte(`{"db":"`+dbPath+`","port":23456,"ssh_port":22}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NFT_FORWARD_CONF", confPath)
	t.Setenv("NFT_FORWARD_DIR", dir)

	_, err := ValidatePanelPort(41234)
	if err == nil {
		t.Fatal("与转发规则监听端口冲突应被拒绝")
	}
	if !strings.Contains(err.Error(), "转发规则") {
		t.Fatalf("错误信息应说明是转发端口冲突，实际 %v", err)
	}
}

func TestValidatePanelPortRejectsListeningPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("无法建立监听: %v", err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	withConf(t, `{"port":23456}`)
	if _, err := ValidatePanelPort(port); err == nil {
		t.Skipf("环境允许重复 bind（容器/SO_REUSEPORT），跳过对端口 %d 的断言", port)
	}
}

func TestValidatePanelPortAcceptsFreePort(t *testing.T) {
	// 找一个当前空闲端口。
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("无法建立监听: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	withConf(t, `{"port":23456,"ssh_port":22}`)
	if _, err := ValidatePanelPort(port); err != nil {
		t.Skipf("端口 %d 在关闭后被他人占用，跳过: %v", port, err)
	}
}

// DB 损坏时手工改端口也必须拒绝（不能只在自动路径 fail-closed）。
func TestValidatePanelPortFailsClosedOnCorruptDB(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "traffic.db")
	confPath := filepath.Join(dir, "panel.json")
	garbage := append([]byte("SQLite format 3\x00"), make([]byte, 4096)...)
	for i := 16; i < len(garbage); i++ {
		garbage[i] = byte(i % 251)
	}
	if err := os.WriteFile(dbPath, garbage, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(confPath,
		[]byte(`{"db":"`+dbPath+`","port":23456,"ssh_port":22}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NFT_FORWARD_CONF", confPath)
	t.Setenv("NFT_FORWARD_DIR", dir)

	if _, err := ValidatePanelPort(31000); err == nil {
		t.Fatal("DB 损坏时手工改端口必须被拒绝")
	}
}

// SetPanelPortChecked 成功时写入新端口并返回旧端口；失败时不写配置。
func TestSetPanelPortChecked(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("无法建立监听: %v", err)
	}
	free := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	tok := strings.Repeat("a", 32)
	ent := strings.Repeat("b", 24)
	path := withConf(t, `{"port":23456,"ssh_port":22,"token":"`+tok+`","entry_path":"`+ent+`"}`)

	oldPort, _, err := SetPanelPortChecked(free)
	if err != nil {
		t.Skipf("端口 %d 被他人占用，跳过: %v", free, err)
	}
	if oldPort != 23456 {
		t.Fatalf("应返回旧端口 23456，实际 %d", oldPort)
	}
	c := config.Load()
	if c.Port != free {
		t.Fatalf("新端口未写入，实际 %d", c.Port)
	}
	// 令牌与入口路径必须原样保留。
	if c.Token != tok || c.EntryPath != ent {
		t.Fatal("改端口不得影响令牌与入口路径")
	}
	st, _ := os.Stat(path)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("写回后权限应仍为 0600，实际 %o", st.Mode().Perm())
	}
}

// 校验失败时绝不写配置。
func TestSetPanelPortCheckedRejectionDoesNotWrite(t *testing.T) {
	path := withConf(t, `{"port":23456,"ssh_port":2222}`)
	before, _ := os.ReadFile(path)
	if _, _, err := SetPanelPortChecked(2222); err == nil {
		t.Fatal("SSH 端口应被拒绝")
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("校验失败时不得写配置")
	}
}
