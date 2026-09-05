package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withConf 把配置路径指向临时文件。
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

func readRaw(t *testing.T, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("配置不是合法 JSON: %v\n%s", err, data)
	}
	return m
}

// ---- 默认值：绝不含固定端口 / 固定令牌 / 固定入口 ----

func TestNoDefaultPortTokenEntry(t *testing.T) {
	withConf(t, "")
	c := Load()
	if c.Port != 0 {
		t.Fatalf("不得有默认面板端口（历史 8090 已删除），实际 %d", c.Port)
	}
	if c.Token != "" {
		t.Fatal("不得有默认令牌")
	}
	if c.EntryPath != "" {
		t.Fatal("不得有默认入口路径")
	}
	// defaultConf 里也不能出现这些键。
	for _, k := range []string{"port", "token", "entry_path"} {
		if _, ok := defaultConf()[k]; ok {
			t.Fatalf("defaultConf 不应包含 %q", k)
		}
	}
}

// serve 前的强校验：三项缺一不可。
func TestValidateServeRequiresAllThree(t *testing.T) {
	withConf(t, "")
	c := Load()
	if err := c.ValidateServe(); err == nil {
		t.Fatal("全新配置应拒绝启动")
	}
	c.Port = 12345
	if err := c.ValidateServe(); err == nil || !strings.Contains(err.Error(), "令牌") {
		t.Fatalf("缺令牌应报错，实际 %v", err)
	}
	c.Token = strings.Repeat("a", 32)
	if err := c.ValidateServe(); err == nil || !strings.Contains(err.Error(), "入口") {
		t.Fatalf("缺入口路径应报错，实际 %v", err)
	}
	c.EntryPath = strings.Repeat("b", 24)
	if err := c.ValidateServe(); err != nil {
		t.Fatalf("三项齐备应通过，实际 %v", err)
	}
}

// ---- EnsureToken ----

func TestEnsureTokenGenerates32HexAndPersists(t *testing.T) {
	path := withConf(t, "{}\n")
	tok, err := EnsureToken()
	if err != nil {
		t.Fatal(err)
	}
	if len(tok) != 32 {
		t.Fatalf("令牌应为 32 位十六进制，实际 %q（%d 位）", tok, len(tok))
	}
	for _, ch := range tok {
		if !strings.ContainsRune("0123456789abcdef", ch) {
			t.Fatalf("令牌含非十六进制字符: %q", tok)
		}
	}
	raw := readRaw(t, path)
	if raw["token"] != tok {
		t.Fatalf("令牌未持久化: %v", raw["token"])
	}
	// 幂等：再次调用返回同一个值，不重新生成。
	tok2, err := EnsureToken()
	if err != nil {
		t.Fatal(err)
	}
	if tok2 != tok {
		t.Fatal("EnsureToken 必须幂等（升级不得重置令牌）")
	}
}

func TestEnsureTokenFilePermissions(t *testing.T) {
	path := withConf(t, "{}\n")
	if _, err := EnsureToken(); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := st.Mode().Perm(); perm != 0o600 {
		t.Fatalf("panel.json 权限必须是 0600，实际 %o", perm)
	}
}

// 已有配置不得被破坏（升级安全补齐）。
func TestEnsureTokenKeepsOtherKeys(t *testing.T) {
	path := withConf(t, `{"port":45678,"tz":"UTC","my_custom":"keep","interval":5}`)
	if _, err := EnsureToken(); err != nil {
		t.Fatal(err)
	}
	raw := readRaw(t, path)
	if raw["my_custom"] != "keep" {
		t.Fatal("用户自定义键被丢弃")
	}
	if fmtNum(raw["port"]) != "45678" {
		t.Fatalf("端口被改动: %v", raw["port"])
	}
	if raw["tz"] != "UTC" {
		t.Fatal("tz 被改动")
	}
}

// 配置损坏时必须 fail-closed：报错、不写回、不覆盖原文件。
func TestEnsureTokenRejectsCorruptConfig(t *testing.T) {
	path := withConf(t, `{"port": 45678, broken`)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := EnsureToken(); err == nil {
		t.Fatal("配置损坏时必须拒绝生成令牌")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("损坏的配置绝不能被覆盖")
	}
}

// 尾部多余 JSON 同样算损坏。
func TestLoadStrictRejectsTrailingGarbage(t *testing.T) {
	withConf(t, `{"port":45678}{"extra":1}`)
	if _, err := LoadStrict(); err == nil {
		t.Fatal("尾部多余数据应视为损坏")
	}
}

// ---- EnsureEntryPath ----

func TestEnsureEntryPathGeneratesIndependentRandom(t *testing.T) {
	path := withConf(t, "{}\n")
	tok, err := EnsureToken()
	if err != nil {
		t.Fatal(err)
	}
	p, err := EnsureEntryPath()
	if err != nil {
		t.Fatal(err)
	}
	if len(p) != 24 {
		t.Fatalf("入口路径应为 24 位十六进制（96 bit），实际 %q（%d 位）", p, len(p))
	}
	if !ValidEntryPath(p) {
		t.Fatalf("生成的入口路径不合法: %q", p)
	}
	if p == tok || strings.Contains(tok, p) || strings.Contains(p, tok) {
		t.Fatal("入口路径必须与令牌完全独立，不能互相推导")
	}
	raw := readRaw(t, path)
	if raw["entry_path"] != p {
		t.Fatal("入口路径未持久化")
	}
	// 幂等
	p2, err := EnsureEntryPath()
	if err != nil {
		t.Fatal(err)
	}
	if p2 != p {
		t.Fatal("EnsureEntryPath 必须幂等（升级不得更换入口）")
	}
}

func TestEnsureEntryPathRejectsCorruptConfig(t *testing.T) {
	withConf(t, `{oops`)
	if _, err := EnsureEntryPath(); err == nil {
		t.Fatal("配置损坏时必须拒绝生成入口路径")
	}
}

// 两次独立生成必须不同（真随机，不是常量）。
func TestRandomValuesDifferAcrossInstalls(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 5; i++ {
		withConf(t, "{}\n")
		tok, err := EnsureToken()
		if err != nil {
			t.Fatal(err)
		}
		p, err := EnsureEntryPath()
		if err != nil {
			t.Fatal(err)
		}
		if seen[tok] || seen[p] {
			t.Fatal("随机值出现重复，疑似非随机源")
		}
		seen[tok] = true
		seen[p] = true
	}
}

// entry_path 允许用户写成 "/abc/"，读取时归一化。
func TestEntryPathNormalized(t *testing.T) {
	withConf(t, `{"entry_path":"/`+strings.Repeat("c", 24)+`/","port":45678,"token":"`+strings.Repeat("a", 32)+`"}`)
	c := Load()
	if c.EntryPath != strings.Repeat("c", 24) {
		t.Fatalf("入口路径未归一化: %q", c.EntryPath)
	}
	if c.EntryRoute() != "/"+strings.Repeat("c", 24) {
		t.Fatalf("EntryRoute 应带单个前导斜杠: %q", c.EntryRoute())
	}
}

// ---- Migrate ----

// token 绝不能被当成废弃键删除（v0.3 曾误删，v0.3.1 恢复认证后必须保留）。
func TestMigrateKeepsToken(t *testing.T) {
	path := withConf(t, `{"token":"`+strings.Repeat("a", 32)+`","port":45678,"rule_listen_address":"0.0.0.0"}`)
	dropped, err := Migrate()
	if err != nil {
		t.Fatal(err)
	}
	if len(dropped) != 1 || dropped[0] != "rule_listen_address" {
		t.Fatalf("应只删除废弃键，实际 %v", dropped)
	}
	raw := readRaw(t, path)
	if raw["token"] != strings.Repeat("a", 32) {
		t.Fatal("迁移不得删除 token")
	}
	if fmtNum(raw["port"]) != "45678" {
		t.Fatal("迁移不得改动端口")
	}
	for _, k := range legacyKeys {
		if k == "token" {
			t.Fatal("token 不应在 legacyKeys 中")
		}
	}
}

func TestMigrateRejectsCorruptConfig(t *testing.T) {
	withConf(t, `{bad`)
	if _, err := Migrate(); err == nil {
		t.Fatal("配置损坏时迁移必须失败")
	}
}

func TestMigrateNoFileIsNoop(t *testing.T) {
	withConf(t, "")
	dropped, err := Migrate()
	if err != nil {
		t.Fatalf("配置不存在时迁移应无操作，实际 %v", err)
	}
	if len(dropped) != 0 {
		t.Fatalf("不应删除任何键，实际 %v", dropped)
	}
}

// ---- Set / SetPort ----

func TestSetPortPersistsAndKeepsSecrets(t *testing.T) {
	tok := strings.Repeat("a", 32)
	ent := strings.Repeat("b", 24)
	path := withConf(t, `{"token":"`+tok+`","entry_path":"`+ent+`","port":45678}`)
	if err := SetPort(23456); err != nil {
		t.Fatal(err)
	}
	raw := readRaw(t, path)
	if fmtNum(raw["port"]) != "23456" {
		t.Fatalf("端口未写入: %v", raw["port"])
	}
	if raw["token"] != tok || raw["entry_path"] != ent {
		t.Fatal("改端口不得影响令牌与入口路径")
	}
	st, _ := os.Stat(path)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("写回后权限应仍为 0600，实际 %o", st.Mode().Perm())
	}
}

func TestSetPortRejectsInvalid(t *testing.T) {
	withConf(t, "{}\n")
	for _, p := range []int{0, -1, 65536, 99999} {
		if err := SetPort(p); err == nil {
			t.Fatalf("非法端口 %d 应被拒绝", p)
		}
	}
}

// GuardPorts 必须含面板端口与 SSH 端口。
func TestGuardPortsIncludesPanelAndSSH(t *testing.T) {
	withConf(t, `{"port":23456,"ssh_port":2222,"guard_ports":{"9000":"自定义"}}`)
	c := Load()
	g := c.GuardPorts()
	if _, ok := g[23456]; !ok {
		t.Fatal("面板端口应在保留表中")
	}
	if _, ok := g[2222]; !ok {
		t.Fatal("SSH 端口应在保留表中")
	}
	if g[9000] != "自定义" {
		t.Fatalf("guard_ports 未生效: %v", g)
	}
}

// 非法 token / entry_path 应在校验阶段被拒绝。
func TestValidateRejectsMalformedSecrets(t *testing.T) {
	withConf(t, `{"token":"not-hex","port":23456}`)
	if _, err := LoadStrict(); err == nil {
		t.Fatal("非法 token 应校验失败")
	}
	withConf(t, `{"entry_path":"short","port":23456}`)
	if _, err := LoadStrict(); err == nil {
		t.Fatal("非法 entry_path 应校验失败")
	}
}

func fmtNum(v any) string {
	switch t := v.(type) {
	case float64:
		return strings.TrimSuffix(strings.TrimRight(json.Number(numToStr(t)).String(), "0"), ".")
	case json.Number:
		return t.String()
	case string:
		return t
	}
	return ""
}

func numToStr(f float64) string {
	b, _ := json.Marshal(f)
	return string(b)
}
