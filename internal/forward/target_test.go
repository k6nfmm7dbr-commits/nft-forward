package forward

import "testing"

// TestValidateIPv4Target IPv4 字面量目标必须被接受并归一化。
func TestValidateIPv4Target(t *testing.T) {
	for _, in := range []string{"38.54.32.199", "1.1.1.1", " 8.8.4.4 "} {
		got, kind, err := NormalizeTarget(in)
		if err != nil {
			t.Fatalf("NormalizeTarget(%q) 意外失败: %v", in, err)
		}
		if kind != TargetIPv4 {
			t.Fatalf("NormalizeTarget(%q) kind=%v，期望 ipv4", in, kind)
		}
		if got == "" {
			t.Fatalf("NormalizeTarget(%q) 返回空", in)
		}
	}
	// ::ffff: 前缀的 IPv4-mapped 必须归一到 IPv4（数据面只有 v4/v6 两条路径）。
	got, kind, err := NormalizeTarget("::ffff:1.2.3.4")
	if err != nil || kind != TargetIPv4 || got != "1.2.3.4" {
		t.Fatalf("IPv4-mapped 未归一: got=%q kind=%v err=%v", got, kind, err)
	}
}

// TestValidateIPv6Target IPv6 字面量目标必须被接受（裸写，不带方括号）。
func TestValidateIPv6Target(t *testing.T) {
	for _, in := range []string{"2001:db8::1", "2606:4700:4700::1111", "fd00::5"} {
		got, kind, err := NormalizeTarget(in)
		if err != nil {
			t.Fatalf("NormalizeTarget(%q) 意外失败: %v", in, err)
		}
		if kind != TargetIPv6 {
			t.Fatalf("NormalizeTarget(%q) kind=%v，期望 ipv6", in, kind)
		}
		if got == "" {
			t.Fatalf("NormalizeTarget(%q) 返回空", in)
		}
	}
}

// TestValidateDomainTarget 合法域名必须被接受并小写化。
func TestValidateDomainTarget(t *testing.T) {
	cases := map[string]string{
		"example.com":        "example.com",
		"hk.example.com":     "hk.example.com",
		"a-b.example.com":    "a-b.example.com",
		"hk01.example.co.uk": "hk01.example.co.uk",
		"tx1.shhsh.cc":       "tx1.shhsh.cc",
		"EXAMPLE.COM":        "example.com",
		"example.com.":       "example.com", // 末尾根点被去掉
	}
	for in, want := range cases {
		got, kind, err := NormalizeTarget(in)
		if err != nil {
			t.Fatalf("NormalizeTarget(%q) 意外失败: %v", in, err)
		}
		if kind != TargetDomain {
			t.Fatalf("NormalizeTarget(%q) kind=%v，期望 domain", in, kind)
		}
		if got != want {
			t.Fatalf("NormalizeTarget(%q)=%q，期望 %q", in, got, want)
		}
	}
}

// TestRejectURLAsTarget URL 形态必须被拒绝，且提示要明确指出不要带 scheme/端口/路径。
func TestRejectURLAsTarget(t *testing.T) {
	for _, in := range []string{
		"http://example.com",
		"https://example.com",
		"example.com/path",
		"HTTPS://EXAMPLE.COM",
	} {
		_, _, err := NormalizeTarget(in)
		if err == nil {
			t.Fatalf("NormalizeTarget(%q) 应当失败", in)
		}
		if err.Error() != msgTargetSchema {
			t.Fatalf("NormalizeTarget(%q) 错误文案=%q，期望 %q", in, err.Error(), msgTargetSchema)
		}
	}
}

// TestRejectDomainWithPort 目标地址不允许内嵌端口（端口是独立字段）。
func TestRejectDomainWithPort(t *testing.T) {
	for _, in := range []string{
		"example.com:443",
		"38.54.32.199:443",
		"[2001:db8::1]:443",
	} {
		_, _, err := NormalizeTarget(in)
		if err == nil {
			t.Fatalf("NormalizeTarget(%q) 应当失败", in)
		}
		if err.Error() != msgTargetSchema {
			t.Fatalf("NormalizeTarget(%q) 错误文案=%q，期望 %q", in, err.Error(), msgTargetSchema)
		}
	}
}

// TestRejectInvalidTarget 其它非法输入必须被拒绝。
func TestRejectInvalidTarget(t *testing.T) {
	bad := []string{
		"",                 // 空
		"   ",              // 全空白
		"not an ip",        // 含空格
		"example",          // 单 label
		"exa mple.com",     // 含空格
		"-bad.example.com", // label 以 - 开头
		"bad-.example.com", // label 以 - 结尾
		"example.c",        // TLD 过短
		"example.123",      // TLD 非字母
		"0.0.0.0",          // 通配地址
		"::",               // 通配地址
		"224.0.0.1",        // 组播
		"ff02::1",          // 组播
		"fe80::1%eth0",     // 带 zone
		"under_score.com",  // 非法字符
		"a..b.com",         // 空 label
	}
	for _, in := range bad {
		if _, _, err := NormalizeTarget(in); err == nil {
			t.Fatalf("NormalizeTarget(%q) 应当失败但通过了", in)
		}
	}
}

// TestNormalizeTargetLongName 超长域名与超长 label 必须被拒绝。
func TestNormalizeTargetLongName(t *testing.T) {
	long := ""
	for i := 0; i < 64; i++ {
		long += "a"
	}
	if _, _, err := NormalizeTarget(long + ".com"); err == nil {
		t.Fatal("64 字符 label 应当被拒绝")
	}
	total := ""
	for i := 0; i < 30; i++ {
		total += "abcdefgh."
	}
	if _, _, err := NormalizeTarget(total + "com"); err == nil {
		t.Fatal("超过 253 字符的域名应当被拒绝")
	}
}

// TestFormatHostPort IPv6 显示必须加方括号，其它形态直接拼接。
func TestFormatHostPort(t *testing.T) {
	cases := []struct{ addr, want string }{
		{"38.54.32.199", "38.54.32.199:443"},
		{"2001:db8::1", "[2001:db8::1]:443"},
		{"example.com", "example.com:443"},
	}
	for _, c := range cases {
		if got := FormatHostPort(c.addr, 443); got != c.want {
			t.Fatalf("FormatHostPort(%q)=%q，期望 %q", c.addr, got, c.want)
		}
	}
}

// TestKindOf 形态判定。
func TestKindOf(t *testing.T) {
	if KindOf("1.2.3.4") != TargetIPv4 {
		t.Fatal("IPv4 判定错误")
	}
	if KindOf("2001:db8::1") != TargetIPv6 {
		t.Fatal("IPv6 判定错误")
	}
	if KindOf("example.com") != TargetDomain {
		t.Fatal("域名判定错误")
	}
	if !IsDomain("hk.example.com") {
		t.Fatal("IsDomain 判定错误")
	}
}

// TestNormalizeName 名称必须去首尾空格、拒绝空串与超长。
func TestNormalizeName(t *testing.T) {
	got, err := NormalizeName("  香港CN2  ")
	if err != nil || got != "香港CN2" {
		t.Fatalf("NormalizeName 去空格失败: got=%q err=%v", got, err)
	}
	if _, err := NormalizeName("   "); err == nil {
		t.Fatal("空名称应当被拒绝")
	}
	long := ""
	for i := 0; i < 65; i++ {
		long += "字"
	}
	if _, err := NormalizeName(long); err == nil {
		t.Fatal("超长名称应当被拒绝")
	}
	if _, err := NormalizeName("a\nb"); err == nil {
		t.Fatal("含换行的名称应当被拒绝")
	}
}
