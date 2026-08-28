package nft

import (
	"strings"
	"testing"

	"github.com/k6nfmm7dbr-commits/nft-forward/internal/forward"
)

func rule(id int64, proto string, listenPort int, target string, targetPort int, enabled bool) *forward.Rule {
	return &forward.Rule{
		ID: id, Name: "r", Enabled: enabled, Protocol: proto,
		ListenAddress: "0.0.0.0", ListenPort: listenPort,
		TargetAddress: target, TargetPort: targetPort,
	}
}

func TestGenNoFlushRuleset(t *testing.T) {
	script := GenScript(&GenInput{Rules: []*forward.Rule{
		rule(1, "tcp", 20000, "1.2.3.4", 443, true),
	}})
	if strings.Contains(script, "flush ruleset") {
		t.Fatal("生成脚本绝不能包含 flush ruleset")
	}
}

func TestGenOnlyOwnedTables(t *testing.T) {
	script := GenScript(&GenInput{Rules: []*forward.Rule{
		rule(1, "tcp", 20000, "1.2.3.4", 443, true),
	}})
	// 只能 create/delete nff_* 表，不能碰 docker/filter/nat 等。
	for _, banned := range []string{"table ip filter", "table ip nat", "docker", "firewalld"} {
		if strings.Contains(script, banned) {
			t.Fatalf("脚本不应操作无关表 %q", banned)
		}
	}
	for _, owned := range []string{TableNAT4, TableFilter} {
		if !strings.Contains(script, owned) {
			t.Fatalf("脚本应包含自有表 %q", owned)
		}
	}
}

func TestGenSingleTCP(t *testing.T) {
	script := GenScript(&GenInput{Rules: []*forward.Rule{
		rule(1, "tcp", 20000, "1.2.3.4", 443, true),
	}})
	if !strings.Contains(script, "tcp dport 20000") {
		t.Fatal("缺 TCP DNAT 规则")
	}
	if !strings.Contains(script, "dnat to 1.2.3.4:443") {
		t.Fatal("缺 dnat 目标")
	}
	// ct mark 标记 + FORWARD 归属计数。
	if !strings.Contains(script, "ct mark set 1 dnat") {
		t.Fatal("应在 DNAT 时设置 ct mark")
	}
	if !strings.Contains(script, "ct mark 1 ct direction original") || !strings.Contains(script, "ct mark 1 ct direction reply") {
		t.Fatal("FORWARD 应按 ct mark 归属 + 双向计数")
	}
	if !strings.Contains(script, TableFilter+"_up_1") || !strings.Contains(script, TableFilter+"_down_1") {
		t.Fatal("缺命名 counter")
	}
	if !strings.Contains(script, "ct mark @nff_nat4_marks masquerade") {
		t.Fatal("缺基于 ct mark 的 masquerade")
	}
}

func TestGenMultiRuleSameTarget(t *testing.T) {
	// 两条规则指向同一目标，但监听端口不同 → 用不同 ct mark 区分归属。
	script := GenScript(&GenInput{Rules: []*forward.Rule{
		rule(1, "tcp", 20000, "1.2.3.4", 8844, true),
		rule(2, "tcp", 30000, "1.2.3.4", 8844, true),
	}})
	if !strings.Contains(script, "ct mark set 1 dnat") || !strings.Contains(script, "ct mark set 2 dnat") {
		t.Fatal("多规则同目标必须用不同 ct mark 区分")
	}
	if !strings.Contains(script, TableFilter+"_up_1") || !strings.Contains(script, TableFilter+"_up_2") {
		t.Fatal("两条规则应有各自 counter")
	}
}

func TestGenTCPUDP(t *testing.T) {
	script := GenScript(&GenInput{Rules: []*forward.Rule{
		rule(1, "tcp+udp", 20000, "1.2.3.4", 443, true),
	}})
	if !strings.Contains(script, "tcp dport 20000") || !strings.Contains(script, "udp dport 20000") {
		t.Fatal("tcp+udp 应同时生成两条 DNAT")
	}
}

func TestGenIPv6(t *testing.T) {
	script := GenScript(&GenInput{Rules: []*forward.Rule{
		rule(1, "tcp", 20000, "2001:db8::1", 443, true),
	}})
	if !strings.Contains(script, TableNAT6) {
		t.Fatal("IPv6 目标应生成 IPv6 NAT 表")
	}
	if !strings.Contains(script, "dnat to [2001:db8::1]:443") && !strings.Contains(script, "dnat to 2001:db8::1:443") {
		t.Logf("脚本: %s", script)
		t.Fatal("IPv6 DNAT 目标应正确")
	}
}

func TestGenDisabledExcluded(t *testing.T) {
	script := GenScript(&GenInput{Rules: []*forward.Rule{
		rule(1, "tcp", 20000, "1.2.3.4", 443, false), // 停用
	}})
	if strings.Contains(script, "dport 20000") {
		t.Fatal("停用规则不应生成转发规则")
	}
}

func TestGenQuotaBlocked(t *testing.T) {
	script := GenScript(&GenInput{
		Rules:  []*forward.Rule{rule(1, "tcp", 20000, "1.2.3.4", 443, true)},
		States: map[int64]*RuleState{1: {QuotaExceeded: true}},
	})
	if !strings.Contains(script, "ct mark 1 drop") {
		t.Fatal("配额达限应生成 drop 规则")
	}
	// 达限时不应再生成该规则的计数/allow。
	if strings.Contains(script, TableFilter+"_up_1") {
		t.Fatal("达限规则不应再生成计数规则")
	}
}

func TestGenIPAllowSet(t *testing.T) {
	script := GenScript(&GenInput{
		Rules: []*forward.Rule{rule(1, "tcp", 20000, "1.2.3.4", 443, true)},
		States: map[int64]*RuleState{1: {
			IPLimitEnabled: true,
			AllowV4:        []string{"1.1.1.1", "2.2.2.2"},
			AllowV6:        []string{"2001:db8::9"},
		}},
	})
	if !strings.Contains(script, TableFilter+"_allow_1_v4") || !strings.Contains(script, TableFilter+"_allow_1_v6") {
		t.Fatal("应生成 v4/v6 allow set")
	}
	if !strings.Contains(script, "1.1.1.1") || !strings.Contains(script, "2.2.2.2") || !strings.Contains(script, "2001:db8::9") {
		t.Fatal("allow set 应包含授予的 IP")
	}
	if !strings.Contains(script, "ct state established") {
		t.Fatal("IP 限制应只 drop 已建立连接（放行 SYN，候选可见）")
	}
}
