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

func structScript(rules []*forward.Rule, states map[int64]*RuleState) string {
	return GenStructScript(&GenInput{Rules: rules, States: states}, nil)
}

// ★ 最重要的一条：结构脚本绝不能 delete table。
// counter 是表级对象，delete table 会连同累计字节一起销毁 —— 那会让周期性
// reconcile 反复清零流量统计（本项目曾因此几乎丢掉全部流量）。
func TestStructScriptNeverDeletesTable(t *testing.T) {
	script := structScript([]*forward.Rule{
		rule(1, "tcp", 20000, "1.2.3.4", 443, true),
	}, nil)
	if strings.Contains(script, "delete table") {
		t.Fatalf("结构脚本绝不能 delete table（会清零 counter）:\n%s", script)
	}
	if strings.Contains(script, "flush ruleset") {
		t.Fatal("生成脚本绝不能包含 flush ruleset")
	}
	// 必须用 flush chain 而不是重建表。
	if !strings.Contains(script, "flush chain inet "+TableFilter) {
		t.Fatal("应用 flush chain 清空链内规则")
	}
	// counter 必须是幂等声明（表已存在时保留原值）。
	if !strings.Contains(script, "counter "+CounterUp(1)) {
		t.Fatal("应幂等声明 counter")
	}
}

func TestStructScriptOnlyOwnedTables(t *testing.T) {
	script := structScript([]*forward.Rule{
		rule(1, "tcp", 20000, "1.2.3.4", 443, true),
	}, nil)
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

func TestStructScriptSingleTCP(t *testing.T) {
	script := structScript([]*forward.Rule{
		rule(1, "tcp", 20000, "1.2.3.4", 443, true),
	}, nil)
	if !strings.Contains(script, "tcp dport 20000") {
		t.Fatal("缺 TCP DNAT 规则")
	}
	if !strings.Contains(script, "dnat to 1.2.3.4:443") {
		t.Fatal("缺 dnat 目标")
	}
	if !strings.Contains(script, "ct mark set 1 dnat") {
		t.Fatal("应在 DNAT 时设置 ct mark")
	}
	if !strings.Contains(script, "ct mark 1 ct direction original") ||
		!strings.Contains(script, "ct mark 1 ct direction reply") {
		t.Fatal("FORWARD 应按 ct mark 归属 + 双向计数")
	}
	if !strings.Contains(script, "ct mark @"+MarksSet(TableNAT4)+" masquerade") {
		t.Fatal("缺基于 ct mark 的 masquerade")
	}
}

func TestStructScriptMultiRuleSameTarget(t *testing.T) {
	script := structScript([]*forward.Rule{
		rule(1, "tcp", 20000, "1.2.3.4", 8844, true),
		rule(2, "tcp", 30000, "1.2.3.4", 8844, true),
	}, nil)
	if !strings.Contains(script, "ct mark set 1 dnat") || !strings.Contains(script, "ct mark set 2 dnat") {
		t.Fatal("多规则同目标必须用不同 ct mark 区分")
	}
	if !strings.Contains(script, CounterUp(1)) || !strings.Contains(script, CounterUp(2)) {
		t.Fatal("两条规则应有各自 counter")
	}
}

func TestStructScriptTCPUDP(t *testing.T) {
	script := structScript([]*forward.Rule{
		rule(1, "tcp+udp", 20000, "1.2.3.4", 443, true),
	}, nil)
	if !strings.Contains(script, "tcp dport 20000") || !strings.Contains(script, "udp dport 20000") {
		t.Fatal("tcp+udp 应同时生成两条 DNAT")
	}
}

func TestStructScriptIPv6(t *testing.T) {
	script := structScript([]*forward.Rule{
		rule(1, "tcp", 20000, "2001:db8::1", 443, true),
	}, nil)
	if !strings.Contains(script, TableNAT6) {
		t.Fatal("IPv6 目标应生成 IPv6 NAT 表")
	}
	if !strings.Contains(script, "dnat to [2001:db8::1]:443") {
		t.Fatalf("IPv6 DNAT 目标应加方括号:\n%s", script)
	}
}

func TestStructScriptDisabledExcluded(t *testing.T) {
	script := structScript([]*forward.Rule{
		rule(1, "tcp", 20000, "1.2.3.4", 443, false),
	}, nil)
	if strings.Contains(script, "dport 20000") {
		t.Fatal("停用规则不应生成转发规则")
	}
}

// 配额阻断现在走 qblock set 元素，不再写死在链规则里 ——
// 这样配额状态翻转不必重建链（因此不清零 counter）。
func TestQuotaBlockUsesSetNotChainRebuild(t *testing.T) {
	rules := []*forward.Rule{rule(1, "tcp", 20000, "1.2.3.4", 443, true)}
	normal := structScript(rules, map[int64]*RuleState{1: {}})
	exceeded := structScript(rules, map[int64]*RuleState{1: {QuotaExceeded: true}})
	if normal != exceeded {
		t.Fatal("配额状态变化不应改变结构脚本（应只改 qblock set 元素）")
	}
	if !strings.Contains(normal, "ct mark @"+SetQuotaBlock+" drop") {
		t.Fatal("链里应有基于 qblock set 的 drop 规则")
	}
	// 结构签名也必须相同，否则会触发不必要的链重建。
	sigA := StructSig(&GenInput{Rules: rules, States: map[int64]*RuleState{1: {}}})
	sigB := StructSig(&GenInput{Rules: rules, States: map[int64]*RuleState{1: {QuotaExceeded: true}}})
	if sigA != sigB {
		t.Fatal("配额状态不应影响结构签名")
	}
}

func TestStructScriptIPLimitRules(t *testing.T) {
	script := structScript([]*forward.Rule{rule(1, "tcp", 20000, "1.2.3.4", 443, true)},
		map[int64]*RuleState{1: {IPLimitEnabled: true}})
	if !strings.Contains(script, AllowSetV4(1)) || !strings.Contains(script, AllowSetV6(1)) {
		t.Fatal("应声明 v4/v6 allow set")
	}
	if !strings.Contains(script, "ct state established") {
		t.Fatal("IP 限制应只 drop 已建立连接（放行 SYN，候选可见）")
	}
	// ★ 关键：必须限定 original 方向。reply 方向的 saddr 是后端地址，
	// 不限定方向会把返回包全部 drop，导致启用 IP 限制后转发彻底不通。
	for _, want := range []string{
		"ct direction original ct state established ip saddr != @" + AllowSetV4(1) + " drop",
		"ct direction original ct state established ip6 saddr != @" + AllowSetV6(1) + " drop",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("IP 限制 drop 规则必须限定 original 方向，缺少:\n%s\n实际脚本:\n%s", want, script)
		}
	}
	// 反向断言：不得存在不限定方向的 drop 规则。
	if strings.Contains(script, "ct mark 1 ct state established ip saddr") {
		t.Fatal("不得生成未限定方向的 drop 规则（会 drop 掉后端返回包）")
	}
}

// allow set 元素变化不得改变结构脚本 —— 否则每次 IP 上下线都重建链。
func TestAllowElementsDoNotAffectStruct(t *testing.T) {
	rules := []*forward.Rule{rule(1, "tcp", 20000, "1.2.3.4", 443, true)}
	a := structScript(rules, map[int64]*RuleState{1: {IPLimitEnabled: true, AllowV4: []string{"1.1.1.1"}}})
	b := structScript(rules, map[int64]*RuleState{1: {IPLimitEnabled: true, AllowV4: []string{"1.1.1.1", "2.2.2.2"}}})
	if a != b {
		t.Fatal("allow set 元素变化不应改变结构脚本")
	}
	sigA := StructSig(&GenInput{Rules: rules, States: map[int64]*RuleState{1: {IPLimitEnabled: true, AllowV4: []string{"1.1.1.1"}}}})
	sigB := StructSig(&GenInput{Rules: rules, States: map[int64]*RuleState{1: {IPLimitEnabled: true, AllowV4: []string{"9.9.9.9"}}}})
	if sigA != sigB {
		t.Fatal("allow set 元素不应影响结构签名")
	}
}

func TestStructSigChangesOnRealStructChange(t *testing.T) {
	base := &GenInput{Rules: []*forward.Rule{rule(1, "tcp", 20000, "1.2.3.4", 443, true)}}
	cases := map[string]*GenInput{
		"改端口":    {Rules: []*forward.Rule{rule(1, "tcp", 20001, "1.2.3.4", 443, true)}},
		"改目标":    {Rules: []*forward.Rule{rule(1, "tcp", 20000, "5.6.7.8", 443, true)}},
		"改协议":    {Rules: []*forward.Rule{rule(1, "tcp+udp", 20000, "1.2.3.4", 443, true)}},
		"停用":     {Rules: []*forward.Rule{rule(1, "tcp", 20000, "1.2.3.4", 443, false)}},
		"新增规则":   {Rules: []*forward.Rule{rule(1, "tcp", 20000, "1.2.3.4", 443, true), rule(2, "tcp", 20002, "1.2.3.4", 443, true)}},
		"开启IP限制": {Rules: base.Rules, States: map[int64]*RuleState{1: {IPLimitEnabled: true}}},
	}
	baseSig := StructSig(base)
	for name, gi := range cases {
		if StructSig(gi) == baseSig {
			t.Fatalf("%s 应改变结构签名", name)
		}
	}
}

func TestStaleObjectCleanup(t *testing.T) {
	// 规则 2 已删除，但 nft 里仍有它的 counter → 结构脚本应删除遗留对象。
	script := GenStructScript(
		&GenInput{Rules: []*forward.Rule{rule(1, "tcp", 20000, "1.2.3.4", 443, true)}},
		&Existing{
			FilterTableExists: true,
			Counters:          []string{CounterUp(1), CounterDown(1), CounterUp(2), CounterDown(2)},
			Sets:              []string{SetQuotaBlock, AllowSetV4(2), "other_table_set"},
		})
	if !strings.Contains(script, "delete counter inet "+TableFilter+" "+CounterUp(2)) {
		t.Fatal("应删除已删规则的遗留 counter")
	}
	if !strings.Contains(script, "delete set inet "+TableFilter+" "+AllowSetV4(2)) {
		t.Fatal("应删除已删规则的遗留 set")
	}
	if strings.Contains(script, CounterUp(1)+"\ndelete") || strings.Contains(script, "delete counter inet "+TableFilter+" "+CounterUp(1)) {
		t.Fatal("不应删除仍在使用的 counter")
	}
	if strings.Contains(script, "delete set inet "+TableFilter+" "+SetQuotaBlock) {
		t.Fatal("绝不能删除 qblock set")
	}
	if strings.Contains(script, "other_table_set") {
		t.Fatal("绝不能删除非本程序前缀的对象")
	}
}
