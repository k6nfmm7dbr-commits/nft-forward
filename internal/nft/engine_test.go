package nft

import (
	"strings"
	"testing"

	"github.com/k6nfmm7dbr-commits/nft-forward/internal/forward"
)

func rule(id int64, proto string, listenPort int, target string, targetPort int, enabled bool) *forward.Rule {
	return &forward.Rule{
		ID: id, Name: "r", Enabled: enabled, Protocol: proto,
		ListenPort:    listenPort,
		TargetAddress: target, TargetPort: targetPort,
	}
}

// domainRule 构造域名规则并附上解析结果（模拟 DNS reconcile 后的状态）。
func domainRule(id int64, proto string, listenPort int, host string, targetPort int, v4, v6 string) *forward.Rule {
	r := rule(id, proto, listenPort, host, targetPort, true)
	r.ResolvedV4 = v4
	r.ResolvedV6 = v6
	if v4 != "" || v6 != "" {
		r.ResolveStatus = forward.ResolveOK
	}
	return r
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
	// iptables 绝不能出现。
	for _, banned := range []string{"iptables", "ip6tables"} {
		if strings.Contains(script, banned) {
			t.Fatalf("nftables-only 项目不得引用 %q", banned)
		}
	}
}

// ★ TestTransitTrafficNotCaptured：每条 DNAT 规则都必须带 fib daddr type local，
// 否则这台机器承担路由职责时，仅仅「经过」本机（目的地址是别人）的同端口流量
// 也会被错误 DNAT 劫持。
func TestTransitTrafficNotCaptured(t *testing.T) {
	script := structScript([]*forward.Rule{
		rule(1, "tcp+udp", 5000, "1.2.3.4", 443, true),
		domainRule(2, "tcp", 5001, "hk.example.com", 443, "", "2001:db8::9"),
	}, nil)
	for _, line := range strings.Split(script, "\n") {
		if !strings.Contains(line, "dnat to") {
			continue
		}
		if !strings.Contains(line, "fib daddr type local") {
			t.Fatalf("DNAT 规则缺少 fib daddr type local（会劫持 transit 流量）:\n%s", line)
		}
		// fib 匹配必须在端口匹配之前（先确认发给本机再看端口）。
		fibIdx := strings.Index(line, "fib daddr type local")
		dportIdx := strings.Index(line, "dport")
		if fibIdx < 0 || dportIdx < 0 || fibIdx > dportIdx {
			t.Fatalf("fib 匹配应在 dport 之前:\n%s", line)
		}
	}
}

// TestLocalDestinationTrafficCaptured 发给本机的 v4/v6 流量都能命中对应数据面。
func TestLocalDestinationTrafficCaptured(t *testing.T) {
	script := structScript([]*forward.Rule{
		rule(1, "tcp", 5000, "1.2.3.4", 443, true),
		rule(2, "tcp", 5001, "2001:db8::1", 443, true),
	}, nil)
	wantV4 := "add rule ip " + TableNAT4 + " " + ChainPrerouting(TableNAT4) +
		" fib daddr type local tcp dport 5000 ct mark set 1 dnat to 1.2.3.4:443"
	if !strings.Contains(script, wantV4) {
		t.Fatalf("缺少 IPv4 本机匹配 DNAT 规则:\n%s", script)
	}
	wantV6 := "add rule ip6 " + TableNAT6 + " " + ChainPrerouting(TableNAT6) +
		" fib daddr type local tcp dport 5001 ct mark set 2 dnat to [2001:db8::1]:443"
	if !strings.Contains(script, wantV6) {
		t.Fatalf("缺少 IPv6 本机匹配 DNAT 规则:\n%s", script)
	}
}

// TestIPv4Forward IPv4 目标只进 nff_nat4。
func TestIPv4Forward(t *testing.T) {
	script := structScript([]*forward.Rule{rule(1, "tcp", 20000, "1.2.3.4", 443, true)}, nil)
	if !strings.Contains(script, "dnat to 1.2.3.4:443") {
		t.Fatal("缺少 IPv4 DNAT")
	}
	// nff_nat6 里不应出现该规则的 DNAT。
	v6Part := sectionOf(script, "table ip6 "+TableNAT6)
	if strings.Contains(v6Part, "dnat to") {
		t.Fatalf("IPv4 目标不应出现在 IPv6 表:\n%s", v6Part)
	}
}

// TestIPv6Forward IPv6 目标只进 nff_nat6，且地址加方括号。
func TestIPv6Forward(t *testing.T) {
	script := structScript([]*forward.Rule{rule(1, "udp", 20000, "2001:db8::1", 443, true)}, nil)
	if !strings.Contains(script, "dnat to [2001:db8::1]:443") {
		t.Fatalf("IPv6 DNAT 目标需方括号:\n%s", script)
	}
	v4Part := sectionOf(script, "table ip "+TableNAT4)
	if strings.Contains(v4Part, "dnat to") {
		t.Fatalf("IPv6 目标不应出现在 IPv4 表:\n%s", v4Part)
	}
}

// TestDomainIPv4DoesNotGenerateIPv6DNAT 只有 A 记录的域名不得产生 IPv6 DNAT。
func TestDomainIPv4DoesNotGenerateIPv6DNAT(t *testing.T) {
	script := structScript([]*forward.Rule{
		domainRule(1, "tcp+udp", 20000, "v4.example.com", 443, "1.2.3.4", ""),
	}, nil)
	if !strings.Contains(script, "dnat to 1.2.3.4:443") {
		t.Fatal("缺少 A 记录的 IPv4 DNAT")
	}
	v6Part := sectionOf(script, "table ip6 "+TableNAT6)
	if strings.Contains(v6Part, "dnat to") {
		t.Fatalf("只有 A 记录时不得生成 IPv6 DNAT（禁止 NAT46）:\n%s", v6Part)
	}
}

// TestDomainIPv6DoesNotGenerateIPv4DNAT 只有 AAAA 记录的域名不得产生 IPv4 DNAT。
func TestDomainIPv6DoesNotGenerateIPv4DNAT(t *testing.T) {
	script := structScript([]*forward.Rule{
		domainRule(1, "tcp", 20000, "v6.example.com", 443, "", "2001:db8::9"),
	}, nil)
	if !strings.Contains(script, "dnat to [2001:db8::9]:443") {
		t.Fatal("缺少 AAAA 记录的 IPv6 DNAT")
	}
	v4Part := sectionOf(script, "table ip "+TableNAT4)
	if strings.Contains(v4Part, "dnat to") {
		t.Fatalf("只有 AAAA 记录时不得生成 IPv4 DNAT（禁止 NAT64）:\n%s", v4Part)
	}
}

// TestDomainDualStackGeneratesBothPaths 双栈域名在两张表各自闭环，监听端口相同。
func TestDomainDualStackGeneratesBothPaths(t *testing.T) {
	script := structScript([]*forward.Rule{
		domainRule(1, "tcp", 20000, "dual.example.com", 443, "1.2.3.4", "2001:db8::9"),
	}, nil)
	if !strings.Contains(script, "add rule ip "+TableNAT4+" "+ChainPrerouting(TableNAT4)+
		" fib daddr type local tcp dport 20000 ct mark set 1 dnat to 1.2.3.4:443") {
		t.Fatalf("缺少 IPv4 路径:\n%s", script)
	}
	if !strings.Contains(script, "add rule ip6 "+TableNAT6+" "+ChainPrerouting(TableNAT6)+
		" fib daddr type local tcp dport 20000 ct mark set 1 dnat to [2001:db8::9]:443") {
		t.Fatalf("缺少 IPv6 路径:\n%s", script)
	}
}

// TestUnresolvedDomainKeepsCounters 域名解析失败时不生成 DNAT，但 counter 必须保留。
//
// 这是「DNS 故障不清零流量」的结构层保证。
func TestUnresolvedDomainKeepsCounters(t *testing.T) {
	r := rule(1, "tcp", 20000, "down.example.com", 443, true)
	r.ResolveStatus = forward.ResolveFailed
	script := structScript([]*forward.Rule{r}, nil)
	if strings.Contains(script, "dnat to") {
		t.Fatalf("无解析结果时不应生成 DNAT:\n%s", script)
	}
	if !strings.Contains(script, "counter "+CounterUp(1)) ||
		!strings.Contains(script, "counter "+CounterDown(1)) {
		t.Fatalf("counter 必须保留（否则 DNS 故障会清零流量）:\n%s", script)
	}
	// FORWARD 链的计数规则也必须保留。
	if !strings.Contains(script, "ct mark 1 ct direction original counter name") {
		t.Fatal("计数规则必须保留")
	}
}

func TestStructScriptSingleTCP(t *testing.T) {
	script := structScript([]*forward.Rule{rule(1, "tcp", 20000, "1.2.3.4", 443, true)}, nil)
	if !strings.Contains(script, "tcp dport 20000") {
		t.Fatal("缺少 TCP dport 匹配")
	}
	if strings.Contains(script, "udp dport 20000") {
		t.Fatal("TCP-only 规则不应生成 UDP 匹配")
	}
	if !strings.Contains(script, "ct mark set 1") {
		t.Fatal("缺少 ct mark 归属")
	}
	if !strings.Contains(script, "masquerade") {
		t.Fatal("缺少 masquerade")
	}
}

// TestStructScriptMultiRuleSameTarget 多规则指向同目标时用 ct mark 区分归属。
func TestStructScriptMultiRuleSameTarget(t *testing.T) {
	script := structScript([]*forward.Rule{
		rule(1, "tcp", 20000, "1.2.3.4", 80, true),
		rule(2, "tcp", 30000, "1.2.3.4", 80, true),
	}, nil)
	if !strings.Contains(script, "ct mark set 1") || !strings.Contains(script, "ct mark set 2") {
		t.Fatal("两条规则应分别打不同 ct mark")
	}
	if !strings.Contains(script, `counter name "`+CounterUp(1)+`"`) ||
		!strings.Contains(script, `counter name "`+CounterUp(2)+`"`) {
		t.Fatal("两条规则应有各自 counter")
	}
}

func TestStructScriptTCPUDP(t *testing.T) {
	script := structScript([]*forward.Rule{rule(1, "tcp+udp", 20000, "1.2.3.4", 443, true)}, nil)
	if !strings.Contains(script, "tcp dport 20000") || !strings.Contains(script, "udp dport 20000") {
		t.Fatalf("tcp+udp 规则应同时生成两种协议匹配:\n%s", script)
	}
}

func TestStructScriptIPv6(t *testing.T) {
	script := structScript([]*forward.Rule{rule(1, "tcp", 20000, "2001:db8::1", 443, true)}, nil)
	if !strings.Contains(script, "table ip6 "+TableNAT6) {
		t.Fatal("IPv6 规则应进 nff_nat6")
	}
}

func TestStructScriptDisabledExcluded(t *testing.T) {
	script := structScript([]*forward.Rule{
		rule(1, "tcp", 20000, "1.2.3.4", 443, false),
	}, nil)
	if strings.Contains(script, "dport 20000") {
		t.Fatal("停用规则不应生成 DNAT")
	}
}

// TestQuotaBlockUsesSetNotChainRebuild 配额阻断走 set 元素，不是重建链。
func TestQuotaBlockUsesSetNotChainRebuild(t *testing.T) {
	script := structScript([]*forward.Rule{rule(1, "tcp", 20000, "1.2.3.4", 443, true)}, nil)
	if !strings.Contains(script, "ct mark @"+SetQuotaBlock+" drop") {
		t.Fatal("应通过 qblock set 实现配额阻断")
	}
	// 配额状态不在结构签名里 —— 翻转配额不应改变签名。
	gi := &GenInput{Rules: []*forward.Rule{rule(1, "tcp", 20000, "1.2.3.4", 443, true)}}
	sig1 := StructSig(gi)
	gi.States = map[int64]*RuleState{1: {QuotaExceeded: true}}
	if StructSig(gi) != sig1 {
		t.Fatal("配额超限状态不应影响结构签名（否则会触发不必要的链重写）")
	}
}

func TestStructScriptIPLimitRules(t *testing.T) {
	states := map[int64]*RuleState{1: {IPLimitEnabled: true}}
	script := structScript([]*forward.Rule{rule(1, "tcp", 20000, "1.2.3.4", 443, true)}, states)
	if !strings.Contains(script, "set "+AllowSetV4(1)) || !strings.Contains(script, "set "+AllowSetV6(1)) {
		t.Fatal("启用 IP 限制应声明 v4/v6 allow set")
	}
	// drop 规则必须限定 ct direction original + established，否则返回包会被丢弃。
	for _, want := range []string{
		"ct direction original ct state established ip saddr != @" + AllowSetV4(1) + " drop",
		"ct direction original ct state established ip6 saddr != @" + AllowSetV6(1) + " drop",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("IP 限制 drop 规则不正确，缺少:\n%s\n实际:\n%s", want, script)
		}
	}
}

// TestAllowElementsDoNotAffectStruct allow set 元素不进结构签名。
func TestAllowElementsDoNotAffectStruct(t *testing.T) {
	gi := &GenInput{
		Rules:  []*forward.Rule{rule(1, "tcp", 20000, "1.2.3.4", 443, true)},
		States: map[int64]*RuleState{1: {IPLimitEnabled: true, AllowV4: []string{"9.9.9.9"}}},
	}
	sig1 := StructSig(gi)
	gi.States[1].AllowV4 = []string{"9.9.9.9", "8.8.8.8"}
	if StructSig(gi) != sig1 {
		t.Fatal("allow set 元素变化不应改变结构签名")
	}
}

// TestStructSigChangesOnRealStructChange 真实结构变化必须改变签名。
func TestStructSigChangesOnRealStructChange(t *testing.T) {
	base := &GenInput{Rules: []*forward.Rule{rule(1, "tcp", 20000, "1.2.3.4", 443, true)}}
	sig := StructSig(base)

	cases := map[string]*GenInput{
		"端口变化":     {Rules: []*forward.Rule{rule(1, "tcp", 20001, "1.2.3.4", 443, true)}},
		"协议变化":     {Rules: []*forward.Rule{rule(1, "tcp+udp", 20000, "1.2.3.4", 443, true)}},
		"目标地址变化":   {Rules: []*forward.Rule{rule(1, "tcp", 20000, "5.6.7.8", 443, true)}},
		"目标端口变化":   {Rules: []*forward.Rule{rule(1, "tcp", 20000, "1.2.3.4", 8443, true)}},
		"新增规则":     {Rules: []*forward.Rule{rule(1, "tcp", 20000, "1.2.3.4", 443, true), rule(2, "tcp", 20002, "1.2.3.4", 443, true)}},
		"启用 IP 限制": {Rules: []*forward.Rule{rule(1, "tcp", 20000, "1.2.3.4", 443, true)}, States: map[int64]*RuleState{1: {IPLimitEnabled: true}}},
	}
	for name, gi := range cases {
		if StructSig(gi) == sig {
			t.Fatalf("%s 应当改变结构签名", name)
		}
	}
}

// TestStructSigChangesOnDNSTargetChange DNS 解析结果变化必须改变签名（触发链重写）。
func TestStructSigChangesOnDNSTargetChange(t *testing.T) {
	gi := &GenInput{Rules: []*forward.Rule{
		domainRule(1, "tcp", 20000, "hk.example.com", 443, "1.2.3.4", ""),
	}}
	sig := StructSig(gi)
	gi.Rules[0].ResolvedV4 = "5.6.7.8"
	if StructSig(gi) == sig {
		t.Fatal("DNS 目标变化必须改变结构签名")
	}
	// 但状态文本（stale/ok）变化不应影响签名 —— 那不改变数据面。
	gi.Rules[0].ResolvedV4 = "1.2.3.4"
	if StructSig(gi) != sig {
		t.Fatal("恢复同一地址后签名应当一致")
	}
	gi.Rules[0].ResolveStatus = forward.ResolveStale
	gi.Rules[0].ResolveError = "timeout"
	if StructSig(gi) != sig {
		t.Fatal("解析状态文本不应影响结构签名")
	}
}

// TestStaleObjectCleanup 规则删除后残留 counter / set 必须被清理（只删自有前缀）。
func TestStaleObjectCleanup(t *testing.T) {
	ex := &Existing{
		FilterTableExists: true,
		Counters:          []string{CounterUp(1), CounterDown(1), CounterUp(99), "someone_else_counter"},
		Sets:              []string{SetQuotaBlock, AllowSetV4(99), "other_set"},
	}
	script := GenStructScript(&GenInput{
		Rules: []*forward.Rule{rule(1, "tcp", 20000, "1.2.3.4", 443, true)},
	}, ex)
	if !strings.Contains(script, "delete counter inet "+TableFilter+" "+CounterUp(99)) {
		t.Fatalf("应清理已删除规则的 counter:\n%s", script)
	}
	if !strings.Contains(script, "delete set inet "+TableFilter+" "+AllowSetV4(99)) {
		t.Fatalf("应清理已删除规则的 allow set:\n%s", script)
	}
	if strings.Contains(script, "someone_else_counter") || strings.Contains(script, "other_set") {
		t.Fatal("绝不能删除非本程序前缀的对象")
	}
	if strings.Contains(script, "delete set inet "+TableFilter+" "+SetQuotaBlock) {
		t.Fatal("qblock set 应永久保留")
	}
}

// sectionOf 截取从 marker 开始到下一个 "table " 声明之前的片段。
func sectionOf(script, marker string) string {
	i := strings.Index(script, marker)
	if i < 0 {
		return ""
	}
	rest := script[i+len(marker):]
	if j := strings.Index(rest, "\ntable "); j >= 0 {
		return rest[:j]
	}
	return rest
}
