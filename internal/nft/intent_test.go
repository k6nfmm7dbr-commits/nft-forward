package nft

import (
	"strings"
	"testing"

	"github.com/k6nfmm7dbr-commits/nft-forward/internal/forward"
)

// ---- 意图 ↔ 事实 同源性（v0.3.2）----
//
// 这一组测试的价值在于**锁死同源关系**：
//
//	ruleIntent.render() → nft 文本（实际下发内容）
//	ruleIntent.facts()  → 期望签名（自愈比对基准）
//
// 若两者漂移（例如脚本改了写法但 facts 没改），自愈会陷入
// 「每轮都判定漂移 → 每轮重建」的死循环。因此必须让「渲染出来的文本
// 再解析回 facts」与「直接 facts()」完全一致。
//
// 实现方式：把 render() 的输出交给一个最小 nft 文本 → JSON expr 转换器，
// 再用生产代码 parseRuleFacts 解析，最后比签名。

// textToExpr 把本项目生成的规则文本转成 nft JSON expr（与真实 nft 输出同构）。
//
// 与 policy 包测试里的 parseNftRuleText 是同一套语法子集；这里独立实现，
// 避免测试之间互相依赖。
func textToExpr(t *testing.T, s string) []any {
	t.Helper()
	toks := strings.Fields(s)
	var out []any
	num := func(v string) float64 {
		var n float64
		for _, c := range v {
			if c < '0' || c > '9' {
				t.Fatalf("非法数字 %q（规则: %s）", v, s)
			}
			n = n*10 + float64(c-'0')
		}
		return n
	}
	match := func(left any, op string, right any) map[string]any {
		return map[string]any{"match": map[string]any{"op": op, "left": left, "right": right}}
	}
	i := 0
	for i < len(toks) {
		switch {
		case i+3 < len(toks) && toks[i] == "fib" && toks[i+1] == "daddr" &&
			toks[i+2] == "type" && toks[i+3] == "local":
			out = append(out, match(
				map[string]any{"fib": map[string]any{"result": "type", "flags": []any{"daddr"}}},
				"==", "local"))
			i += 4
		case i+2 < len(toks) && (toks[i] == "tcp" || toks[i] == "udp") && toks[i+1] == "dport":
			out = append(out, match(
				map[string]any{"payload": map[string]any{"protocol": toks[i], "field": "dport"}},
				"==", num(toks[i+2])))
			i += 3
		case i+3 < len(toks) && toks[i] == "ct" && toks[i+1] == "mark" && toks[i+2] == "set":
			out = append(out, map[string]any{"mangle": map[string]any{
				"key":   map[string]any{"ct": map[string]any{"key": "mark"}},
				"value": num(toks[i+3]),
			}})
			i += 4
		case i+2 < len(toks) && toks[i] == "ct" && toks[i+1] == "mark":
			var right any
			if strings.HasPrefix(toks[i+2], "@") {
				right = toks[i+2]
			} else {
				right = num(toks[i+2])
			}
			out = append(out, match(map[string]any{"ct": map[string]any{"key": "mark"}}, "==", right))
			i += 3
		case i+2 < len(toks) && toks[i] == "ct" && toks[i+1] == "direction":
			out = append(out, match(
				map[string]any{"ct": map[string]any{"key": "direction"}}, "==", toks[i+2]))
			i += 3
		case i+2 < len(toks) && toks[i] == "ct" && toks[i+1] == "state":
			out = append(out, match(
				map[string]any{"ct": map[string]any{"key": "state"}}, "in", toks[i+2]))
			i += 3
		case i+3 < len(toks) && (toks[i] == "ip" || toks[i] == "ip6") &&
			toks[i+1] == "saddr" && toks[i+2] == "!=":
			out = append(out, match(
				map[string]any{"payload": map[string]any{"protocol": toks[i], "field": "saddr"}},
				"!=", toks[i+3]))
			i += 4
		case i+2 < len(toks) && toks[i] == "counter" && toks[i+1] == "name":
			out = append(out, map[string]any{"counter": strings.Trim(toks[i+2], `"`)})
			i += 3
		case i+2 < len(toks) && toks[i] == "dnat" && toks[i+1] == "to":
			target := toks[i+2]
			var addr string
			var port float64
			if strings.HasPrefix(target, "[") {
				end := strings.LastIndex(target, "]:")
				if end < 0 {
					t.Fatalf("非法 IPv6 DNAT 目标 %q", target)
				}
				addr = target[1:end]
				port = num(target[end+2:])
			} else {
				idx := strings.LastIndex(target, ":")
				if idx < 0 {
					t.Fatalf("非法 DNAT 目标 %q", target)
				}
				addr = target[:idx]
				port = num(target[idx+1:])
			}
			out = append(out, map[string]any{"dnat": map[string]any{"addr": addr, "port": port}})
			i += 3
		case toks[i] == "masquerade":
			out = append(out, map[string]any{"masquerade": nil})
			i++
		case toks[i] == "drop":
			out = append(out, map[string]any{"drop": nil})
			i++
		default:
			t.Fatalf("未识别 token %q（规则: %s）", toks[i], s)
		}
	}
	return out
}

// stripAddRulePrefix 去掉 "add rule <family> <table> <chain> " 前缀。
func stripAddRulePrefix(t *testing.T, line string) string {
	t.Helper()
	f := strings.Fields(line)
	if len(f) < 6 || f[0] != "add" || f[1] != "rule" {
		t.Fatalf("不是 add rule 行: %s", line)
	}
	return strings.Join(f[5:], " ")
}

// ★ 核心不变量：render() 的文本解析回来的 facts 必须等于 facts()。
func TestIntentRenderMatchesFacts(t *testing.T) {
	intents := []ruleIntent{
		{kind: intentDNAT, family: "ip", table: TableNAT4, chain: ChainPrerouting(TableNAT4),
			proto: "tcp", dport: 20000, mark: 7, dnatAddr: "1.2.3.4", dnatPort: 443},
		{kind: intentDNAT, family: "ip", table: TableNAT4, chain: ChainPrerouting(TableNAT4),
			proto: "udp", dport: 20001, mark: 8, dnatAddr: "10.0.0.9", dnatPort: 53},
		{kind: intentDNAT, family: "ip6", table: TableNAT6, chain: ChainPrerouting(TableNAT6),
			proto: "tcp", dport: 20002, mark: 9, dnatAddr: "2001:db8::1", dnatPort: 8443},
		{kind: intentMasquerade, family: "ip", table: TableNAT4, chain: ChainPostrouting(TableNAT4),
			markSet: MarksSet(TableNAT4)},
		{kind: intentQuotaDrop, family: "inet", table: TableFilter, chain: ChainForward(),
			markSet: SetQuotaBlock},
		{kind: intentCounter, family: "inet", table: TableFilter, chain: ChainForward(),
			mark: 7, dir: "original", counter: CounterUp(7)},
		{kind: intentCounter, family: "inet", table: TableFilter, chain: ChainForward(),
			mark: 7, dir: "reply", counter: CounterDown(7)},
		{kind: intentIPLimitDrop, family: "inet", table: TableFilter, chain: ChainForward(),
			mark: 7, dir: "original", saddrFam: "ip", allowSet: AllowSetV4(7)},
		{kind: intentIPLimitDrop, family: "inet", table: TableFilter, chain: ChainForward(),
			mark: 7, dir: "original", saddrFam: "ip6", allowSet: AllowSetV6(7)},
	}
	for _, in := range intents {
		line := in.render()
		if line == "" {
			t.Fatalf("%s 渲染为空", in.kind)
		}
		expr := textToExpr(t, stripAddRulePrefix(t, line))
		gotSig := parseRuleFacts(expr).Sig()
		wantSig := in.facts().Sig()
		if gotSig != wantSig {
			t.Errorf("%s 意图与事实不同源：\n  渲染文本: %s\n  解析签名: %s\n  期望签名: %s",
				in.kind, line, gotSig, wantSig)
		}
	}
}

// 生成的完整结构脚本里，每条 add rule 都必须能被 facts 识别（Kind != "other"）。
func TestGeneratedScriptRulesAllRecognized(t *testing.T) {
	gi := &GenInput{
		Rules: []*forward.Rule{{
			ID: 1, Name: "dual", Enabled: true, Protocol: forward.ProtoTCPUDP,
			ListenPort: 20000, TargetAddress: "dual.example.com", TargetPort: 443,
			ResolvedV4: "1.2.3.4", ResolvedV6: "2001:db8::1", ResolveStatus: forward.ResolveOK,
		}},
		States: map[int64]*RuleState{1: {IPLimitEnabled: true}},
	}
	script := GenStructScript(gi, nil)
	n := 0
	for _, line := range strings.Split(script, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "add rule ") {
			continue
		}
		n++
		expr := textToExpr(t, stripAddRulePrefix(t, line))
		f := parseRuleFacts(expr)
		if f.Kind == "other" {
			t.Errorf("生成的规则无法归类（自愈会漏检）: %s", line)
		}
		if len(f.Unknown) > 0 {
			t.Errorf("生成的规则含未识别表达式 %v: %s", f.Unknown, line)
		}
	}
	if n == 0 {
		t.Fatal("脚本里应有 add rule")
	}
}

// 生成脚本 → 解析签名 → 与 DesiredRuleSigs 完全一致（顺序也一致）。
func TestScriptSigsMatchDesiredSigs(t *testing.T) {
	gi := &GenInput{
		Rules: []*forward.Rule{
			{ID: 1, Name: "a", Enabled: true, Protocol: forward.ProtoTCP,
				ListenPort: 20000, TargetAddress: "1.2.3.4", TargetPort: 80},
			{ID: 2, Name: "b", Enabled: true, Protocol: forward.ProtoTCPUDP,
				ListenPort: 20001, TargetAddress: "2001:db8::2", TargetPort: 443},
		},
		States: map[int64]*RuleState{2: {IPLimitEnabled: true}},
	}
	script := GenStructScript(gi, nil)

	// 从脚本里按链收集签名
	got := map[string][]string{}
	for _, line := range strings.Split(script, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "add rule ") {
			continue
		}
		f := strings.Fields(line)
		key := ObjKey(f[2], f[3], f[4])
		expr := textToExpr(t, stripAddRulePrefix(t, line))
		got[key] = append(got[key], parseRuleFacts(expr).Sig())
	}

	want := DesiredRuleSigs(gi)
	if len(got) != len(want) {
		t.Fatalf("链数量不符：脚本 %d 期望 %d\n脚本键 %v\n期望键 %v",
			len(got), len(want), sortedChainKeys(got), sortedChainKeys(want))
	}
	for k, ws := range want {
		gs := got[k]
		if len(gs) != len(ws) {
			t.Errorf("链 %s 规则数不符：脚本 %d 期望 %d", k, len(gs), len(ws))
			continue
		}
		for i := range ws {
			if gs[i] != ws[i] {
				t.Errorf("链 %s 第 %d 条签名不符：\n  脚本 %s\n  期望 %s", k, i+1, gs[i], ws[i])
			}
		}
	}
}

// 未知表达式必须被记录（人为加料不得被忽略）。
func TestUnknownExpressionsRecorded(t *testing.T) {
	expr := []any{
		map[string]any{"match": map[string]any{"op": "==",
			"left": map[string]any{"ct": map[string]any{"key": "mark"}}, "right": float64(1)}},
		map[string]any{"limit": map[string]any{"rate": float64(10), "per": "second"}},
		map[string]any{"drop": nil},
	}
	f := parseRuleFacts(expr)
	if len(f.Unknown) == 0 {
		t.Fatal("limit 表达式应被记为 unknown（否则加料不被发现）")
	}
	if !strings.Contains(f.Sig(), "unknown=") {
		t.Fatalf("签名应体现 unknown，实际 %s", f.Sig())
	}
}

// meta 表达式（例如 meta mark）也必须计入 unknown。
func TestMetaExpressionRecorded(t *testing.T) {
	expr := []any{
		map[string]any{"match": map[string]any{"op": "==",
			"left": map[string]any{"meta": map[string]any{"key": "mark"}}, "right": float64(5)}},
		map[string]any{"accept": nil},
	}
	f := parseRuleFacts(expr)
	if len(f.Unknown) == 0 {
		t.Fatal("meta 匹配应被记为 unknown")
	}
}

// 匿名 counter 与 named counter 必须区分（前者不是本程序生成的）。
func TestAnonymousCounterRecorded(t *testing.T) {
	expr := []any{
		map[string]any{"counter": map[string]any{"packets": float64(1), "bytes": float64(2)}},
	}
	f := parseRuleFacts(expr)
	if f.Counter != "" {
		t.Fatal("匿名 counter 不应被当成 named counter 引用")
	}
	if len(f.Unknown) == 0 {
		t.Fatal("匿名 counter 应记为 unknown")
	}
}

// counter 的实时读数不得影响签名（否则有流量就会触发重建）。
func TestCounterBytesDoNotAffectSig(t *testing.T) {
	js := func(bytes int64) string {
		return `{"nftables":[
		 {"table":{"family":"inet","name":"nff_filter"}},
		 {"chain":{"family":"inet","table":"nff_filter","name":"nff_filter_forward",
		   "type":"filter","hook":"forward","prio":0,"policy":"accept"}},
		 {"counter":{"family":"inet","table":"nff_filter","name":"nff_filter_up_1","bytes":` +
			itoa(bytes) + `}},
		 {"rule":{"family":"inet","table":"nff_filter","chain":"nff_filter_forward","expr":[
		   {"match":{"op":"==","left":{"ct":{"key":"mark"}},"right":1}},
		   {"match":{"op":"==","left":{"ct":{"key":"direction"}},"right":"original"}},
		   {"counter":"nff_filter_up_1"}]}}
		]}`
	}
	a, err := ParseState(js(0))
	if err != nil {
		t.Fatal(err)
	}
	b, err := ParseState(js(999999999))
	if err != nil {
		t.Fatal(err)
	}
	key := ObjKey("inet", TableFilter, ChainForward())
	sa, _ := a.RuleSigsOf("inet", TableFilter, ChainForward())
	sb, _ := b.RuleSigsOf("inet", TableFilter, ChainForward())
	if len(sa) != 1 || len(sb) != 1 {
		t.Fatalf("应各有 1 条规则签名：%v / %v", sa, sb)
	}
	if sa[0] != sb[0] {
		t.Fatalf("counter 字节变化不应影响签名：\n%s\n%s", sa[0], sb[0])
	}
	if a.CounterBytes["nff_filter_up_1"] == b.CounterBytes["nff_filter_up_1"] {
		t.Fatal("counter 字节应被分别记录（供配额使用）")
	}
	_ = key
}

func itoa(v int64) string {
	if v == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}
