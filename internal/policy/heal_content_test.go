package policy

import (
	"context"
	"strings"
	"testing"

	"github.com/k6nfmm7dbr-commits/nft-forward/internal/nft"
)

// ---- 内容漂移自愈（v0.3.2）----
//
// 这一组测试的共同特征：**规则条数不变、对象都在**，只有规则内容被改动。
// 旧实现（只比对象存在 + 条数）对它们全部漏检。
//
// 篡改手法一律是直接改模拟器里的 expr（等价于 `nft replace rule`），
// 而 nft.State 由生产代码 nft.ParseState 从模拟器输出的真 JSON 解析，
// 因此这些测试真正验证的是生产侧的 parseRuleFacts + DetectDrift。

// natPre 返回 IPv4 NAT prerouting 链的三元组。
func natPre() (string, string, string) {
	return "ip", nft.TableNAT4, nft.ChainPrerouting(nft.TableNAT4)
}

// natPost 返回 IPv4 NAT postrouting 链的三元组。
func natPost() (string, string, string) {
	return "ip", nft.TableNAT4, nft.ChainPostrouting(nft.TableNAT4)
}

// fwd 返回 filter forward 链的三元组。
func fwd() (string, string, string) {
	return "inet", nft.TableFilter, nft.ChainForward()
}

// assertContentHealed 跑一轮 reconcile 并断言：
//  1. 发生了结构重建（说明漂移被检测到）；
//  2. 重建后不再有漂移（再跑一轮不应继续重建）；
//  3. 脚本里没有 flush ruleset / delete table。
func assertContentHealed(t *testing.T, svc *Service, fake *fakeNFT, what string) {
	t.Helper()
	fake.resetScripts()
	if err := svc.Reconcile(context.Background()); err != nil {
		t.Fatalf("%s：自愈 reconcile 失败: %v", what, err)
	}
	if fake.structRebuilds() == 0 {
		t.Fatalf("%s：未触发结构重建（漂移被漏检）", what)
	}
	for _, s := range fake.allScripts() {
		if strings.Contains(s, "flush ruleset") || strings.Contains(s, "delete table") {
			t.Fatalf("%s：自愈脚本不得出现 flush ruleset / delete table:\n%s", what, s)
		}
	}
	// 收敛性：修好之后不应继续重建（否则会无限重写链、反复触发）。
	fake.resetScripts()
	if err := svc.Reconcile(context.Background()); err != nil {
		t.Fatalf("%s：二次 reconcile 失败: %v", what, err)
	}
	if n := fake.structRebuilds(); n != 0 {
		t.Fatalf("%s：修复后仍反复重建 %d 次（期望收敛）", what, n)
	}
}

// ① DNAT 目标地址被改（条数不变）—— 最危险的篡改：流量被劫持到别处。
func TestHealDNATAddressTampered(t *testing.T) {
	svc, _, fake, _ := healSetup(t)
	f, tb, ch := natPre()
	rules := fake.rulesOf(f, tb, ch)
	if len(rules) == 0 {
		t.Fatal("前置条件失败：prerouting 应有 DNAT 规则")
	}
	before := fake.ruleCount(f, tb, ch)

	// 把第一条 DNAT 的目标地址换成 8.8.8.8。
	fake.replaceRule(f, tb, ch, 0, tamperDNATAddr(rules[0], "8.8.8.8"))
	if fake.ruleCount(f, tb, ch) != before {
		t.Fatal("篡改不应改变规则条数（否则测的就不是等数量篡改）")
	}
	assertContentHealed(t, svc, fake, "DNAT 目标地址被改")

	// 修复后目标必须回到原值。
	for _, expr := range fake.rulesOf(f, tb, ch) {
		if addr := dnatAddrOf(expr); addr == "8.8.8.8" {
			t.Fatal("篡改的 DNAT 目标未被修复")
		}
	}
}

// ② DNAT 目标端口被改。
func TestHealDNATPortTampered(t *testing.T) {
	svc, _, fake, _ := healSetup(t)
	f, tb, ch := natPre()
	rules := fake.rulesOf(f, tb, ch)
	fake.replaceRule(f, tb, ch, 0, tamperDNATPort(rules[0], 31337))
	assertContentHealed(t, svc, fake, "DNAT 目标端口被改")
	for _, expr := range fake.rulesOf(f, tb, ch) {
		if p := dnatPortOf(expr); p == 31337 {
			t.Fatal("篡改的 DNAT 端口未被修复")
		}
	}
}

// ③ 协议 tcp → udp（监听端口与目标都不变）。
func TestHealDNATProtocolTampered(t *testing.T) {
	svc, _, fake, _ := healSetup(t)
	f, tb, ch := natPre()
	rules := fake.rulesOf(f, tb, ch)
	// healSetup 的规则是 tcp+udp，第 0 条是 tcp；把它改成 udp 会造成
	// 「两条 udp、零条 tcp」——条数不变但 TCP 转发已失效。
	fake.replaceRule(f, tb, ch, 0, tamperProto(rules[0], "udp"))
	assertContentHealed(t, svc, fake, "DNAT 协议被改")
	protos := map[string]int{}
	for _, expr := range fake.rulesOf(f, tb, ch) {
		protos[protoOf(expr)]++
	}
	if protos["tcp"] == 0 {
		t.Fatalf("TCP DNAT 未被恢复: %v", protos)
	}
}

// ④ 监听端口被改。
func TestHealDNATListenPortTampered(t *testing.T) {
	svc, _, fake, _ := healSetup(t)
	f, tb, ch := natPre()
	rules := fake.rulesOf(f, tb, ch)
	fake.replaceRule(f, tb, ch, 0, tamperDPort(rules[0], 65001))
	assertContentHealed(t, svc, fake, "监听端口被改")
	for _, expr := range fake.rulesOf(f, tb, ch) {
		if dportOf(expr) == 65001 {
			t.Fatal("篡改的监听端口未被修复")
		}
	}
}

// ⑤ ct mark 被改（流量会记到别的规则名下）。
func TestHealCtMarkTampered(t *testing.T) {
	svc, _, fake, _ := healSetup(t)
	f, tb, ch := natPre()
	rules := fake.rulesOf(f, tb, ch)
	fake.replaceRule(f, tb, ch, 0, tamperSetMark(rules[0], 9999))
	assertContentHealed(t, svc, fake, "ct mark set 被改")
}

// ⑥ fib daddr type local 被删（会劫持 transit 流量）。
func TestHealFibLocalRemoved(t *testing.T) {
	svc, _, fake, _ := healSetup(t)
	f, tb, ch := natPre()
	rules := fake.rulesOf(f, tb, ch)
	fake.replaceRule(f, tb, ch, 0, dropFirstExpr(rules[0]))
	assertContentHealed(t, svc, fake, "fib daddr local 被删")
}

// ⑦ counter 引用被删（流量不再计数，但规则条数不变）。
func TestHealCounterReferenceRemoved(t *testing.T) {
	svc, _, fake, id := healSetup(t)
	f, tb, ch := fwd()
	rules := fake.rulesOf(f, tb, ch)
	idx := findExprIdx(rules, func(e []any) bool { return counterOf(e) == nft.CounterUp(id) })
	if idx < 0 {
		t.Fatal("前置条件失败：未找到 up counter 规则")
	}
	// 把 counter 表达式换成 accept —— 条数不变，计数彻底失效。
	fake.replaceRule(f, tb, ch, idx, replaceLastExpr(rules[idx], map[string]any{"accept": nil}))
	assertContentHealed(t, svc, fake, "counter 引用被删")
	rules = fake.rulesOf(f, tb, ch)
	if findExprIdx(rules, func(e []any) bool { return counterOf(e) == nft.CounterUp(id) }) < 0 {
		t.Fatal("counter 引用未被恢复")
	}
}

// ⑧ counter 引用被换成另一个 counter（流量记到别处）。
func TestHealCounterReferenceSwapped(t *testing.T) {
	svc, _, fake, id := healSetup(t)
	f, tb, ch := fwd()
	rules := fake.rulesOf(f, tb, ch)
	idx := findExprIdx(rules, func(e []any) bool { return counterOf(e) == nft.CounterUp(id) })
	fake.replaceRule(f, tb, ch, idx,
		replaceLastExpr(rules[idx], map[string]any{"counter": nft.CounterDown(id)}))
	assertContentHealed(t, svc, fake, "counter 引用被换")
}

// ⑨ allow set 引用被换错（IP 限制被绕过或误伤）。
func TestHealAllowSetReferenceSwapped(t *testing.T) {
	svc, _, fake, id := healSetup(t)
	f, tb, ch := fwd()
	rules := fake.rulesOf(f, tb, ch)
	idx := findExprIdx(rules, func(e []any) bool {
		return saddrSetOf(e) == "@"+nft.AllowSetV4(id)
	})
	if idx < 0 {
		t.Fatal("前置条件失败：未找到 IPv4 allow set drop 规则")
	}
	fake.replaceRule(f, tb, ch, idx, tamperSaddrSet(rules[idx], "@nff_filter_allow_99999_v4"))
	assertContentHealed(t, svc, fake, "allow set 引用被换")
	rules = fake.rulesOf(f, tb, ch)
	if findExprIdx(rules, func(e []any) bool {
		return saddrSetOf(e) == "@"+nft.AllowSetV4(id)
	}) < 0 {
		t.Fatal("allow set 引用未被恢复")
	}
}

// ⑩ 配额阻断规则被改成 accept（配额彻底失效）。
func TestHealQuotaDropTampered(t *testing.T) {
	svc, _, fake, _ := healSetup(t)
	f, tb, ch := fwd()
	rules := fake.rulesOf(f, tb, ch)
	// 第 0 条必须是 qblock drop。
	if verdictOf(rules[0]) != "drop" {
		t.Fatalf("前置条件失败：forward 首条应为 drop，实际 %+v", rules[0])
	}
	fake.replaceRule(f, tb, ch, 0, replaceLastExpr(rules[0], map[string]any{"accept": nil}))
	assertContentHealed(t, svc, fake, "配额阻断规则被改成 accept")
	rules = fake.rulesOf(f, tb, ch)
	if verdictOf(rules[0]) != "drop" {
		t.Fatal("配额阻断规则未被恢复")
	}
}

// ⑪ masquerade 被改成 accept（回程 SNAT 失效）。
func TestHealMasqueradeTampered(t *testing.T) {
	svc, _, fake, _ := healSetup(t)
	f, tb, ch := natPost()
	rules := fake.rulesOf(f, tb, ch)
	if len(rules) == 0 {
		t.Fatal("前置条件失败：postrouting 应有 masquerade 规则")
	}
	fake.replaceRule(f, tb, ch, 0, replaceLastExpr(rules[0], map[string]any{"accept": nil}))
	assertContentHealed(t, svc, fake, "masquerade 被改")
}

// ⑫ 链属性被改（hook / priority / policy）—— 整条链失效但对象都在。
func TestHealChainHookTampered(t *testing.T) {
	svc, _, fake, _ := healSetup(t)
	f, tb, ch := fwd()
	fake.setChainAttrs(f, tb, ch, nft.ChainAttrs{
		Type: "filter", Hook: "input", Priority: 0, Policy: "accept",
	})
	// 注意：模拟器的链属性只在链首次创建时设置，重建脚本用的是幂等
	// `chain {...}` 声明，不会覆盖已存在链的属性。因此这里断言的是
	// 「漂移被检测到」，真实 nft 上重建会带上正确的 hook。
	fake.resetScripts()
	if err := svc.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fake.structRebuilds() == 0 {
		t.Fatal("链 hook 被改动应触发重建")
	}
}

func TestHealChainPriorityTampered(t *testing.T) {
	svc, _, fake, _ := healSetup(t)
	f, tb, ch := natPre()
	fake.setChainAttrs(f, tb, ch, nft.ChainAttrs{
		Type: "nat", Hook: "prerouting", Priority: 200, Policy: "accept",
	})
	fake.resetScripts()
	if err := svc.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fake.structRebuilds() == 0 {
		t.Fatal("链 priority 被改动应触发重建")
	}
}

func TestHealChainPolicyTampered(t *testing.T) {
	svc, _, fake, _ := healSetup(t)
	f, tb, ch := fwd()
	fake.setChainAttrs(f, tb, ch, nft.ChainAttrs{
		Type: "filter", Hook: "forward", Priority: 0, Policy: "drop",
	})
	fake.resetScripts()
	if err := svc.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fake.structRebuilds() == 0 {
		t.Fatal("链 policy 被改动应触发重建")
	}
}

// ⑬ 插入额外规则（条数变多）。
func TestHealExtraRuleInjected(t *testing.T) {
	svc, _, fake, _ := healSetup(t)
	f, tb, ch := fwd()
	fake.appendRawRule(f, tb, ch, []any{map[string]any{"drop": nil}})
	assertContentHealed(t, svc, fake, "插入额外规则")
}

// ⑭ 删一条正确规则 + 加一条无关规则（条数完全相同）。
//
// 这是最能区分「数量校验」与「内容校验」的场景：旧实现完全看不出来。
func TestHealSameCountDifferentRules(t *testing.T) {
	svc, _, fake, id := healSetup(t)
	f, tb, ch := fwd()
	rules := fake.rulesOf(f, tb, ch)
	before := len(rules)
	idx := findExprIdx(rules, func(e []any) bool { return counterOf(e) == nft.CounterDown(id) })
	if idx < 0 {
		t.Fatal("前置条件失败：未找到 down counter 规则")
	}
	fake.deleteRuleAt(f, tb, ch, idx)
	fake.appendRawRule(f, tb, ch, []any{map[string]any{"accept": nil}})
	if fake.ruleCount(f, tb, ch) != before {
		t.Fatalf("条数应保持不变：期望 %d 实际 %d", before, fake.ruleCount(f, tb, ch))
	}
	assertContentHealed(t, svc, fake, "等数量替换规则")
	rules = fake.rulesOf(f, tb, ch)
	if findExprIdx(rules, func(e []any) bool { return counterOf(e) == nft.CounterDown(id) }) < 0 {
		t.Fatal("down counter 规则未被恢复")
	}
}

// ⑮ 规则顺序被调换（配额阻断被挪到 counter 之后 → 被阻断流量仍计费）。
func TestHealRuleOrderSwapped(t *testing.T) {
	svc, _, fake, _ := healSetup(t)
	f, tb, ch := fwd()
	rules := fake.rulesOf(f, tb, ch)
	if len(rules) < 2 {
		t.Fatal("前置条件失败：forward 链规则太少")
	}
	fake.mu.Lock()
	key := f + "/" + tb + "/" + ch
	fake.chainExprs[key][0], fake.chainExprs[key][1] = fake.chainExprs[key][1], fake.chainExprs[key][0]
	fake.mu.Unlock()
	assertContentHealed(t, svc, fake, "规则顺序被调换")
	rules = fake.rulesOf(f, tb, ch)
	if verdictOf(rules[0]) != "drop" {
		t.Fatal("配额阻断规则未回到首位")
	}
}

// ⑯ ct direction 被改（up/down 方向统计错位）。
func TestHealCtDirectionTampered(t *testing.T) {
	svc, _, fake, id := healSetup(t)
	f, tb, ch := fwd()
	rules := fake.rulesOf(f, tb, ch)
	idx := findExprIdx(rules, func(e []any) bool { return counterOf(e) == nft.CounterUp(id) })
	fake.replaceRule(f, tb, ch, idx, tamperDirection(rules[idx], "reply"))
	assertContentHealed(t, svc, fake, "ct direction 被改")
}

// ⑰ ct state established 被删（IP 限制会把 SYN 也 drop，新客户端永远连不上）。
func TestHealCtStateRemoved(t *testing.T) {
	svc, _, fake, id := healSetup(t)
	f, tb, ch := fwd()
	rules := fake.rulesOf(f, tb, ch)
	idx := findExprIdx(rules, func(e []any) bool {
		return saddrSetOf(e) == "@"+nft.AllowSetV4(id)
	})
	fake.replaceRule(f, tb, ch, idx, dropExprAt(rules[idx], 2))
	assertContentHealed(t, svc, fake, "ct state established 被删")
}

// ⑱ 稳定期不得反复重建（内容一致时 counter 不能被清零）。
func TestContentCheckDoesNotCauseRebuildLoop(t *testing.T) {
	svc, _, fake, id := healSetup(t)
	fake.resetScripts()
	for i := 0; i < 12; i++ {
		if err := svc.Reconcile(context.Background()); err != nil {
			t.Fatalf("第 %d 轮失败: %v", i, err)
		}
		// 每轮制造流量：counter 读数变化绝不能被当成结构漂移。
		fake.bumpCounter(nft.CounterUp(id), int64(1000*(i+1)))
		fake.bumpCounter(nft.CounterDown(id), int64(500*(i+1)))
	}
	if n := fake.structRebuilds(); n != 0 {
		t.Fatalf("内容一致 + 有流量时不应重建，实际 %d 次", n)
	}
}

// ---- expr 篡改辅助 ----

func tamperDNATAddr(expr []any, addr string) []any {
	out := cloneExpr(expr)
	for _, e := range out {
		if m, ok := e.(map[string]any); ok {
			if d, ok := m["dnat"].(map[string]any); ok {
				d["addr"] = addr
			}
		}
	}
	return out
}

func tamperDNATPort(expr []any, port int) []any {
	out := cloneExpr(expr)
	for _, e := range out {
		if m, ok := e.(map[string]any); ok {
			if d, ok := m["dnat"].(map[string]any); ok {
				d["port"] = float64(port)
			}
		}
	}
	return out
}

func tamperProto(expr []any, proto string) []any {
	out := cloneExpr(expr)
	for _, e := range out {
		if m, ok := e.(map[string]any); ok {
			if mm, ok := m["match"].(map[string]any); ok {
				if lm, ok := mm["left"].(map[string]any); ok {
					if pl, ok := lm["payload"].(map[string]any); ok && pl["field"] == "dport" {
						pl["protocol"] = proto
					}
				}
			}
		}
	}
	return out
}

func tamperDPort(expr []any, port int) []any {
	out := cloneExpr(expr)
	for _, e := range out {
		if m, ok := e.(map[string]any); ok {
			if mm, ok := m["match"].(map[string]any); ok {
				if lm, ok := mm["left"].(map[string]any); ok {
					if pl, ok := lm["payload"].(map[string]any); ok && pl["field"] == "dport" {
						mm["right"] = float64(port)
					}
				}
			}
		}
	}
	return out
}

func tamperSetMark(expr []any, mark int) []any {
	out := cloneExpr(expr)
	for _, e := range out {
		if m, ok := e.(map[string]any); ok {
			if mg, ok := m["mangle"].(map[string]any); ok {
				mg["value"] = float64(mark)
			}
		}
	}
	return out
}

func tamperDirection(expr []any, dir string) []any {
	out := cloneExpr(expr)
	for _, e := range out {
		if m, ok := e.(map[string]any); ok {
			if mm, ok := m["match"].(map[string]any); ok {
				if lm, ok := mm["left"].(map[string]any); ok {
					if ct, ok := lm["ct"].(map[string]any); ok && ct["key"] == "direction" {
						mm["right"] = dir
					}
				}
			}
		}
	}
	return out
}

func tamperSaddrSet(expr []any, setRef string) []any {
	out := cloneExpr(expr)
	for _, e := range out {
		if m, ok := e.(map[string]any); ok {
			if mm, ok := m["match"].(map[string]any); ok {
				if lm, ok := mm["left"].(map[string]any); ok {
					if pl, ok := lm["payload"].(map[string]any); ok && pl["field"] == "saddr" {
						mm["right"] = setRef
					}
				}
			}
		}
	}
	return out
}

// dropFirstExpr 删掉第一个表达式。
func dropFirstExpr(expr []any) []any { return dropExprAt(expr, 0) }

// dropExprAt 删掉第 idx 个表达式。
func dropExprAt(expr []any, idx int) []any {
	out := cloneExpr(expr)
	if idx < 0 || idx >= len(out) {
		return out
	}
	return append(out[:idx:idx], out[idx+1:]...)
}

// replaceLastExpr 用 repl 替换最后一个表达式（通常是 verdict / counter）。
func replaceLastExpr(expr []any, repl map[string]any) []any {
	out := cloneExpr(expr)
	if len(out) == 0 {
		return []any{repl}
	}
	out[len(out)-1] = repl
	return out
}

// cloneExpr 深拷贝 expr（避免篡改影响原始切片）。
func cloneExpr(expr []any) []any {
	out := make([]any, 0, len(expr))
	for _, e := range expr {
		out = append(out, cloneAny(e))
	}
	return out
}

func cloneAny(v any) any {
	switch t := v.(type) {
	case map[string]any:
		m := make(map[string]any, len(t))
		for k, val := range t {
			m[k] = cloneAny(val)
		}
		return m
	case []any:
		l := make([]any, 0, len(t))
		for _, val := range t {
			l = append(l, cloneAny(val))
		}
		return l
	}
	return v
}

// ---- expr 读取辅助 ----

func findExprIdx(rules [][]any, pred func([]any) bool) int {
	for i, r := range rules {
		if pred(r) {
			return i
		}
	}
	return -1
}

func counterOf(expr []any) string {
	for _, e := range expr {
		if m, ok := e.(map[string]any); ok {
			if s, ok := m["counter"].(string); ok {
				return s
			}
		}
	}
	return ""
}

func verdictOf(expr []any) string {
	for _, e := range expr {
		if m, ok := e.(map[string]any); ok {
			for _, k := range []string{"drop", "accept", "masquerade"} {
				if _, ok := m[k]; ok {
					return k
				}
			}
		}
	}
	return ""
}

func dnatAddrOf(expr []any) string {
	for _, e := range expr {
		if m, ok := e.(map[string]any); ok {
			if d, ok := m["dnat"].(map[string]any); ok {
				s, _ := d["addr"].(string)
				return s
			}
		}
	}
	return ""
}

func dnatPortOf(expr []any) int {
	for _, e := range expr {
		if m, ok := e.(map[string]any); ok {
			if d, ok := m["dnat"].(map[string]any); ok {
				if f, ok := d["port"].(float64); ok {
					return int(f)
				}
			}
		}
	}
	return 0
}

func protoOf(expr []any) string {
	for _, e := range expr {
		if m, ok := e.(map[string]any); ok {
			if mm, ok := m["match"].(map[string]any); ok {
				if lm, ok := mm["left"].(map[string]any); ok {
					if pl, ok := lm["payload"].(map[string]any); ok && pl["field"] == "dport" {
						s, _ := pl["protocol"].(string)
						return s
					}
				}
			}
		}
	}
	return ""
}

func dportOf(expr []any) int {
	for _, e := range expr {
		if m, ok := e.(map[string]any); ok {
			if mm, ok := m["match"].(map[string]any); ok {
				if lm, ok := mm["left"].(map[string]any); ok {
					if pl, ok := lm["payload"].(map[string]any); ok && pl["field"] == "dport" {
						if f, ok := mm["right"].(float64); ok {
							return int(f)
						}
					}
				}
			}
		}
	}
	return 0
}

func saddrSetOf(expr []any) string {
	for _, e := range expr {
		if m, ok := e.(map[string]any); ok {
			if mm, ok := m["match"].(map[string]any); ok {
				if lm, ok := mm["left"].(map[string]any); ok {
					if pl, ok := lm["payload"].(map[string]any); ok && pl["field"] == "saddr" {
						s, _ := mm["right"].(string)
						return s
					}
				}
			}
		}
	}
	return ""
}
