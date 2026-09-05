package nft

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// ---- 规则意图（intent）：文本脚本与 Desired 内容校验的**唯一来源** ----
//
// 为什么需要它：自愈如果只比「对象存在 + 链内规则条数」，下面这类篡改会漏检
//
//	tcp dport 30001 dnat to 1.2.3.4:443   →   tcp dport 30001 dnat to 8.8.8.8:443
//
// 表、链、set、counter 都在，规则条数也没变，但数据面已经被劫持到别处。
//
// 因此必须做**内容**校验。而内容校验最大的风险是「期望值」与「实际生成的脚本」
// 各写一遍导致漂移：脚本改了、期望没改，自愈就会陷入无限重建或永久漏检。
//
// 解决办法是让两者同源：
//
//	ruleIntent ──render()──▶ nft 文本脚本（GenStructScript 实际下发的内容）
//	           └─facts()──▶ RuleFacts（与 nft -j 输出解析结果比对的期望值）
//
// 任何规则形态变化只需改 ruleIntent 一处，两侧自动同步。

// intentKind 是规则意图的类别。
type intentKind string

const (
	// intentDNAT 是 NAT 表 prerouting 里的一条 DNAT 规则。
	intentDNAT intentKind = "dnat"
	// intentMasquerade 是 NAT 表 postrouting 里的 masquerade 规则。
	intentMasquerade intentKind = "masquerade"
	// intentQuotaDrop 是 filter forward 链最前的配额阻断规则。
	intentQuotaDrop intentKind = "qdrop"
	// intentCounter 是 filter forward 链里按方向计数的规则。
	intentCounter intentKind = "counter"
	// intentIPLimitDrop 是 filter forward 链里的 IP 限制 drop 规则。
	intentIPLimitDrop intentKind = "iplimit"
)

// ruleIntent 描述一条待下发规则的全部语义要素。
type ruleIntent struct {
	kind intentKind

	// 位置
	family string // ip / ip6 / inet
	table  string
	chain  string

	// DNAT
	proto    string // tcp / udp
	dport    int
	dnatAddr string
	dnatPort int

	// ct mark
	mark    int64  // 具体 mark 值（DNAT / counter / iplimit）
	markSet string // mark set 引用（masquerade / 配额阻断）

	// filter
	dir      string // original / reply
	counter  string // named counter 名
	saddrFam string // ip / ip6（IP 限制 drop 的地址族）
	allowSet string // allow set 名
}

// render 把意图渲染成 nft 脚本里的一行（不含结尾换行）。
//
// ★ 这些文本就是实际下发给内核的规则，改动必须同时反映到 facts()。
func (in ruleIntent) render() string {
	switch in.kind {
	case intentDNAT:
		target := in.dnatAddr + ":" + strconv.Itoa(in.dnatPort)
		if strings.Contains(in.dnatAddr, ":") {
			target = "[" + in.dnatAddr + "]:" + strconv.Itoa(in.dnatPort) // IPv6 需方括号
		}
		// fib daddr type local 必须在最前：先确认「发给本机」，
		// 再看端口，最后打 ct mark 并 DNAT。
		return fmt.Sprintf("add rule %s %s %s fib daddr type local %s dport %d ct mark set %d dnat to %s",
			in.family, in.table, in.chain, in.proto, in.dport, in.mark, target)
	case intentMasquerade:
		return fmt.Sprintf("add rule %s %s %s ct mark @%s masquerade",
			in.family, in.table, in.chain, in.markSet)
	case intentQuotaDrop:
		return fmt.Sprintf("add rule %s %s %s ct mark @%s drop",
			in.family, in.table, in.chain, in.markSet)
	case intentCounter:
		return fmt.Sprintf("add rule %s %s %s ct mark %d ct direction %s counter name %q",
			in.family, in.table, in.chain, in.mark, in.dir, in.counter)
	case intentIPLimitDrop:
		return fmt.Sprintf(
			"add rule %s %s %s ct mark %d ct direction %s ct state established %s saddr != @%s drop",
			in.family, in.table, in.chain, in.mark, in.dir, in.saddrFam, in.allowSet)
	}
	return ""
}

// facts 把意图转成与「nft -j 输出解析结果」可比的期望值。
func (in ruleIntent) facts() RuleFacts {
	f := RuleFacts{Kind: string(in.kind)}
	switch in.kind {
	case intentDNAT:
		f.FibDaddrLocal = true
		f.Proto = in.proto
		f.DPort = in.dport
		f.SetMark = in.mark
		f.HasSetMark = true
		f.DNATAddr = in.dnatAddr
		f.DNATPort = in.dnatPort
	case intentMasquerade:
		f.MarkSet = in.markSet
		f.Verdict = "masquerade"
	case intentQuotaDrop:
		f.MarkSet = in.markSet
		f.Verdict = "drop"
	case intentCounter:
		f.Mark = in.mark
		f.HasMark = true
		f.Direction = in.dir
		f.Counter = in.counter
	case intentIPLimitDrop:
		f.Mark = in.mark
		f.HasMark = true
		f.Direction = in.dir
		f.CtState = "established"
		f.SAddrFamily = in.saddrFam
		f.SAddrNotInSet = in.allowSet
		f.Verdict = "drop"
	}
	return f
}

// ---- 意图构建 ----

// chainRef 唯一标识一条链。
type chainRef struct {
	family string
	table  string
	chain  string
}

func (c chainRef) key() string { return ObjKey(c.family, c.table, c.chain) }

// natIntents 返回某族 NAT 表 prerouting / postrouting 的规则意图（按下发顺序）。
func natIntents(family, table string, targets []dnatTarget) (pre, post []ruleIntent) {
	if len(targets) == 0 {
		return nil, nil
	}
	preChain := ChainPrerouting(table)
	postChain := ChainPostrouting(table)
	for _, t := range targets {
		for _, p := range ruleProtos(t.rule) {
			pre = append(pre, ruleIntent{
				kind: intentDNAT, family: family, table: table, chain: preChain,
				proto: p, dport: t.rule.ListenPort, mark: t.rule.ID,
				dnatAddr: t.addr, dnatPort: t.rule.TargetPort,
			})
		}
	}
	post = append(post, ruleIntent{
		kind: intentMasquerade, family: family, table: table, chain: postChain,
		markSet: MarksSet(table),
	})
	return pre, post
}

// filterIntents 返回 filter forward 链的规则意图（按下发顺序）。
//
// 顺序有语义：配额阻断必须排在最前，否则被阻断的流量会先被 counter 计入，
// 用量会继续虚增。因此比较时必须**按序**比较，不能只比集合。
func filterIntents(g *GenInput) []ruleIntent {
	all := g.enabledRules()
	if len(all) == 0 {
		return nil
	}
	fwd := ChainForward()
	out := []ruleIntent{{
		kind: intentQuotaDrop, family: "inet", table: TableFilter, chain: fwd,
		markSet: SetQuotaBlock,
	}}
	for _, r := range all {
		out = append(out,
			ruleIntent{kind: intentCounter, family: "inet", table: TableFilter, chain: fwd,
				mark: r.ID, dir: "original", counter: CounterUp(r.ID)},
			ruleIntent{kind: intentCounter, family: "inet", table: TableFilter, chain: fwd,
				mark: r.ID, dir: "reply", counter: CounterDown(r.ID)},
		)
		if st := g.stateOf(r.ID); st != nil && st.IPLimitEnabled {
			// ★ 必须限定 ct direction original：FORWARD 链同时看到往返两个方向，
			// reply 方向的 saddr 是后端目标地址，永远不在客户端 allow set 里 ——
			// 不限定方向会把返回包全部 drop，启用 IP 限制等于切断转发。
			// 只 drop「已建立 + original 方向 + 源不在 allow set」的包；
			// SYN（ct state new）放行，这样 conntrack 才能看到候选 IP。
			out = append(out,
				ruleIntent{kind: intentIPLimitDrop, family: "inet", table: TableFilter, chain: fwd,
					mark: r.ID, dir: "original", saddrFam: "ip", allowSet: AllowSetV4(r.ID)},
				ruleIntent{kind: intentIPLimitDrop, family: "inet", table: TableFilter, chain: fwd,
					mark: r.ID, dir: "original", saddrFam: "ip6", allowSet: AllowSetV6(r.ID)},
			)
		}
	}
	return out
}

// buildIntents 返回全部自有链的期望规则序列（键为 chainRef.key()）。
func buildIntents(g *GenInput) map[string][]ruleIntent {
	v4, v6 := g.families()
	out := map[string][]ruleIntent{}

	add := func(cr chainRef, list []ruleIntent) {
		if len(list) == 0 {
			return
		}
		out[cr.key()] = list
	}

	pre4, post4 := natIntents("ip", TableNAT4, v4)
	add(chainRef{"ip", TableNAT4, ChainPrerouting(TableNAT4)}, pre4)
	add(chainRef{"ip", TableNAT4, ChainPostrouting(TableNAT4)}, post4)

	pre6, post6 := natIntents("ip6", TableNAT6, v6)
	add(chainRef{"ip6", TableNAT6, ChainPrerouting(TableNAT6)}, pre6)
	add(chainRef{"ip6", TableNAT6, ChainPostrouting(TableNAT6)}, post6)

	add(chainRef{"inet", TableFilter, ChainForward()}, filterIntents(g))
	return out
}

// DesiredRuleSigs 返回每条自有链的期望规则签名序列（按下发顺序）。
//
// 键为 "family/table/chain"，与 State.ChainRuleSigs 同构，可直接逐项比较。
func DesiredRuleSigs(g *GenInput) map[string][]string {
	intents := buildIntents(g)
	out := make(map[string][]string, len(intents))
	for k, list := range intents {
		sigs := make([]string, 0, len(list))
		for _, in := range list {
			sigs = append(sigs, in.facts().Sig())
		}
		out[k] = sigs
	}
	return out
}

// DesiredChainAttrs 返回每条自有链的期望属性（type/hook/priority/policy）。
func DesiredChainAttrs(g *GenInput) map[string]ChainAttrs {
	out := map[string]ChainAttrs{}
	all := g.enabledRules()
	v4, v6 := g.families()

	if len(all) > 0 {
		out[ObjKey("inet", TableFilter, ChainForward())] = ChainAttrs{
			Type: "filter", Hook: "forward", Priority: 0, Policy: "accept",
		}
	}
	natAttrs := func(family, table string, targets []dnatTarget) {
		if len(targets) == 0 {
			return
		}
		out[ObjKey(family, table, ChainPrerouting(table))] = ChainAttrs{
			Type: "nat", Hook: "prerouting", Priority: -100, Policy: "accept",
		}
		out[ObjKey(family, table, ChainPostrouting(table))] = ChainAttrs{
			Type: "nat", Hook: "postrouting", Priority: 100, Policy: "accept",
		}
	}
	natAttrs("ip", TableNAT4, v4)
	natAttrs("ip6", TableNAT6, v6)
	return out
}

// sortedChainKeys 返回稳定顺序的链键（日志/测试用）。
func sortedChainKeys(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
