package nft

import (
	"fmt"
	"sort"
	"strings"
)

// ---- Desired State（期望对象集合）与自愈判定 ----
//
// 旧实现只检查 FilterTableExists + up counter + v4 allow set 三项，因此
// 「删掉 nff_nat4 表」「删掉 down counter」「删掉 IPv6 allow set」「删掉某条链」
// 都不会触发重建，转发会一直坏着直到结构签名恰好变化。这里改成完整的
// desired state 对比：任何一个期望对象缺失都触发一次结构重建（幂等 add +
// flush chain，counter 保留累计值）。

// ObjectKind 是期望对象的类别。
type ObjectKind string

// 期望对象类别常量。
const (
	// ObjTable 是表。
	ObjTable ObjectKind = "table"
	// ObjChain 是链。
	ObjChain ObjectKind = "chain"
	// ObjSet 是 set。
	ObjSet ObjectKind = "set"
	// ObjCounter 是 named counter。
	ObjCounter ObjectKind = "counter"
	// ObjChainRules 是「某链内至少应有 N 条规则」。
	ObjChainRules ObjectKind = "rules"
)

// Object 描述一个期望存在的 nft 自有对象。
type Object struct {
	Kind   ObjectKind
	Family string // ip / ip6 / inet
	Table  string
	Name   string // chain / set / counter 名；Kind==ObjTable 时为空
	MinN   int    // Kind==ObjChainRules 时：链内最少规则条数
}

// String 返回可读描述（只用于日志/测试断言）。
func (o Object) String() string {
	if o.Name == "" {
		return string(o.Kind) + " " + o.Family + " " + o.Table
	}
	return string(o.Kind) + " " + o.Family + " " + o.Table + " " + o.Name
}

// DesiredObjects 返回「当前规则集应该在 nft 里存在」的全部自有对象。
//
// 覆盖：
//   - 三张表 nff_nat4 / nff_nat6 / nff_filter（NAT 表只在该族有目标时才需要）；
//   - 每张 NAT 表的 prerouting / postrouting 链与 marks set；
//   - filter 表的 forward 链与 qblock set；
//   - 每条启用规则的 up / down counter（两个方向都要）；
//   - 启用 IP 限制的规则的 IPv4 + IPv6 allow set；
//   - 各链内的最小规则条数（检测「对象都在但规则被删」的漂移）。
func DesiredObjects(g *GenInput) []Object {
	v4, v6 := g.families()
	all := g.enabledRules()

	var out []Object

	// filter 表：只要有启用规则就必须存在（counter 挂在它上面）。
	if len(all) > 0 {
		out = append(out,
			Object{Kind: ObjTable, Family: "inet", Table: TableFilter},
			Object{Kind: ObjChain, Family: "inet", Table: TableFilter, Name: ChainForward()},
			Object{Kind: ObjSet, Family: "inet", Table: TableFilter, Name: SetQuotaBlock},
		)
		// forward 链规则数：1 条 qblock drop + 每规则 2 条 counter
		// （+ 启用 IP 限制时每规则再 2 条 drop）。
		minRules := 1
		for _, r := range all {
			minRules += 2
			if st := g.stateOf(r.ID); st != nil && st.IPLimitEnabled {
				minRules += 2
			}
		}
		out = append(out, Object{Kind: ObjChainRules, Family: "inet",
			Table: TableFilter, Name: ChainForward(), MinN: minRules})

		for _, r := range all {
			out = append(out,
				Object{Kind: ObjCounter, Family: "inet", Table: TableFilter, Name: CounterUp(r.ID)},
				Object{Kind: ObjCounter, Family: "inet", Table: TableFilter, Name: CounterDown(r.ID)},
			)
			if st := g.stateOf(r.ID); st != nil && st.IPLimitEnabled {
				out = append(out,
					Object{Kind: ObjSet, Family: "inet", Table: TableFilter, Name: AllowSetV4(r.ID)},
					Object{Kind: ObjSet, Family: "inet", Table: TableFilter, Name: AllowSetV6(r.ID)},
				)
			}
		}
	}

	out = append(out, natObjects("ip", TableNAT4, v4)...)
	out = append(out, natObjects("ip6", TableNAT6, v6)...)
	return out
}

// natObjects 返回某族 NAT 表的期望对象（该族无目标时返回 nil）。
func natObjects(family, table string, targets []dnatTarget) []Object {
	if len(targets) == 0 {
		return nil
	}
	pre := ChainPrerouting(table)
	post := ChainPostrouting(table)
	// prerouting：每个目标按协议展开若干条 DNAT；postrouting：1 条 masquerade。
	preRules := 0
	for _, t := range targets {
		preRules += len(ruleProtos(t.rule))
	}
	return []Object{
		{Kind: ObjTable, Family: family, Table: table},
		{Kind: ObjChain, Family: family, Table: table, Name: pre},
		{Kind: ObjChain, Family: family, Table: table, Name: post},
		{Kind: ObjSet, Family: family, Table: table, Name: MarksSet(table)},
		{Kind: ObjChainRules, Family: family, Table: table, Name: pre, MinN: preRules},
		{Kind: ObjChainRules, Family: family, Table: table, Name: post, MinN: 1},
	}
}

// MissingObjects 返回 desired 中在 cur 里缺失的对象（已排序，便于日志与测试）。
//
// cur 为 nil 时视为「什么都没有」，全部 desired 都算缺失。
func MissingObjects(cur *State, desired []Object) []Object {
	var miss []Object
	for _, o := range desired {
		if !objectPresent(cur, o) {
			miss = append(miss, o)
		}
	}
	sort.Slice(miss, func(i, j int) bool { return miss[i].String() < miss[j].String() })
	return miss
}

func objectPresent(cur *State, o Object) bool {
	if cur == nil {
		return false
	}
	switch o.Kind {
	case ObjTable:
		switch o.Table {
		case TableFilter:
			return cur.FilterTableExists
		case TableNAT4:
			return cur.NAT4TableExists
		case TableNAT6:
			return cur.NAT6TableExists
		}
		return false
	case ObjChain:
		return cur.HasChain(o.Family, o.Table, o.Name)
	case ObjSet:
		if o.Table == TableFilter {
			// filter 表的 set 有完整列表，直接判定。
			return containsStr(cur.Sets, o.Name)
		}
		return cur.HasTableSet(o.Family, o.Table, o.Name)
	case ObjCounter:
		return containsStr(cur.Counters, o.Name)
	case ObjChainRules:
		n, ok := cur.ChainRuleCount(o.Family, o.Table, o.Name)
		if !ok {
			return true // 信息不可用 → 不据此触发重建
		}
		return n >= o.MinN
	}
	return true
}

func containsStr(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// DescribeMissing 把缺失对象列表压成一行日志文本（最多列前 8 项）。
func DescribeMissing(miss []Object) string {
	if len(miss) == 0 {
		return ""
	}
	n := len(miss)
	if n > 8 {
		n = 8
	}
	parts := make([]string, 0, n)
	for _, o := range miss[:n] {
		parts = append(parts, o.String())
	}
	s := strings.Join(parts, ", ")
	if len(miss) > n {
		s += fmt.Sprintf(" …(共 %d 项)", len(miss))
	}
	return s
}

// ---- 内容校验（v0.3.2）----
//
// 只判断「对象存在 + 规则条数 >= N」会漏掉等数量篡改，例如
//
//	tcp dport 30001 dnat to 1.2.3.4:443  →  tcp dport 30001 dnat to 8.8.8.8:443
//
// 表、链、set、counter 都在，条数也没变，但数据面已被劫持。
// 因此在对象校验之上再做**内容**校验：
//
//	期望：DesiredRuleSigs / DesiredChainAttrs（由 ruleIntent 派生）
//	实际：State.ChainRuleSigs / State.ChainAttrsMap（由 nft -j 解析派生）
//
// 两侧都是 canonical signature，逐项按序比较。counter 的实时读数不参与，
// 因此有流量不会触发重建。

// Drift 描述一次 desired-state 比对的结果。
type Drift struct {
	// Missing 是缺失的对象（表/链/set/counter/规则条数不足）。
	Missing []Object
	// Content 是内容不一致的描述（每项一行，已排序）。
	Content []string
}

// Empty 报告是否完全一致。
func (d Drift) Empty() bool { return len(d.Missing) == 0 && len(d.Content) == 0 }

// Describe 返回一行可读描述（对象缺失优先，随后内容差异）。
func (d Drift) Describe() string {
	var parts []string
	if s := DescribeMissing(d.Missing); s != "" {
		parts = append(parts, s)
	}
	if len(d.Content) > 0 {
		n := len(d.Content)
		if n > 6 {
			n = 6
		}
		s := strings.Join(d.Content[:n], "; ")
		if len(d.Content) > n {
			s += fmt.Sprintf(" …(共 %d 项内容差异)", len(d.Content))
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, " | ")
}

// DetectDrift 比对期望与现状，返回全部差异。
//
// cur 为 nil 视为「什么都没有」。State 未携带某维度信息（旧夹具/降级读取）时
// 跳过该维度 —— 「未知」不等于「不一致」，否则会陷入无意义的反复重建。
func DetectDrift(g *GenInput, cur *State) Drift {
	d := Drift{Missing: MissingObjects(cur, DesiredObjects(g))}
	if cur == nil {
		return d // 全部缺失，内容比较无意义
	}

	// 链属性（type / hook / priority / policy）
	wantAttrs := DesiredChainAttrs(g)
	attrKeys := make([]string, 0, len(wantAttrs))
	for k := range wantAttrs {
		attrKeys = append(attrKeys, k)
	}
	sort.Strings(attrKeys)
	for _, k := range attrKeys {
		want := wantAttrs[k]
		got, ok := cur.ChainAttrsMap[k]
		if cur.ChainAttrsMap == nil {
			break // 信息不可用，整个维度跳过
		}
		if !ok {
			continue // 链本身缺失，已由 Missing 覆盖
		}
		if got.Sig() != want.Sig() {
			d.Content = append(d.Content,
				fmt.Sprintf("chain %s 属性不符(期望 %s 实际 %s)", k, want.Sig(), got.Sig()))
		}
	}

	// 链内规则序列
	wantSigs := DesiredRuleSigs(g)
	if cur.ChainRuleSigs != nil {
		for _, k := range sortedChainKeys(wantSigs) {
			want := wantSigs[k]
			got, ok := cur.ChainRuleSigs[k]
			if !ok {
				continue // 链缺失，Missing 已覆盖
			}
			if diff := diffSigs(want, got); diff != "" {
				d.Content = append(d.Content, fmt.Sprintf("chain %s 规则不符: %s", k, diff))
			}
		}
		// 期望里没有、但实际存在规则的自有链 —— 说明规则残留在不该有内容的链上。
		for _, k := range sortedChainKeys(cur.ChainRuleSigs) {
			if _, expected := wantSigs[k]; expected {
				continue
			}
			if n := len(cur.ChainRuleSigs[k]); n > 0 {
				d.Content = append(d.Content,
					fmt.Sprintf("chain %s 存在 %d 条不应有的规则", k, n))
			}
		}
	}
	sort.Strings(d.Content)
	return d
}

// diffSigs 比较两个签名序列，返回首个差异的可读描述（相同返回空串）。
//
// 按序比较：本程序的规则顺序有语义（配额阻断必须在 counter 之前，
// 否则被阻断流量会先被计数、用量继续虚增）。
func diffSigs(want, got []string) string {
	if len(want) != len(got) {
		return fmt.Sprintf("条数 %d→%d", len(want), len(got))
	}
	for i := range want {
		if want[i] != got[i] {
			return fmt.Sprintf("第 %d 条 期望[%s] 实际[%s]", i+1, want[i], got[i])
		}
	}
	return ""
}
