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
