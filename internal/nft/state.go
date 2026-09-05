package nft

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// State 是从 nft 读回的自有对象现状（增量同步与自愈判定的基准）。
//
// 只解析 nff_* 自有对象，其它表一律忽略 —— 绝不基于系统其它表做任何决策。
type State struct {
	FilterTableExists bool
	NAT4TableExists   bool
	NAT6TableExists   bool
	Counters          []string            // nff_filter 表内 named counter
	Sets              []string            // nff_filter 表内 set 名
	SetElements       map[string][]string // nff_filter set 名 -> 元素
	QuotaBlocked      []int64             // qblock set 里的规则 ID

	// Chains 是自有链的存在性，键为 "family/table/chain"。
	// nil 表示「本 State 未包含链信息」（例如旧测试夹具），此时自愈检查跳过该维度。
	Chains map[string]bool

	// RuleCounts 是自有链内的规则条数，键同 Chains。
	// 用途：检测「表/链/set/counter 都在，但链内规则被 nft delete rule 删掉」
	// 这种结构签名无法察觉的漂移。nil 时跳过该维度。
	RuleCounts map[string]int

	// TableSets 是所有自有表内的 set 名，键为 "family/table"。nil 时跳过。
	// 与 Sets 的区别：Sets 只含 inet nff_filter，这里含 NAT 表的 marks set。
	TableSets map[string][]string

	// CounterBytes 是 nff_filter 表内每个 named counter 的当前字节读数。
	//
	// 用途：配额实时判定。policy 每轮本就要执行一次 `nft -j list ruleset`，
	// 顺带取出 counter 读数即可算出「尚未落库的增量」，无需额外
	// `nft list counters` 系统调用（那会与 collector 的采集重复）。
	CounterBytes map[string]int64
}

// Existing 视图（供 GenStructScript 清理遗留对象）。
func (s *State) Existing() *Existing {
	if s == nil {
		return nil
	}
	return &Existing{
		FilterTableExists: s.FilterTableExists,
		NAT4TableExists:   s.NAT4TableExists,
		NAT6TableExists:   s.NAT6TableExists,
		Counters:          s.Counters,
		Sets:              s.Sets,
	}
}

// ElementsOf 返回某 set 当前元素（不存在返回 nil）。
func (s *State) ElementsOf(set string) []string {
	if s == nil || s.SetElements == nil {
		return nil
	}
	return s.SetElements[set]
}

// ObjKey 拼出 "family/table/name" 形式的对象键。
func ObjKey(family, table, name string) string { return family + "/" + table + "/" + name }

// tableKey 拼出 "family/table"。
func tableKey(family, table string) string { return family + "/" + table }

// HasChain 报告某链是否存在。State 未携带链信息（Chains==nil）时返回 true
// —— 「未知」不等于「缺失」，避免夹具/降级读取导致无意义的反复重建。
func (s *State) HasChain(family, table, chain string) bool {
	if s == nil || s.Chains == nil {
		return true
	}
	return s.Chains[ObjKey(family, table, chain)]
}

// ChainRuleCount 返回某链内规则条数与该信息是否可用。
func (s *State) ChainRuleCount(family, table, chain string) (int, bool) {
	if s == nil || s.RuleCounts == nil {
		return 0, false
	}
	return s.RuleCounts[ObjKey(family, table, chain)], true
}

// HasTableSet 报告某表内是否存在指定 set。TableSets 未提供时返回 true。
func (s *State) HasTableSet(family, table, set string) bool {
	if s == nil || s.TableSets == nil {
		return true
	}
	for _, name := range s.TableSets[tableKey(family, table)] {
		if name == set {
			return true
		}
	}
	return false
}

// nft -j list ruleset 的最小结构（只取本程序需要的部分）。
type rulesetDoc struct {
	Nftables []struct {
		Table *struct {
			Family string `json:"family"`
			Name   string `json:"name"`
		} `json:"table"`
		Chain *struct {
			Family string `json:"family"`
			Table  string `json:"table"`
			Name   string `json:"name"`
		} `json:"chain"`
		Rule *struct {
			Family string `json:"family"`
			Table  string `json:"table"`
			Chain  string `json:"chain"`
		} `json:"rule"`
		Counter *struct {
			Family string `json:"family"`
			Table  string `json:"table"`
			Name   string `json:"name"`
			Bytes  int64  `json:"bytes"`
		} `json:"counter"`
		Set *struct {
			Family string `json:"family"`
			Table  string `json:"table"`
			Name   string `json:"name"`
			Elem   []any  `json:"elem"`
		} `json:"set"`
	} `json:"nftables"`
}

// ownedTable 报告表名是否属于本程序。
func ownedTable(name string) bool {
	switch name {
	case TableNAT4, TableNAT6, TableFilter:
		return true
	}
	return false
}

// ReadState 读取本程序自有对象现状。
//
// 用 `nft -j list ruleset` 一次读全（自有表可能尚不存在，逐表 list 会报错）。
// 只解析 nff_* 表的内容，其它表一律忽略。
func ReadState(ctx context.Context, runner Runner) (*State, error) {
	if runner == nil {
		runner = ExecRunner{}
	}
	rc, out, stderr, err := runner.Run(ctx, "nft", "-j", "list", "ruleset")
	if err != nil {
		return nil, fmt.Errorf("读取 nft 状态失败: %w", err)
	}
	if rc != 0 {
		return nil, fmt.Errorf("读取 nft 状态失败: %s", strings.TrimSpace(stderr))
	}
	return ParseState(out)
}

// ParseState 解析 `nft -j list ruleset` 输出。
func ParseState(jsonOut string) (*State, error) {
	st := &State{
		SetElements:  map[string][]string{},
		Chains:       map[string]bool{},
		RuleCounts:   map[string]int{},
		TableSets:    map[string][]string{},
		CounterBytes: map[string]int64{},
	}
	if strings.TrimSpace(jsonOut) == "" {
		return st, nil
	}
	var doc rulesetDoc
	if err := json.Unmarshal([]byte(jsonOut), &doc); err != nil {
		return nil, fmt.Errorf("nft JSON 解析失败: %w", err)
	}
	for _, item := range doc.Nftables {
		switch {
		case item.Table != nil:
			switch item.Table.Name {
			case TableFilter:
				st.FilterTableExists = true
			case TableNAT4:
				st.NAT4TableExists = true
			case TableNAT6:
				st.NAT6TableExists = true
			}
		case item.Chain != nil && ownedTable(item.Chain.Table):
			st.Chains[ObjKey(item.Chain.Family, item.Chain.Table, item.Chain.Name)] = true
		case item.Rule != nil && ownedTable(item.Rule.Table):
			st.RuleCounts[ObjKey(item.Rule.Family, item.Rule.Table, item.Rule.Chain)]++
		case item.Counter != nil && item.Counter.Table == TableFilter:
			st.Counters = append(st.Counters, item.Counter.Name)
			st.CounterBytes[item.Counter.Name] = item.Counter.Bytes
		case item.Set != nil && ownedTable(item.Set.Table):
			k := tableKey(item.Set.Family, item.Set.Table)
			st.TableSets[k] = append(st.TableSets[k], item.Set.Name)
			elems := flattenElems(item.Set.Elem)
			if item.Set.Table != TableFilter {
				continue
			}
			st.Sets = append(st.Sets, item.Set.Name)
			st.SetElements[item.Set.Name] = elems
			if item.Set.Name == SetQuotaBlock {
				for _, e := range elems {
					if id, err := strconv.ParseInt(e, 10, 64); err == nil {
						st.QuotaBlocked = append(st.QuotaBlocked, id)
					}
				}
			}
		}
	}
	return st, nil
}

// flattenElems 把 nft JSON 的元素数组转成字符串切片。
// 元素可能是裸值（"1.2.3.4"、数字）或带修饰的对象（{"elem":{"val":...}}）。
func flattenElems(raw []any) []string {
	var out []string
	for _, e := range raw {
		if s := elemToString(e); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func elemToString(e any) string {
	switch v := e.(type) {
	case string:
		return v
	case float64:
		return strconv.FormatInt(int64(v), 10)
	case json.Number:
		return v.String()
	case map[string]any:
		// {"elem": {"val": X, ...}} 或 {"prefix": {...}} 等。
		if inner, ok := v["elem"]; ok {
			if m, ok := inner.(map[string]any); ok {
				if val, ok := m["val"]; ok {
					return elemToString(val)
				}
			}
			return elemToString(inner)
		}
		if val, ok := v["val"]; ok {
			return elemToString(val)
		}
	}
	return ""
}
