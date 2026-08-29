package nft

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// State 是从 nft 读回的自有对象现状（增量同步的基准）。
type State struct {
	FilterTableExists bool
	NAT4TableExists   bool
	NAT6TableExists   bool
	Counters          []string            // nff_filter 表内 named counter
	Sets              []string            // nff_filter 表内 set 名
	SetElements       map[string][]string // set 名 -> 元素（仅 nff_filter 表）
	QuotaBlocked      []int64             // qblock set 里的规则 ID
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

// nft -j list ruleset 的最小结构（只取本程序需要的部分）。
type rulesetDoc struct {
	Nftables []struct {
		Table *struct {
			Family string `json:"family"`
			Name   string `json:"name"`
		} `json:"table"`
		Counter *struct {
			Family string `json:"family"`
			Table  string `json:"table"`
			Name   string `json:"name"`
		} `json:"counter"`
		Set *struct {
			Family string `json:"family"`
			Table  string `json:"table"`
			Name   string `json:"name"`
			Elem   []any  `json:"elem"`
		} `json:"set"`
	} `json:"nftables"`
}

// ReadState 读取本程序自有对象现状。
//
// 用 `nft -j list ruleset` 一次读全（自有表可能尚不存在，逐表 list 会报错）。
// 只解析 nff_* 表的内容，其它表一律忽略 —— 绝不基于系统其它表做任何决策。
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
	st := &State{SetElements: map[string][]string{}}
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
		case item.Counter != nil && item.Counter.Table == TableFilter:
			st.Counters = append(st.Counters, item.Counter.Name)
		case item.Set != nil && item.Set.Table == TableFilter:
			st.Sets = append(st.Sets, item.Set.Name)
			elems := flattenElems(item.Set.Elem)
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
