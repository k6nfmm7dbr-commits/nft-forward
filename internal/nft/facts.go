package nft

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// ---- RuleFacts：从 nft -j 规则表达式里提取的「本程序关心的事实」 ----
//
// 设计原则：
//
//  1. **不做整串文本比较**。nft 版本、handle 编号、表达式书写顺序都会让完整
//     字符串比较变得极其脆弱（升级 nft 就全量重建，counter 反复清零）。
//  2. **只提取决定数据面行为的字段**，其余（handle、comment、counter 的
//     packets/bytes 实时读数）一律忽略 —— 否则每次有流量都会触发 rebuild。
//  3. 提取结果生成 canonical signature，与 DesiredRuleSigs 逐项比较。
//
// 覆盖字段：协议、监听端口、DNAT 目标地址与端口、ct mark（set/match）、
// mark set 引用、ct direction、ct state、named counter 引用、
// 源地址族与 allow set 引用、verdict（drop / masquerade）、fib daddr local。

// RuleFacts 是一条规则的结构化事实。
type RuleFacts struct {
	// Kind 是规则类别（与 intentKind 同值）。空串表示无法归类。
	Kind string

	FibDaddrLocal bool   // 是否带 fib daddr type local
	Proto         string // payload 协议（tcp/udp）
	DPort         int    // 目的端口匹配值
	HasSetMark    bool   // 是否有 ct mark set
	SetMark       int64  // ct mark set 的值
	HasMark       bool   // 是否有 ct mark == N 匹配
	Mark          int64  // ct mark 匹配值
	MarkSet       string // ct mark @set 引用（不含 @）
	Direction     string // ct direction 匹配值
	CtState       string // ct state 匹配值
	Counter       string // counter name 引用
	SAddrFamily   string // 源地址匹配的族（ip / ip6）
	SAddrNotInSet string // saddr != @set 的 set 名（不含 @）
	DNATAddr      string // dnat 目标地址
	DNATPort      int    // dnat 目标端口
	Verdict       string // drop / accept / masquerade / …

	// Unknown 记录无法识别的表达式类型（按字典序）。
	//
	// 为什么要记：人为插入的额外表达式（例如给 DNAT 规则加个 limit）必须被
	// 察觉。忽略未知表达式等于给攻击者留一条「加料不被发现」的路。
	Unknown []string
}

// Sig 返回 canonical signature。字段顺序固定，因此可直接字符串比较。
func (f RuleFacts) Sig() string {
	var b strings.Builder
	b.WriteString("k=" + f.Kind)
	if f.FibDaddrLocal {
		b.WriteString("|fib=local")
	}
	if f.Proto != "" {
		b.WriteString("|proto=" + f.Proto)
	}
	if f.DPort != 0 {
		b.WriteString("|dport=" + strconv.Itoa(f.DPort))
	}
	if f.HasSetMark {
		b.WriteString("|setmark=" + strconv.FormatInt(f.SetMark, 10))
	}
	if f.HasMark {
		b.WriteString("|mark=" + strconv.FormatInt(f.Mark, 10))
	}
	if f.MarkSet != "" {
		b.WriteString("|markset=" + f.MarkSet)
	}
	if f.Direction != "" {
		b.WriteString("|dir=" + f.Direction)
	}
	if f.CtState != "" {
		b.WriteString("|state=" + f.CtState)
	}
	if f.Counter != "" {
		b.WriteString("|counter=" + f.Counter)
	}
	if f.SAddrFamily != "" {
		b.WriteString("|saddrfam=" + f.SAddrFamily)
	}
	if f.SAddrNotInSet != "" {
		b.WriteString("|saddrnotin=" + f.SAddrNotInSet)
	}
	if f.DNATAddr != "" {
		b.WriteString("|dnat=" + f.DNATAddr + ":" + strconv.Itoa(f.DNATPort))
	}
	if f.Verdict != "" {
		b.WriteString("|verdict=" + f.Verdict)
	}
	if len(f.Unknown) > 0 {
		b.WriteString("|unknown=" + strings.Join(f.Unknown, ","))
	}
	return b.String()
}

// ChainAttrs 是链的关键属性（base chain 的挂载点决定数据面是否生效）。
type ChainAttrs struct {
	Type     string // filter / nat
	Hook     string // prerouting / postrouting / forward
	Priority int
	Policy   string // accept / drop
}

// Sig 返回 canonical signature。
func (a ChainAttrs) Sig() string {
	return fmt.Sprintf("type=%s|hook=%s|prio=%d|policy=%s", a.Type, a.Hook, a.Priority, a.Policy)
}

// ---- 从 nft JSON 表达式提取 facts ----

// parseRuleFacts 解析一条规则的 expr 数组。
func parseRuleFacts(exprs []any) RuleFacts {
	var f RuleFacts
	for _, raw := range exprs {
		m, ok := raw.(map[string]any)
		if !ok {
			f.Unknown = append(f.Unknown, "nonobject")
			continue
		}
		if len(m) != 1 {
			// nft JSON 的每个表达式恰好一个顶层键。
			f.Unknown = append(f.Unknown, "multikey")
			continue
		}
		for key, val := range m {
			switch key {
			case "match":
				parseMatch(&f, val)
			case "mangle":
				parseMangle(&f, val)
			case "dnat":
				parseDNAT(&f, val)
			case "counter":
				// {"counter":"name"} 是 named counter 引用；
				// {"counter":{...}} 是匿名 counter（本程序不生成）。
				if s, ok := val.(string); ok {
					f.Counter = s
				} else {
					f.Unknown = append(f.Unknown, "anon-counter")
				}
			case "masquerade":
				f.Verdict = "masquerade"
			case "drop":
				f.Verdict = "drop"
			case "accept":
				f.Verdict = "accept"
			case "snat", "redirect", "jump", "goto", "log", "limit", "queue", "reject":
				f.Unknown = append(f.Unknown, key)
			default:
				f.Unknown = append(f.Unknown, key)
			}
		}
	}
	sort.Strings(f.Unknown)
	f.Kind = classify(&f)
	return f
}

// parseMatch 解析 {"match":{"op":..,"left":..,"right":..}}。
func parseMatch(f *RuleFacts, val any) {
	m, ok := val.(map[string]any)
	if !ok {
		f.Unknown = append(f.Unknown, "match")
		return
	}
	op, _ := m["op"].(string)
	left := m["left"]
	right := m["right"]

	// fib daddr type local
	if lm, ok := left.(map[string]any); ok {
		if fib, ok := lm["fib"].(map[string]any); ok {
			if fib["result"] == "type" && hasFlag(fib["flags"], "daddr") &&
				op == "==" && right == "local" {
				f.FibDaddrLocal = true
				return
			}
			f.Unknown = append(f.Unknown, "fib-other")
			return
		}
		// payload：协议 + 字段
		if pl, ok := lm["payload"].(map[string]any); ok {
			proto, _ := pl["protocol"].(string)
			field, _ := pl["field"].(string)
			switch {
			case field == "dport" && op == "==":
				f.Proto = proto
				f.DPort = toInt(right)
			case field == "saddr" && op == "!=":
				f.SAddrFamily = proto
				f.SAddrNotInSet = trimSetRef(right)
			default:
				f.Unknown = append(f.Unknown, "payload-"+proto+"-"+field+"-"+op)
			}
			return
		}
		// ct：mark / direction / state
		if ct, ok := lm["ct"].(map[string]any); ok {
			ckey, _ := ct["key"].(string)
			switch ckey {
			case "mark":
				if s, isStr := right.(string); isStr && strings.HasPrefix(s, "@") {
					f.MarkSet = strings.TrimPrefix(s, "@")
				} else {
					f.HasMark = true
					f.Mark = int64(toInt(right))
				}
			case "direction":
				f.Direction, _ = right.(string)
			case "state":
				f.CtState = ctStateString(right)
			default:
				f.Unknown = append(f.Unknown, "ct-"+ckey)
			}
			return
		}
		if _, ok := lm["meta"]; ok {
			f.Unknown = append(f.Unknown, "meta")
			return
		}
	}
	f.Unknown = append(f.Unknown, "match-unknown")
}

// parseMangle 解析 {"mangle":{"key":{"ct":{"key":"mark"}},"value":N}}。
func parseMangle(f *RuleFacts, val any) {
	m, ok := val.(map[string]any)
	if !ok {
		f.Unknown = append(f.Unknown, "mangle")
		return
	}
	km, ok := m["key"].(map[string]any)
	if !ok {
		f.Unknown = append(f.Unknown, "mangle-key")
		return
	}
	ct, ok := km["ct"].(map[string]any)
	if !ok || ct["key"] != "mark" {
		f.Unknown = append(f.Unknown, "mangle-nonctmark")
		return
	}
	f.HasSetMark = true
	f.SetMark = int64(toInt(m["value"]))
}

// parseDNAT 解析 {"dnat":{"addr":"1.2.3.4","port":443}}。
func parseDNAT(f *RuleFacts, val any) {
	m, ok := val.(map[string]any)
	if !ok {
		f.Unknown = append(f.Unknown, "dnat")
		return
	}
	f.DNATAddr, _ = m["addr"].(string)
	f.DNATPort = toInt(m["port"])
	if f.DNATAddr == "" {
		f.Unknown = append(f.Unknown, "dnat-noaddr")
	}
}

// classify 按已提取的事实推断规则类别。
//
// 分类只用于让签名更可读、并让「类别本身变了」也能被察觉；
// 真正的比较依据是完整签名。
func classify(f *RuleFacts) string {
	switch {
	case f.DNATAddr != "":
		return string(intentDNAT)
	case f.Verdict == "masquerade":
		return string(intentMasquerade)
	case f.Counter != "":
		return string(intentCounter)
	case f.SAddrNotInSet != "":
		return string(intentIPLimitDrop)
	case f.MarkSet != "" && f.Verdict == "drop":
		return string(intentQuotaDrop)
	}
	return "other"
}

func hasFlag(raw any, want string) bool {
	list, ok := raw.([]any)
	if !ok {
		return false
	}
	for _, v := range list {
		if s, ok := v.(string); ok && s == want {
			return true
		}
	}
	return false
}

// ctStateString 归一化 ct state 的右值（可能是字符串或字符串数组）。
func ctStateString(raw any) string {
	switch v := raw.(type) {
	case string:
		return v
	case []any:
		parts := make([]string, 0, len(v))
		for _, e := range v {
			if s, ok := e.(string); ok {
				parts = append(parts, s)
			}
		}
		sort.Strings(parts)
		return strings.Join(parts, ",")
	}
	return ""
}

// trimSetRef 取出 "@setname" 里的 setname。
func trimSetRef(raw any) string {
	s, ok := raw.(string)
	if !ok {
		return ""
	}
	return strings.TrimPrefix(s, "@")
}

// toInt 把 nft JSON 里的数字（float64 / json.Number / string）转成 int。
func toInt(raw any) int {
	switch v := raw.(type) {
	case float64:
		return int(v)
	case int:
		return v
	case int64:
		return int(v)
	case string:
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return 0
}
