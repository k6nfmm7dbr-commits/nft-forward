package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/k6nfmm7dbr-commits/nft-forward/internal/nft"
)

// fakeNFT 是一个**最小 nftables 模拟器**，只理解本项目生成的脚本语法。
//
// ★ v0.3.2 起它走「真 JSON」路线：
//
//	execScript()  把下发的文本脚本解析成内部对象模型（含每条规则的 expr）
//	snapshot()    把内部模型序列化成 `nft -j list ruleset` 形态的 JSON
//	readState()   调用**生产代码** nft.ParseState 解析那段 JSON
//
// 这样一来 parseRuleFacts / ChainRuleSigs / ChainAttrs 全部由生产代码产生，
// 测试才真正验证了「内容漂移检测」，而不是测试自己写的一套影子解析。
// 篡改测试也更贴近现实：直接改内部模型里的 expr（等价于 `nft replace rule`）。
type fakeNFT struct {
	mu sync.Mutex

	// tables 是存在的表，键 "family/table"。
	tables map[string]bool
	// chains 是存在的链，键 "family/table/chain" → 属性。
	chains map[string]nft.ChainAttrs
	// chainExprs 是链内规则的 expr 数组序列（保持顺序），键同 chains。
	chainExprs map[string][][]any
	// sets 是存在的 set，键 "family/table/set"。
	sets map[string]bool
	// setElems 是 set 元素，键同 sets。
	setElems map[string]map[string]bool
	// counters 是 named counter 的字节值，键 "family/table/counter"。
	counters map[string]int64

	// scripts 记录每次应用的脚本（断言用）。
	scripts []string
	// applyErr 非 nil 时所有 apply 直接失败（故障注入）。
	applyErr error
	// applyErrOnce 非 nil 时只让下一次 apply 失败。
	applyErrOnce error
}

func newFakeNFT() *fakeNFT {
	return &fakeNFT{
		tables:     map[string]bool{},
		chains:     map[string]nft.ChainAttrs{},
		chainExprs: map[string][][]any{},
		sets:       map[string]bool{},
		setElems:   map[string]map[string]bool{},
		counters:   map[string]int64{},
	}
}

// apply 是注入给 policy 的 nftApply。
func (f *fakeNFT) apply(_ context.Context, _ nft.Runner, _ string, script string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.applyErrOnce != nil {
		err := f.applyErrOnce
		f.applyErrOnce = nil
		return err
	}
	if f.applyErr != nil {
		return f.applyErr
	}
	f.scripts = append(f.scripts, script)
	f.execScript(script)
	return nil
}

// readState 是注入给 policy 的 nftReadState：走生产解析器。
func (f *fakeNFT) readState(_ context.Context, _ nft.Runner) (*nft.State, error) {
	f.mu.Lock()
	js := f.renderJSON()
	f.mu.Unlock()
	return nft.ParseState(js)
}

// renderJSON 把内部模型序列化成 nft -j list ruleset 形态（调用方持锁）。
func (f *fakeNFT) renderJSON() string {
	items := []any{
		map[string]any{"metainfo": map[string]any{"version": "1.1.3", "json_schema_version": 1}},
	}
	for _, key := range sortedKeys(f.tables) {
		family, table := splitKey2(key)
		items = append(items, map[string]any{
			"table": map[string]any{"family": family, "name": table},
		})
	}
	chainKeys := make([]string, 0, len(f.chains))
	for k := range f.chains {
		chainKeys = append(chainKeys, k)
	}
	sort.Strings(chainKeys)
	for _, key := range chainKeys {
		family, table, name := splitKey3(key)
		a := f.chains[key]
		items = append(items, map[string]any{
			"chain": map[string]any{
				"family": family, "table": table, "name": name,
				"type": a.Type, "hook": a.Hook, "prio": float64(a.Priority), "policy": a.Policy,
			},
		})
	}
	for _, key := range sortedKeys(f.sets) {
		family, table, name := splitKey3(key)
		elems := make([]any, 0, len(f.setElems[key]))
		for _, e := range sortedStrSet(f.setElems[key]) {
			if n, err := strconv.ParseFloat(e, 64); err == nil {
				elems = append(elems, n)
			} else {
				elems = append(elems, e)
			}
		}
		items = append(items, map[string]any{
			"set": map[string]any{"family": family, "table": table, "name": name, "elem": elems},
		})
	}
	counterKeys := make([]string, 0, len(f.counters))
	for k := range f.counters {
		counterKeys = append(counterKeys, k)
	}
	sort.Strings(counterKeys)
	for _, key := range counterKeys {
		family, table, name := splitKey3(key)
		items = append(items, map[string]any{
			"counter": map[string]any{
				"family": family, "table": table, "name": name,
				"bytes": float64(f.counters[key]), "packets": float64(0),
			},
		})
	}
	for _, key := range chainKeys {
		family, table, chain := splitKey3(key)
		for _, expr := range f.chainExprs[key] {
			items = append(items, map[string]any{
				"rule": map[string]any{
					"family": family, "table": table, "chain": chain, "expr": expr,
				},
			})
		}
	}
	b, err := json.Marshal(map[string]any{"nftables": items})
	if err != nil {
		panic("fakeNFT 序列化失败: " + err.Error())
	}
	return string(b)
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k, v := range m {
		if v {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func sortedStrSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func splitKey2(k string) (family, table string) {
	parts := strings.SplitN(k, "/", 2)
	if len(parts) != 2 {
		return "", ""
	}
	return parts[0], parts[1]
}

func splitKey3(k string) (family, table, name string) {
	parts := strings.SplitN(k, "/", 3)
	if len(parts) != 3 {
		return "", "", ""
	}
	return parts[0], parts[1], parts[2]
}

// ---- 脚本解析：文本 → 内部对象模型 ----

// execScript 解析并执行脚本（只支持本项目生成的语法子集）。
//
// 脚本形如：
//
//	table ip nff_nat4 {
//	    set nff_nat4_marks { type mark }
//	    chain nff_nat4_prerouting { type nat hook prerouting priority dstnat; policy accept; }
//	}
//	flush chain ip nff_nat4 nff_nat4_prerouting
//	add rule ip nff_nat4 nff_nat4_prerouting fib daddr type local tcp dport 20000 ct mark set 1 dnat to 1.2.3.4:80
//
// 必须跟踪花括号深度：table 块内还嵌套 set / chain 块，只看 "}" 会误判
// table 块提前结束（曾导致 chain/set 全部识别不出来）。
func (f *fakeNFT) execScript(script string) {
	var curFamily, curTable string
	depth := 0
	for _, raw := range strings.Split(script, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if depth > 0 {
			switch {
			case line == "}":
				depth--
				if depth == 0 {
					curFamily, curTable = "", ""
				}
			case strings.HasSuffix(line, "{"):
				if depth == 1 {
					f.execInTable(curFamily, curTable, line)
				}
				depth++
			}
			continue
		}
		switch {
		case strings.HasPrefix(line, "table "):
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				curFamily, curTable = fields[1], fields[2]
				f.tables[curFamily+"/"+curTable] = true
				if strings.HasSuffix(line, "{") {
					depth = 1
				}
			}
		case strings.HasPrefix(line, "flush chain "):
			fields := strings.Fields(line)
			if len(fields) >= 5 {
				f.chainExprs[fields[2]+"/"+fields[3]+"/"+fields[4]] = nil
			}
		case strings.HasPrefix(line, "flush set "):
			fields := strings.Fields(line)
			if len(fields) >= 5 {
				f.setElems[fields[2]+"/"+fields[3]+"/"+fields[4]] = map[string]bool{}
			}
		case strings.HasPrefix(line, "add rule "):
			f.addRule(line)
		case strings.HasPrefix(line, "add element "):
			f.elementOp(line, true)
		case strings.HasPrefix(line, "delete element "):
			f.elementOp(line, false)
		case strings.HasPrefix(line, "delete counter "):
			fields := strings.Fields(line)
			if len(fields) >= 5 {
				delete(f.counters, fields[2]+"/"+fields[3]+"/"+fields[4])
			}
		case strings.HasPrefix(line, "delete set "):
			fields := strings.Fields(line)
			if len(fields) >= 5 {
				key := fields[2] + "/" + fields[3] + "/" + fields[4]
				delete(f.sets, key)
				delete(f.setElems, key)
			}
		}
	}
}

// execInTable 处理 `table ... {` 块内的声明行（set / counter / chain）。
func (f *fakeNFT) execInTable(family, table, line string) {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return
	}
	key := family + "/" + table + "/" + fields[1]
	switch fields[0] {
	case "set":
		if !f.sets[key] {
			f.sets[key] = true
			f.setElems[key] = map[string]bool{}
		}
	case "counter":
		if _, ok := f.counters[key]; !ok {
			f.counters[key] = 0 // 幂等声明：已存在则保留累计值
		}
	case "chain":
		if _, ok := f.chains[key]; !ok {
			f.chains[key] = chainAttrsFor(table, fields[1])
			f.chainExprs[key] = nil
		}
	}
}

// chainAttrsFor 按链名推断本项目声明的链属性。
//
// 脚本里的属性写在 chain 块的下一行（`type nat hook prerouting priority dstnat;`），
// 模拟器不解析那一行，改为按链名映射 —— 值与 nft 对 dstnat/srcnat/filter
// 这三个优先级别名的实际解析结果一致（-100 / 100 / 0）。
func chainAttrsFor(table, chain string) nft.ChainAttrs {
	switch {
	case strings.HasSuffix(chain, "_prerouting"):
		return nft.ChainAttrs{Type: "nat", Hook: "prerouting", Priority: -100, Policy: "accept"}
	case strings.HasSuffix(chain, "_postrouting"):
		return nft.ChainAttrs{Type: "nat", Hook: "postrouting", Priority: 100, Policy: "accept"}
	case strings.HasSuffix(chain, "_forward"):
		return nft.ChainAttrs{Type: "filter", Hook: "forward", Priority: 0, Policy: "accept"}
	}
	return nft.ChainAttrs{}
}

// addRule 把一行 `add rule <family> <table> <chain> <expr...>` 转成 expr 数组。
func (f *fakeNFT) addRule(line string) {
	fields := strings.Fields(line)
	if len(fields) < 5 {
		return
	}
	key := fields[2] + "/" + fields[3] + "/" + fields[4]
	expr := parseNftRuleText(strings.Join(fields[5:], " "))
	f.chainExprs[key] = append(f.chainExprs[key], expr)
}

// parseNftRuleText 把本项目生成的规则文本转成 nft JSON expr 数组。
//
// 只支持本项目实际生成的表达式；遇到未知 token 会 panic，
// 这是刻意的：脚本新增了模拟器不认识的语法时必须立刻暴露，
// 而不是静默产生一个「看起来正确」的 expr。
func parseNftRuleText(s string) []any {
	toks := strings.Fields(s)
	var out []any
	i := 0
	num := func(v string) float64 {
		n, err := strconv.Atoi(v)
		if err != nil {
			panic("fakeNFT: 非法数字 " + v)
		}
		return float64(n)
	}
	match := func(left any, op string, right any) map[string]any {
		return map[string]any{"match": map[string]any{"op": op, "left": left, "right": right}}
	}
	for i < len(toks) {
		switch {
		case i+4 < len(toks) && toks[i] == "fib" && toks[i+1] == "daddr" &&
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
			right := any(nil)
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
			addr, port := splitDNATTarget(toks[i+2])
			out = append(out, map[string]any{"dnat": map[string]any{
				"addr": addr, "port": float64(port),
			}})
			i += 3
		case toks[i] == "masquerade":
			out = append(out, map[string]any{"masquerade": nil})
			i++
		case toks[i] == "drop":
			out = append(out, map[string]any{"drop": nil})
			i++
		case toks[i] == "accept":
			out = append(out, map[string]any{"accept": nil})
			i++
		default:
			panic("fakeNFT: 未识别的规则 token " + toks[i] + " （完整规则: " + s + "）")
		}
	}
	return out
}

// splitDNATTarget 拆分 "1.2.3.4:80" 或 "[2001:db8::1]:443"。
func splitDNATTarget(t string) (string, int) {
	if strings.HasPrefix(t, "[") {
		end := strings.LastIndex(t, "]:")
		if end < 0 {
			panic("fakeNFT: 非法 IPv6 DNAT 目标 " + t)
		}
		p, err := strconv.Atoi(t[end+2:])
		if err != nil {
			panic("fakeNFT: 非法 DNAT 端口 " + t)
		}
		return t[1:end], p
	}
	idx := strings.LastIndex(t, ":")
	if idx < 0 {
		panic("fakeNFT: 非法 DNAT 目标 " + t)
	}
	p, err := strconv.Atoi(t[idx+1:])
	if err != nil {
		panic("fakeNFT: 非法 DNAT 端口 " + t)
	}
	return t[:idx], p
}

// elementOp 处理 add/delete element。
func (f *fakeNFT) elementOp(line string, add bool) {
	open := strings.Index(line, "{")
	closeIdx := strings.LastIndex(line, "}")
	if open < 0 || closeIdx < open {
		return
	}
	head := strings.Fields(line[:open])
	if len(head) < 5 {
		return
	}
	key := head[2] + "/" + head[3] + "/" + head[4]
	if f.setElems[key] == nil {
		f.setElems[key] = map[string]bool{}
	}
	for _, e := range strings.Split(line[open+1:closeIdx], ",") {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if add {
			f.setElems[key][e] = true
		} else {
			delete(f.setElems[key], e)
		}
	}
}

// ---- 测试辅助：故障注入与断言 ----

// bumpCounter 模拟真实流量：给某 counter 加字节。
func (f *fakeNFT) bumpCounter(name string, delta int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.counters["inet/"+nft.TableFilter+"/"+name] += delta
}

// counterOf 读取 counter 当前值（-1 表示不存在）。
func (f *fakeNFT) counterOf(name string) int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.counters["inet/"+nft.TableFilter+"/"+name]
	if !ok {
		return -1
	}
	return v
}

// dropTable 人为删除一张表（连带其内部对象），模拟 `nft delete table ...`。
func (f *fakeNFT) dropTable(family, table string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.tables, family+"/"+table)
	prefix := family + "/" + table + "/"
	for k := range f.chains {
		if strings.HasPrefix(k, prefix) {
			delete(f.chains, k)
			delete(f.chainExprs, k)
		}
	}
	for k := range f.sets {
		if strings.HasPrefix(k, prefix) {
			delete(f.sets, k)
			delete(f.setElems, k)
		}
	}
	for k := range f.counters {
		if strings.HasPrefix(k, prefix) {
			delete(f.counters, k)
		}
	}
}

// dropChain 人为删除一条链。
func (f *fakeNFT) dropChain(family, table, chain string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := family + "/" + table + "/" + chain
	delete(f.chains, key)
	delete(f.chainExprs, key)
}

// dropCounter 人为删除一个 named counter。
func (f *fakeNFT) dropCounter(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.counters, "inet/"+nft.TableFilter+"/"+name)
}

// dropSet 人为删除 filter 表里的一个 set。
func (f *fakeNFT) dropSet(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := "inet/" + nft.TableFilter + "/" + name
	delete(f.sets, key)
	delete(f.setElems, key)
}

// flushChainRules 人为清空某链的规则（对象都在，规则没了）。
func (f *fakeNFT) flushChainRules(family, table, chain string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.chainExprs[family+"/"+table+"/"+chain] = nil
}

// setChainAttrs 人为改动链属性（模拟 hook / priority / policy 被换掉）。
func (f *fakeNFT) setChainAttrs(family, table, chain string, a nft.ChainAttrs) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.chains[family+"/"+table+"/"+chain] = a
}

// rulesOf 返回某链的 expr 序列副本（篡改测试用）。
func (f *fakeNFT) rulesOf(family, table, chain string) [][]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	src := f.chainExprs[family+"/"+table+"/"+chain]
	out := make([][]any, len(src))
	copy(out, src)
	return out
}

// replaceRule 用新 expr 替换某链第 idx 条规则（模拟 `nft replace rule`）。
//
// 这是「等数量篡改」的核心手法：规则条数不变、对象都在，只有内容变了。
func (f *fakeNFT) replaceRule(family, table, chain string, idx int, expr []any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := family + "/" + table + "/" + chain
	if idx < 0 || idx >= len(f.chainExprs[key]) {
		panic(fmt.Sprintf("fakeNFT: replaceRule 索引越界 %d/%d", idx, len(f.chainExprs[key])))
	}
	f.chainExprs[key][idx] = expr
}

// appendRawRule 追加一条任意 expr（模拟人为插入额外规则）。
func (f *fakeNFT) appendRawRule(family, table, chain string, expr []any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := family + "/" + table + "/" + chain
	f.chainExprs[key] = append(f.chainExprs[key], expr)
}

// deleteRuleAt 删除某链第 idx 条规则。
func (f *fakeNFT) deleteRuleAt(family, table, chain string, idx int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := family + "/" + table + "/" + chain
	src := f.chainExprs[key]
	if idx < 0 || idx >= len(src) {
		panic(fmt.Sprintf("fakeNFT: deleteRuleAt 索引越界 %d/%d", idx, len(src)))
	}
	f.chainExprs[key] = append(src[:idx:idx], src[idx+1:]...)
}

// hasTable / hasChain / hasSet 断言辅助。
func (f *fakeNFT) hasTable(family, table string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tables[family+"/"+table]
}

func (f *fakeNFT) hasChain(family, table, chain string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.chains[family+"/"+table+"/"+chain]
	return ok
}

func (f *fakeNFT) hasSet(family, table, set string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.sets[family+"/"+table+"/"+set]
}

func (f *fakeNFT) ruleCount(family, table, chain string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.chainExprs[family+"/"+table+"/"+chain])
}

func (f *fakeNFT) elementsOf(family, table, set string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for e := range f.setElems[family+"/"+table+"/"+set] {
		out = append(out, e)
	}
	sort.Strings(out)
	return out
}

// resetScripts 清空脚本记录。
func (f *fakeNFT) resetScripts() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.scripts = nil
}

// failNextApply 让下一次 apply 失败（原子性故障注入）。
func (f *fakeNFT) failNextApply(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.applyErrOnce = err
}

// structRebuilds 统计结构重建次数（含 flush chain 的脚本）。
func (f *fakeNFT) structRebuilds() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, s := range f.scripts {
		if strings.Contains(s, "flush chain") {
			n++
		}
	}
	return n
}

// elementOps 统计纯元素脚本次数。
func (f *fakeNFT) elementOps() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, s := range f.scripts {
		if strings.Contains(s, "element") && !strings.Contains(s, "flush chain") {
			n++
		}
	}
	return n
}

// scriptCount 返回本轮记录的脚本数。
func (f *fakeNFT) scriptCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.scripts)
}

// allScripts 返回脚本副本。
func (f *fakeNFT) allScripts() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string{}, f.scripts...)
}
