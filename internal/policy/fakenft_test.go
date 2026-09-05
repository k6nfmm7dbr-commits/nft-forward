package policy

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/k6nfmm7dbr-commits/nft-forward/internal/nft"
)

// fakeNFT 是一个**最小 nftables 模拟器**，只理解本项目生成的脚本语法。
//
// 为什么需要它：自愈判定改成完整 desired-state 比对后，手工拼出来的
// nft.State 夹具必然缺表/缺链/缺 set，每轮都会被判定「需要重建」，
// 既掩盖了真实回归，也测不出自愈行为。让测试真的「应用」脚本、
// 真的维护对象存在性与 counter 值，才能同时验证：
//
//	· 稳定期不重建结构（counter 不清零）
//	· 人为删除任一自有对象后下一轮自动恢复
//	· 元素增量不触碰链与 counter
type fakeNFT struct {
	mu sync.Mutex

	// tables 是存在的表，键 "family/table"。
	tables map[string]bool
	// chains 是存在的链，键 "family/table/chain"。
	chains map[string]bool
	// chainRules 是链内规则条数，键同 chains。
	chainRules map[string]int
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
}

func newFakeNFT() *fakeNFT {
	return &fakeNFT{
		tables:     map[string]bool{},
		chains:     map[string]bool{},
		chainRules: map[string]int{},
		sets:       map[string]bool{},
		setElems:   map[string]map[string]bool{},
		counters:   map[string]int64{},
	}
}

// apply 是注入给 policy 的 nftApply。
func (f *fakeNFT) apply(_ context.Context, _ nft.Runner, _ string, script string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.applyErr != nil {
		return f.applyErr
	}
	f.scripts = append(f.scripts, script)
	f.execScript(script)
	return nil
}

// readState 是注入给 policy 的 nftReadState。
func (f *fakeNFT) readState(_ context.Context, _ nft.Runner) (*nft.State, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.snapshot(), nil
}

// snapshot 把模拟器现状转成 nft.State（调用方持锁）。
func (f *fakeNFT) snapshot() *nft.State {
	st := &nft.State{
		SetElements:  map[string][]string{},
		Chains:       map[string]bool{},
		RuleCounts:   map[string]int{},
		TableSets:    map[string][]string{},
		CounterBytes: map[string]int64{},
	}
	st.FilterTableExists = f.tables["inet/"+nft.TableFilter]
	st.NAT4TableExists = f.tables["ip/"+nft.TableNAT4]
	st.NAT6TableExists = f.tables["ip6/"+nft.TableNAT6]
	for k, v := range f.chains {
		st.Chains[k] = v
	}
	for k, v := range f.chainRules {
		st.RuleCounts[k] = v
	}
	for key := range f.sets {
		family, table, name := splitKey3(key)
		tk := family + "/" + table
		st.TableSets[tk] = append(st.TableSets[tk], name)
		if table != nft.TableFilter {
			continue
		}
		st.Sets = append(st.Sets, name)
		var elems []string
		for e := range f.setElems[key] {
			elems = append(elems, e)
		}
		sort.Strings(elems)
		st.SetElements[name] = elems
		if name == nft.SetQuotaBlock {
			for _, e := range elems {
				var id int64
				if _, err := fmt.Sscanf(e, "%d", &id); err == nil {
					st.QuotaBlocked = append(st.QuotaBlocked, id)
				}
			}
		}
	}
	for key, bytes := range f.counters {
		family, table, name := splitKey3(key)
		if family != "inet" || table != nft.TableFilter {
			continue
		}
		st.Counters = append(st.Counters, name)
		st.CounterBytes[name] = bytes
	}
	sort.Strings(st.Counters)
	sort.Strings(st.Sets)
	for k := range st.TableSets {
		sort.Strings(st.TableSets[k])
	}
	return st
}

func splitKey3(k string) (family, table, name string) {
	parts := strings.SplitN(k, "/", 3)
	if len(parts) != 3 {
		return "", "", ""
	}
	return parts[0], parts[1], parts[2]
}

// execScript 解析并执行脚本（只支持本项目生成的语法子集）。
//
// 脚本形如：
//
//	table ip nff_nat4 {
//	    set nff_nat4_marks {
//	        type mark
//	    }
//	    chain nff_nat4_prerouting {
//	        type nat hook prerouting priority dstnat; policy accept;
//	    }
//	}
//	flush chain ip nff_nat4 nff_nat4_prerouting
//	add rule ip nff_nat4 nff_nat4_prerouting ...
//
// 因此必须跟踪花括号深度：table 块内还嵌套 set / chain 块，
// 只看 "}" 会误判 table 块提前结束（曾导致 chain/set 全部识别不出来）。
func (f *fakeNFT) execScript(script string) {
	var curFamily, curTable string
	depth := 0
	for _, raw := range strings.Split(script, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if depth > 0 {
			// table 块内部：depth==1 是直接子声明（set/chain/counter），
			// 更深的是它们的属性行（type/hook/policy），一律忽略。
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
				f.chainRules[fields[2]+"/"+fields[3]+"/"+fields[4]] = 0
			}
		case strings.HasPrefix(line, "flush set "):
			fields := strings.Fields(line)
			if len(fields) >= 5 {
				f.setElems[fields[2]+"/"+fields[3]+"/"+fields[4]] = map[string]bool{}
			}
		case strings.HasPrefix(line, "add rule "):
			fields := strings.Fields(line)
			if len(fields) >= 5 {
				f.chainRules[fields[2]+"/"+fields[3]+"/"+fields[4]]++
			}
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
		if !f.chains[key] {
			f.chains[key] = true
			f.chainRules[key] = 0
		}
	}
}

// elementOp 处理 add/delete element。
func (f *fakeNFT) elementOp(line string, add bool) {
	open := strings.Index(line, "{")
	close := strings.LastIndex(line, "}")
	if open < 0 || close < open {
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
	for _, e := range strings.Split(line[open+1:close], ",") {
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
			delete(f.chainRules, k)
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
	delete(f.chainRules, key)
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
	f.chainRules[family+"/"+table+"/"+chain] = 0
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
	return f.chains[family+"/"+table+"/"+chain]
}

func (f *fakeNFT) hasSet(family, table, set string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.sets[family+"/"+table+"/"+set]
}

func (f *fakeNFT) ruleCount(family, table, chain string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.chainRules[family+"/"+table+"/"+chain]
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
