package nft

import (
	"strings"
	"testing"

	"github.com/k6nfmm7dbr-commits/nft-forward/internal/forward"
)

func dualRule(id int64) *forward.Rule {
	return &forward.Rule{
		ID: id, Name: "dual", Enabled: true, Protocol: forward.ProtoTCPUDP,
		ListenPort: 20000 + int(id), TargetAddress: "dual.example.com", TargetPort: 443,
		ResolvedV4: "1.2.3.4", ResolvedV6: "2001:db8::1",
		ResolveStatus: forward.ResolveOK,
	}
}

// fullState 返回「一切齐全」的状态（由 DesiredObjects 反推），作为破坏测试的基准。
func fullState(gi *GenInput) *State {
	st := &State{
		SetElements:  map[string][]string{},
		Chains:       map[string]bool{},
		RuleCounts:   map[string]int{},
		TableSets:    map[string][]string{},
		CounterBytes: map[string]int64{},
	}
	for _, o := range DesiredObjects(gi) {
		switch o.Kind {
		case ObjTable:
			switch o.Table {
			case TableFilter:
				st.FilterTableExists = true
			case TableNAT4:
				st.NAT4TableExists = true
			case TableNAT6:
				st.NAT6TableExists = true
			}
		case ObjChain:
			st.Chains[ObjKey(o.Family, o.Table, o.Name)] = true
		case ObjSet:
			tk := o.Family + "/" + o.Table
			st.TableSets[tk] = append(st.TableSets[tk], o.Name)
			if o.Table == TableFilter {
				st.Sets = append(st.Sets, o.Name)
			}
		case ObjCounter:
			st.Counters = append(st.Counters, o.Name)
			st.CounterBytes[o.Name] = 0
		case ObjChainRules:
			st.RuleCounts[ObjKey(o.Family, o.Table, o.Name)] = o.MinN
		}
	}
	return st
}

// desired 集合必须覆盖三张表、必要链、三类 set、双向 counter。
func TestDesiredObjectsCoverage(t *testing.T) {
	gi := &GenInput{
		Rules:  []*forward.Rule{dualRule(1)},
		States: map[int64]*RuleState{1: {IPLimitEnabled: true}},
	}
	objs := DesiredObjects(gi)
	want := []string{
		"table inet " + TableFilter,
		"table ip " + TableNAT4,
		"table ip6 " + TableNAT6,
		"chain inet " + TableFilter + " " + ChainForward(),
		"chain ip " + TableNAT4 + " " + ChainPrerouting(TableNAT4),
		"chain ip " + TableNAT4 + " " + ChainPostrouting(TableNAT4),
		"chain ip6 " + TableNAT6 + " " + ChainPrerouting(TableNAT6),
		"chain ip6 " + TableNAT6 + " " + ChainPostrouting(TableNAT6),
		"set inet " + TableFilter + " " + SetQuotaBlock,
		"set inet " + TableFilter + " " + AllowSetV4(1),
		"set inet " + TableFilter + " " + AllowSetV6(1),
		"set ip " + TableNAT4 + " " + MarksSet(TableNAT4),
		"set ip6 " + TableNAT6 + " " + MarksSet(TableNAT6),
		"counter inet " + TableFilter + " " + CounterUp(1),
		"counter inet " + TableFilter + " " + CounterDown(1),
	}
	have := map[string]bool{}
	for _, o := range objs {
		have[o.String()] = true
	}
	for _, w := range want {
		if !have[w] {
			t.Errorf("desired 集合缺少: %s", w)
		}
	}
}

// 只有 IPv4 目标时不应要求 nff_nat6（否则会无限重建）。
func TestDesiredObjectsSkipsUnusedFamily(t *testing.T) {
	gi := &GenInput{Rules: []*forward.Rule{{
		ID: 1, Name: "v4", Enabled: true, Protocol: forward.ProtoTCP,
		ListenPort: 20000, TargetAddress: "1.2.3.4", TargetPort: 80,
	}}}
	for _, o := range DesiredObjects(gi) {
		if o.Table == TableNAT6 {
			t.Fatalf("无 IPv6 目标时不应要求 %s", o)
		}
	}
}

// 未启用 IP 限制的规则不应要求 allow set。
func TestDesiredObjectsSkipsAllowSetsWithoutIPLimit(t *testing.T) {
	gi := &GenInput{Rules: []*forward.Rule{{
		ID: 7, Name: "r", Enabled: true, Protocol: forward.ProtoTCP,
		ListenPort: 20000, TargetAddress: "1.2.3.4", TargetPort: 80,
	}}}
	for _, o := range DesiredObjects(gi) {
		if o.Name == AllowSetV4(7) || o.Name == AllowSetV6(7) {
			t.Fatalf("未启用 IP 限制不应要求 %s", o)
		}
	}
}

// 齐全状态下不应报缺失（否则每轮都会重建、清零 counter）。
func TestMissingObjectsNoneWhenComplete(t *testing.T) {
	gi := &GenInput{
		Rules:  []*forward.Rule{dualRule(1)},
		States: map[int64]*RuleState{1: {IPLimitEnabled: true}},
	}
	if miss := MissingObjects(fullState(gi), DesiredObjects(gi)); len(miss) != 0 {
		t.Fatalf("齐全状态不应有缺失，实际 %v", miss)
	}
}

// 逐项破坏：每种删除都必须被检测出来。
func TestMissingObjectsDetectsEachBreakage(t *testing.T) {
	gi := &GenInput{
		Rules:  []*forward.Rule{dualRule(1)},
		States: map[int64]*RuleState{1: {IPLimitEnabled: true}},
	}
	desired := DesiredObjects(gi)

	cases := []struct {
		name   string
		break_ func(*State)
		expect string
	}{
		{"删除 nff_nat4", func(s *State) { s.NAT4TableExists = false }, "table ip " + TableNAT4},
		{"删除 nff_nat6", func(s *State) { s.NAT6TableExists = false }, "table ip6 " + TableNAT6},
		{"删除 nff_filter", func(s *State) { s.FilterTableExists = false }, "table inet " + TableFilter},
		{"删除 forward 链", func(s *State) {
			delete(s.Chains, ObjKey("inet", TableFilter, ChainForward()))
		}, "chain inet " + TableFilter},
		{"删除 nat4 prerouting 链", func(s *State) {
			delete(s.Chains, ObjKey("ip", TableNAT4, ChainPrerouting(TableNAT4)))
		}, "chain ip " + TableNAT4},
		{"删除 up counter", func(s *State) {
			s.Counters = removeStr(s.Counters, CounterUp(1))
		}, "counter inet " + TableFilter + " " + CounterUp(1)},
		{"删除 down counter", func(s *State) {
			s.Counters = removeStr(s.Counters, CounterDown(1))
		}, "counter inet " + TableFilter + " " + CounterDown(1)},
		{"删除 IPv4 allow set", func(s *State) {
			s.Sets = removeStr(s.Sets, AllowSetV4(1))
		}, "set inet " + TableFilter + " " + AllowSetV4(1)},
		{"删除 IPv6 allow set", func(s *State) {
			s.Sets = removeStr(s.Sets, AllowSetV6(1))
		}, "set inet " + TableFilter + " " + AllowSetV6(1)},
		{"删除 qblock set", func(s *State) {
			s.Sets = removeStr(s.Sets, SetQuotaBlock)
		}, "set inet " + TableFilter + " " + SetQuotaBlock},
		{"删除 nat4 marks set", func(s *State) {
			s.TableSets["ip/"+TableNAT4] = nil
		}, "set ip " + TableNAT4},
		{"清空 forward 链规则", func(s *State) {
			s.RuleCounts[ObjKey("inet", TableFilter, ChainForward())] = 0
		}, "rules inet " + TableFilter},
	}
	for _, c := range cases {
		st := fullState(gi)
		c.break_(st)
		miss := MissingObjects(st, desired)
		if len(miss) == 0 {
			t.Errorf("%s：未检测到缺失", c.name)
			continue
		}
		found := false
		for _, m := range miss {
			if strings.Contains(m.String(), c.expect) {
				found = true
			}
		}
		if !found {
			t.Errorf("%s：缺失项应含 %q，实际 %v", c.name, c.expect, miss)
		}
	}
}

// State 不携带链/规则数信息时（旧夹具/降级读取）不得误判缺失。
func TestMissingObjectsToleratesUnknownChainInfo(t *testing.T) {
	gi := &GenInput{Rules: []*forward.Rule{{
		ID: 1, Name: "r", Enabled: true, Protocol: forward.ProtoTCP,
		ListenPort: 20000, TargetAddress: "1.2.3.4", TargetPort: 80,
	}}}
	st := &State{
		FilterTableExists: true,
		NAT4TableExists:   true,
		Counters:          []string{CounterUp(1), CounterDown(1)},
		Sets:              []string{SetQuotaBlock},
		// Chains / RuleCounts / TableSets 均为 nil
	}
	miss := MissingObjects(st, DesiredObjects(gi))
	for _, m := range miss {
		if m.Kind == ObjChain || m.Kind == ObjChainRules {
			t.Fatalf("链信息未知时不应判定缺失: %s", m)
		}
		if m.Kind == ObjSet && m.Table != TableFilter {
			t.Fatalf("NAT 表 set 信息未知时不应判定缺失: %s", m)
		}
	}
}

// nil 状态 = 全都缺。
func TestMissingObjectsNilState(t *testing.T) {
	gi := &GenInput{Rules: []*forward.Rule{dualRule(1)}}
	desired := DesiredObjects(gi)
	if miss := MissingObjects(nil, desired); len(miss) != len(desired) {
		t.Fatalf("nil 状态应全部缺失：期望 %d，实得 %d", len(desired), len(miss))
	}
}

func TestDescribeMissing(t *testing.T) {
	if DescribeMissing(nil) != "" {
		t.Fatal("空列表应返回空串")
	}
	var many []Object
	for i := 0; i < 20; i++ {
		many = append(many, Object{Kind: ObjCounter, Family: "inet", Table: TableFilter, Name: "c" + itoaSmall(i)})
	}
	s := DescribeMissing(many)
	if !strings.Contains(s, "共 20 项") {
		t.Fatalf("超长列表应带总数提示，实际 %q", s)
	}
}

// ---- ParseState 扩展：链 / 规则数 / counter 字节 ----

func TestParseStateChainsRulesAndCounterBytes(t *testing.T) {
	js := `{"nftables":[
	 {"table":{"family":"inet","name":"nff_filter"}},
	 {"table":{"family":"ip","name":"nff_nat4"}},
	 {"table":{"family":"ip","name":"other_table"}},
	 {"chain":{"family":"inet","table":"nff_filter","name":"nff_filter_forward"}},
	 {"chain":{"family":"ip","table":"nff_nat4","name":"nff_nat4_prerouting"}},
	 {"chain":{"family":"ip","table":"other_table","name":"foreign_chain"}},
	 {"rule":{"family":"inet","table":"nff_filter","chain":"nff_filter_forward"}},
	 {"rule":{"family":"inet","table":"nff_filter","chain":"nff_filter_forward"}},
	 {"rule":{"family":"ip","table":"other_table","chain":"foreign_chain"}},
	 {"counter":{"family":"inet","table":"nff_filter","name":"nff_filter_up_1","bytes":4242}},
	 {"set":{"family":"ip","table":"nff_nat4","name":"nff_nat4_marks","elem":[1]}},
	 {"set":{"family":"inet","table":"nff_filter","name":"nff_filter_qblock","elem":[7]}}
	]}`
	st, err := ParseState(js)
	if err != nil {
		t.Fatal(err)
	}
	if !st.HasChain("inet", TableFilter, ChainForward()) {
		t.Fatal("未解析出 forward 链")
	}
	if !st.HasChain("ip", TableNAT4, ChainPrerouting(TableNAT4)) {
		t.Fatal("未解析出 nat4 prerouting 链")
	}
	if n, ok := st.ChainRuleCount("inet", TableFilter, ChainForward()); !ok || n != 2 {
		t.Fatalf("forward 链规则数应为 2，实际 %d ok=%v", n, ok)
	}
	if st.CounterBytes[CounterUp(1)] != 4242 {
		t.Fatalf("counter 字节未解析，实际 %d", st.CounterBytes[CounterUp(1)])
	}
	if !st.HasTableSet("ip", TableNAT4, MarksSet(TableNAT4)) {
		t.Fatal("未解析出 NAT 表的 marks set")
	}
	if len(st.QuotaBlocked) != 1 || st.QuotaBlocked[0] != 7 {
		t.Fatalf("qblock 元素解析错误: %v", st.QuotaBlocked)
	}
	// 外部表的链与规则不得进入自有对象视图。
	if st.Chains[ObjKey("ip", "other_table", "foreign_chain")] {
		t.Fatal("绝不能记录外部表的链")
	}
	if _, ok := st.RuleCounts[ObjKey("ip", "other_table", "foreign_chain")]; ok {
		t.Fatal("绝不能统计外部表的规则")
	}
}

func removeStr(list []string, v string) []string {
	out := make([]string, 0, len(list))
	for _, x := range list {
		if x != v {
			out = append(out, x)
		}
	}
	return out
}

func itoaSmall(v int) string {
	if v == 0 {
		return "0"
	}
	var b [4]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}
