package nft

import (
	"strings"
	"testing"
)

func TestDiffElements(t *testing.T) {
	add, del := DiffElements([]string{"1.1.1.1", "2.2.2.2"}, []string{"2.2.2.2", "3.3.3.3"})
	if len(add) != 1 || add[0] != "3.3.3.3" {
		t.Fatalf("add 应为 [3.3.3.3]，实际 %v", add)
	}
	if len(del) != 1 || del[0] != "1.1.1.1" {
		t.Fatalf("del 应为 [1.1.1.1]，实际 %v", del)
	}
}

func TestDiffElementsNoChange(t *testing.T) {
	add, del := DiffElements([]string{"1.1.1.1"}, []string{"1.1.1.1"})
	if len(add) != 0 || len(del) != 0 {
		t.Fatal("无变化时不应产生增删")
	}
}

// 无变化时必须返回空脚本 —— 调用方据此完全跳过 nft 调用。
func TestGenElementScriptEmptyWhenNoChange(t *testing.T) {
	script := GenElementScript([]ElementDiff{
		{Family: "inet", Table: TableFilter, Set: AllowSetV4(1)},
	})
	if script != "" {
		t.Fatalf("无变化应返回空脚本，实际:\n%s", script)
	}
}

func TestGenElementScriptDeleteBeforeAdd(t *testing.T) {
	script := GenElementScript([]ElementDiff{{
		Family: "inet", Table: TableFilter, Set: AllowSetV4(1),
		Add: []string{"3.3.3.3"}, Del: []string{"1.1.1.1"},
	}})
	di := strings.Index(script, "delete element")
	ai := strings.Index(script, "add element")
	if di < 0 || ai < 0 {
		t.Fatal("应同时包含 delete/add element")
	}
	if di > ai {
		t.Fatal("delete 必须在 add 之前（避免元素迁移冲突）")
	}
	// 绝不能出现表/链级操作。
	for _, banned := range []string{"delete table", "flush", "add rule", "add chain"} {
		if strings.Contains(script, banned) {
			t.Fatalf("元素脚本不应包含 %q（会导致 counter 清零或规则重建）", banned)
		}
	}
}

func TestQuotaBlockDiff(t *testing.T) {
	d := QuotaBlockDiff([]int64{1, 2}, []int64{2, 3})
	if len(d.Add) != 1 || d.Add[0] != "3" {
		t.Fatalf("应新增 mark 3，实际 %v", d.Add)
	}
	if len(d.Del) != 1 || d.Del[0] != "1" {
		t.Fatalf("应删除 mark 1，实际 %v", d.Del)
	}
	if d.Set != SetQuotaBlock {
		t.Fatalf("set 名应为 %s", SetQuotaBlock)
	}
}

func TestAllowDiffSetNames(t *testing.T) {
	v4 := AllowDiff(7, false, nil, []string{"1.1.1.1"})
	if v4.Set != AllowSetV4(7) {
		t.Fatalf("v4 set 名错误: %s", v4.Set)
	}
	v6 := AllowDiff(7, true, nil, []string{"2001:db8::1"})
	if v6.Set != AllowSetV6(7) {
		t.Fatalf("v6 set 名错误: %s", v6.Set)
	}
}

func TestParseStateCountersAndSets(t *testing.T) {
	js := `{"nftables":[
	  {"table":{"family":"inet","name":"nff_filter"}},
	  {"table":{"family":"ip","name":"nff_nat4"}},
	  {"table":{"family":"ip","name":"docker"}},
	  {"counter":{"family":"inet","table":"nff_filter","name":"nff_filter_up_1","bytes":123}},
	  {"counter":{"family":"inet","table":"docker","name":"other_counter","bytes":9}},
	  {"set":{"family":"inet","table":"nff_filter","name":"nff_filter_allow_1_v4","elem":["1.1.1.1","2.2.2.2"]}},
	  {"set":{"family":"inet","table":"nff_filter","name":"nff_filter_qblock","elem":[5,7]}}
	]}`
	st, err := ParseState(js)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if !st.FilterTableExists || !st.NAT4TableExists {
		t.Fatal("应识别自有表存在")
	}
	if st.NAT6TableExists {
		t.Fatal("不存在的表不应被标记存在")
	}
	if len(st.Counters) != 1 || st.Counters[0] != "nff_filter_up_1" {
		t.Fatalf("只应收集自有表 counter，实际 %v", st.Counters)
	}
	elems := st.ElementsOf("nff_filter_allow_1_v4")
	if len(elems) != 2 {
		t.Fatalf("allow set 元素应为 2 个，实际 %v", elems)
	}
	if len(st.QuotaBlocked) != 2 {
		t.Fatalf("qblock 应解析出 2 个规则 ID，实际 %v", st.QuotaBlocked)
	}
}

func TestParseStateEmpty(t *testing.T) {
	st, err := ParseState("")
	if err != nil {
		t.Fatalf("空输入不应报错: %v", err)
	}
	if st.FilterTableExists {
		t.Fatal("空 ruleset 时表不应存在")
	}
}

func TestParseStateNestedElem(t *testing.T) {
	// nft 有时把元素包成 {"elem":{"val":...}}。
	js := `{"nftables":[
	  {"table":{"family":"inet","name":"nff_filter"}},
	  {"set":{"family":"inet","table":"nff_filter","name":"nff_filter_qblock",
	          "elem":[{"elem":{"val":3}},{"elem":{"val":4}}]}}
	]}`
	st, err := ParseState(js)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(st.QuotaBlocked) != 2 {
		t.Fatalf("应解析嵌套元素，实际 %v", st.QuotaBlocked)
	}
}
