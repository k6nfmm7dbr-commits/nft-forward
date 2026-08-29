package nft

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// ElementDiff 描述一次增量 set 元素同步的意图。
//
// 只增删元素，绝不触碰链与 counter —— 这样在线 IP 频繁上下线、配额状态
// 翻转都不会导致规则重建或计数清零。
type ElementDiff struct {
	Family string // ip / ip6 / inet
	Table  string
	Set    string
	Add    []string
	Del    []string
}

// Empty 报告本 diff 是否无操作。
func (d ElementDiff) Empty() bool { return len(d.Add) == 0 && len(d.Del) == 0 }

// DiffElements 计算 want 相对 have 的增删（结果已排序，保证脚本稳定可测）。
func DiffElements(have, want []string) (add, del []string) {
	haveSet := make(map[string]bool, len(have))
	for _, v := range have {
		haveSet[v] = true
	}
	wantSet := make(map[string]bool, len(want))
	for _, v := range want {
		wantSet[v] = true
	}
	for v := range wantSet {
		if !haveSet[v] {
			add = append(add, v)
		}
	}
	for v := range haveSet {
		if !wantSet[v] {
			del = append(del, v)
		}
	}
	sort.Strings(add)
	sort.Strings(del)
	return add, del
}

// GenElementScript 把若干 diff 合成单个 nft 脚本（一个原子事务）。
// 返回空串表示无需应用。
func GenElementScript(diffs []ElementDiff) string {
	var b strings.Builder
	for _, d := range diffs {
		if d.Empty() {
			continue
		}
		// 先删后加：同一元素从一个 set 迁移到另一个时不会冲突。
		if len(d.Del) > 0 {
			fmt.Fprintf(&b, "delete element %s %s %s { %s }\n",
				d.Family, d.Table, d.Set, strings.Join(d.Del, ", "))
		}
		if len(d.Add) > 0 {
			fmt.Fprintf(&b, "add element %s %s %s { %s }\n",
				d.Family, d.Table, d.Set, strings.Join(d.Add, ", "))
		}
	}
	if b.Len() == 0 {
		return ""
	}
	return "#!/usr/sbin/nft -f\n" + b.String()
}

// ApplyElements 事务化应用元素增量。空 diff 直接返回 nil（不调用 nft）。
func ApplyElements(ctx context.Context, runner Runner, scriptPath string, diffs []ElementDiff) error {
	script := GenElementScript(diffs)
	if script == "" {
		return nil
	}
	return Apply(ctx, runner, scriptPath, script)
}

// QuotaBlockDiff 构造配额阻断 set 的增量（元素是规则 ID 的 mark 值）。
func QuotaBlockDiff(have, want []int64) ElementDiff {
	toStr := func(ids []int64) []string {
		out := make([]string, 0, len(ids))
		for _, id := range ids {
			out = append(out, strconv.FormatInt(id, 10))
		}
		return out
	}
	add, del := DiffElements(toStr(have), toStr(want))
	return ElementDiff{Family: "inet", Table: TableFilter, Set: SetQuotaBlock, Add: add, Del: del}
}

// AllowDiff 构造某规则某地址族 allow set 的增量。
func AllowDiff(ruleID int64, v6 bool, have, want []string) ElementDiff {
	set := AllowSetV4(ruleID)
	if v6 {
		set = AllowSetV6(ruleID)
	}
	add, del := DiffElements(have, want)
	return ElementDiff{Family: "inet", Table: TableFilter, Set: set, Add: add, Del: del}
}
