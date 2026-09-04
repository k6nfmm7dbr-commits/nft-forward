package nft

import (
	"context"
	"fmt"
	"strings"
)

// ownedTables 是本程序唯一允许删除的表。顺序无关。
var ownedTables = []struct{ family, name string }{
	{"ip", TableNAT4},
	{"ip6", TableNAT6},
	{"inet", TableFilter},
}

// IsMissingTable 判断 nft 错误是否表示「对象不存在」（卸载/clear 时视为成功）。
func IsMissingTable(stderr string) bool {
	s := strings.ToLower(stderr)
	return strings.Contains(s, "no such file") ||
		strings.Contains(s, "does not exist") ||
		strings.Contains(s, "not found") ||
		strings.Contains(s, "no such table")
}

// ClearOwned 只删除本程序自有的 nff_* 三张表。
//
// 绝不 flush ruleset，绝不触碰 INPUT/OUTPUT/FORWARD 默认链，
// 绝不删除 Docker / firewalld / 用户自己的表。
// 某张表不存在视为成功（幂等）。
func ClearOwned(ctx context.Context, runner Runner) error {
	if runner == nil {
		runner = ExecRunner{}
	}
	var first error
	for _, t := range ownedTables {
		rc, _, stderr, err := runner.Run(ctx, "nft", "delete", "table", t.family, t.name)
		if err != nil && first == nil {
			first = fmt.Errorf("删除 %s %s 失败: %w", t.family, t.name, err)
			continue
		}
		if rc != 0 && !IsMissingTable(stderr) {
			if first == nil {
				first = fmt.Errorf("删除 %s %s 失败: %s", t.family, t.name, strings.TrimSpace(stderr))
			}
		}
	}
	return first
}
