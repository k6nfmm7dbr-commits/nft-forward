package nft

import (
	"context"
	"strings"
	"testing"
)

type mockRunner struct {
	fn func(ctx context.Context, args ...string) (int, string, string, error)
}

func (m *mockRunner) Run(ctx context.Context, args ...string) (int, string, string, error) {
	return m.fn(ctx, args...)
}

func TestClearOwnedOnlyTouchesOwnedTables(t *testing.T) {
	var cmds [][]string
	r := &mockRunner{fn: func(_ context.Context, args ...string) (int, string, string, error) {
		cmds = append(cmds, append([]string{}, args...))
		return 0, "", "", nil
	}}
	if err := ClearOwned(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	if len(cmds) != 3 {
		t.Fatalf("期望 3 次 delete table，实得 %d", len(cmds))
	}
	want := map[string]bool{
		"ip nff_nat4":     false,
		"ip6 nff_nat6":    false,
		"inet nff_filter": false,
	}
	for _, c := range cmds {
		joined := strings.Join(c, " ")
		if strings.Contains(joined, "flush") {
			t.Fatalf("ClearOwned 禁止 flush: %s", joined)
		}
		if len(c) < 5 || c[0] != "nft" || c[1] != "delete" || c[2] != "table" {
			t.Fatalf("非法命令: %v", c)
		}
		key := c[3] + " " + c[4]
		if _, ok := want[key]; !ok {
			t.Fatalf("删除了非自有表: %s", key)
		}
		want[key] = true
	}
	for k, seen := range want {
		if !seen {
			t.Fatalf("未删除自有表 %s", k)
		}
	}
}

func TestClearOwnedMissingIsOK(t *testing.T) {
	r := &mockRunner{fn: func(_ context.Context, args ...string) (int, string, string, error) {
		return 1, "", "Error: No such file or directory", nil
	}}
	if err := ClearOwned(context.Background(), r); err != nil {
		t.Fatalf("表不存在应视为成功: %v", err)
	}
}

func TestIsMissingTable(t *testing.T) {
	if !IsMissingTable("Error: No such file or directory") {
		t.Fatal("no such file")
	}
	if IsMissingTable("Operation not permitted") {
		t.Fatal("权限错误不应当成 missing")
	}
}
