package traffic

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/k6nfmm7dbr-commits/nft-forward/internal/database"
)

// mockRunner 返回预置的 `nft -j list counters` JSON。
type mockRunner struct{ out string }

func (m mockRunner) Run(ctx context.Context, args ...string) (int, string, string, error) {
	return 0, m.out, "", nil
}

func countersJSON(counters map[string]int64) string {
	s := `{"nftables":[`
	first := true
	for name, b := range counters {
		if !first {
			s += ","
		}
		first = false
		s += fmt.Sprintf(`{"counter":{"name":%q,"bytes":%d,"packets":0}}`, name, b)
	}
	s += `]}`
	return s
}

func newTestCollector(t *testing.T, counters map[string]int64) (*Collector, *database.DB) {
	t.Helper()
	dir := t.TempDir()
	db, err := database.Open(filepath.Join(dir, "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	c := NewCollector(db, mockRunner{out: countersJSON(counters)}, "Asia/Shanghai")
	return c, db
}

func totalsOf(t *testing.T, db *database.DB, ruleID int64) (int64, int64) {
	t.Helper()
	var up, down sql.NullInt64
	err := db.QueryRow("SELECT upload_bytes,download_bytes FROM traffic_totals WHERE rule_id=?", ruleID).Scan(&up, &down)
	if err == sql.ErrNoRows {
		return 0, 0
	}
	if err != nil {
		t.Fatal(err)
	}
	return up.Int64, down.Int64
}

// 正常单调差分：两轮累计，增量正确写入。
func TestMonotonicDelta(t *testing.T) {
	c, db := newTestCollector(t, map[string]int64{"nff_filter_up_1": 1000, "nff_filter_down_1": 500})
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	c.SetClock(func() time.Time { return now })
	if err := c.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	up, down := totalsOf(t, db, 1)
	if up != 1000 || down != 500 {
		t.Fatalf("首轮应为 1000/500, got %d/%d", up, down)
	}

	// 第二轮：counter 增长。
	c.runner = mockRunner{out: countersJSON(map[string]int64{"nff_filter_up_1": 3000, "nff_filter_down_1": 1500})}
	c.SetClock(func() time.Time { return now.Add(2 * time.Second) })
	if err := c.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	up, down = totalsOf(t, db, 1)
	if up != 3000 || down != 1500 {
		t.Fatalf("累计应为 3000/1500, got %d/%d", up, down)
	}
}

// counter reset（表重建/重启）：绝不产生负值、不把旧累计再加一次。
func TestCounterResetNoFakeTraffic(t *testing.T) {
	c, db := newTestCollector(t, map[string]int64{"nff_filter_up_1": 100000, "nff_filter_down_1": 50000})
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	c.SetClock(func() time.Time { return now })
	if err := c.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	up, _ := totalsOf(t, db, 1)
	if up != 100000 {
		t.Fatalf("首轮累计应 100000, got %d", up)
	}

	// 模拟 counter 被重置：值从 100000 掉到 5（重置后新增）。
	c.runner = mockRunner{out: countersJSON(map[string]int64{"nff_filter_up_1": 5, "nff_filter_down_1": 3})}
	c.SetClock(func() time.Time { return now.Add(2 * time.Second) })
	if err := c.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	up, down := totalsOf(t, db, 1)
	// 期望：100000 + 5 = 100005（新值作为重置后增量），绝不下溢、绝不重复加旧值。
	if up != 100005 {
		t.Fatalf("reset 后累计应 100005, got %d", up)
	}
	if down != 50003 {
		t.Fatalf("reset 后下载应 50003, got %d", down)
	}
}

// 零增量不重复入账。
func TestZeroDelta(t *testing.T) {
	c, db := newTestCollector(t, map[string]int64{"nff_filter_up_1": 1000})
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	c.SetClock(func() time.Time { return now })
	_ = c.Tick(context.Background())
	c.SetClock(func() time.Time { return now.Add(2 * time.Second) })
	_ = c.Tick(context.Background()) // 值不变
	up, _ := totalsOf(t, db, 1)
	if up != 1000 {
		t.Fatalf("零增量累计应不变 1000, got %d", up)
	}
}

// 跨天：daily 按天分行（UTC+8）。
func TestDailyRollover(t *testing.T) {
	c, db := newTestCollector(t, map[string]int64{"nff_filter_up_1": 100})
	day1 := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	c.SetClock(func() time.Time { return day1 })
	_ = c.Tick(context.Background())
	// 下一天（跨天）。
	day2 := day1.Add(25 * time.Hour) // UTC 次日（含 +8 已过天界）
	c.SetClock(func() time.Time { return day2 })
	c.runner = mockRunner{out: countersJSON(map[string]int64{"nff_filter_up_1": 300})}
	_ = c.Tick(context.Background())

	rows, err := db.Query("SELECT day, upload_bytes FROM traffic_daily WHERE rule_id=1 ORDER BY day")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var d string
		var b int64
		_ = rows.Scan(&d, &b)
		count++
	}
	if count != 2 {
		t.Fatalf("跨天应有 2 行每日数据, got %d", count)
	}
}
