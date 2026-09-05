package traffic

import (
	"context"
	"testing"
	"time"

	"github.com/k6nfmm7dbr-commits/nft-forward/internal/database"
)

// ---- quota 边界（v0.3.2 复核）----
//
// 目标：在 collector flush 前后、reset、counter 重置、counter 消失后恢复、
// 服务重启等场景下，实时用量既不双算也不漏算。

// ① collector flush 前后，实时用量必须连续（不跳变、不翻倍）。
func TestQuotaContinuousAcrossFlush(t *testing.T) {
	c, _ := newTestCollector(t, map[string]int64{
		"nff_filter_up_1": 1000, "nff_filter_down_1": 500,
	})
	base := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	tick := 0
	c.SetClock(func() time.Time { return base.Add(time.Duration(tick) * time.Second) })

	// 首轮：全部 1500 入账
	if err := c.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	s := c.LiveSnapshot()
	cur := map[string]int64{"nff_filter_up_1": 1000, "nff_filter_down_1": 500}
	if used := s.Used(1, cur); used != 1500 {
		t.Fatalf("首轮后应为 1500，实际 %d", used)
	}

	// flush 之前又跑了 700（policy 视角）
	cur = map[string]int64{"nff_filter_up_1": 1500, "nff_filter_down_1": 700}
	if used := s.Used(1, cur); used != 2200 {
		t.Fatalf("flush 前实时用量应为 2200，实际 %d", used)
	}

	// collector flush（把 2200 落库）
	tick = 2
	c.runner = mockRunner{out: countersJSON(cur)}
	if err := c.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	s2 := c.LiveSnapshot()
	if used := s2.Used(1, cur); used != 2200 {
		t.Fatalf("flush 后同一读数仍应为 2200（不得翻倍），实际 %d", used)
	}
	up, down := totalsOf(t, dbOf(c), 1)
	if up+down != 2200 {
		t.Fatalf("库内累计应为 2200，实际 %d", up+down)
	}
}

// ② policy 手上的读数比 collector 已提交的旧（错位）→ 绝不双算。
func TestQuotaNoDoubleCountOnStaleRead(t *testing.T) {
	c, _ := newTestCollector(t, map[string]int64{
		"nff_filter_up_1": 1000, "nff_filter_down_1": 200,
	})
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	c.SetClock(func() time.Time { return now })
	if err := c.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	s := c.LiveSnapshot()
	// 模拟错位：policy 拿到的是比基线更小的旧读数。
	stale := map[string]int64{"nff_filter_up_1": 800, "nff_filter_down_1": 150}
	used := s.Used(1, stale)
	if used != 1200 {
		t.Fatalf("读数错位时应仍为已落库的 1200（不得变成 2150），实际 %d", used)
	}
}

// ③ counter 真被重置（自愈重建）：由 collector 的 reset 检测入账，不丢不重。
func TestQuotaCounterResetAccountedOnce(t *testing.T) {
	c, db := newTestCollector(t, map[string]int64{
		"nff_filter_up_1": 100000, "nff_filter_down_1": 50000,
	})
	base := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	tick := 0
	c.SetClock(func() time.Time { return base.Add(time.Duration(tick) * time.Second) })
	if err := c.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	up, down := totalsOf(t, db, 1)
	if up+down != 150000 {
		t.Fatalf("首轮应入账 150000，实际 %d", up+down)
	}

	// counter 被重建后从小值开始
	tick = 2
	reset := map[string]int64{"nff_filter_up_1": 5, "nff_filter_down_1": 3}
	c.runner = mockRunner{out: countersJSON(reset)}
	if err := c.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	up, down = totalsOf(t, db, 1)
	if up+down != 150008 {
		t.Fatalf("reset 后应为 150000+8=150008，实际 %d", up+down)
	}
	// 实时快照对同一读数不得再加一遍
	s := c.LiveSnapshot()
	if used := s.Used(1, reset); used != 150008 {
		t.Fatalf("reset 入账后实时用量应为 150008，实际 %d", used)
	}
}

// ④ counter 消失后恢复：消失期间不计，恢复后从新值开始累计。
func TestQuotaCounterDisappearAndReturn(t *testing.T) {
	c, db := newTestCollector(t, map[string]int64{
		"nff_filter_up_1": 1000, "nff_filter_down_1": 500,
	})
	base := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	tick := 0
	c.SetClock(func() time.Time { return base.Add(time.Duration(tick) * time.Second) })
	if err := c.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}

	// 只剩 up counter（down 被删）：不应把 down 的旧值重复入账。
	tick = 2
	c.runner = mockRunner{out: countersJSON(map[string]int64{"nff_filter_up_1": 1200})}
	if err := c.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	up, down := totalsOf(t, db, 1)
	if up != 1200 {
		t.Fatalf("up 应累计到 1200，实际 %d", up)
	}
	if down != 500 {
		t.Fatalf("down 消失期间不应变化，实际 %d", down)
	}

	// down counter 恢复（新建，从 0 开始涨到 60）
	tick = 4
	c.runner = mockRunner{out: countersJSON(map[string]int64{
		"nff_filter_up_1": 1300, "nff_filter_down_1": 60,
	})}
	if err := c.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	up, down = totalsOf(t, db, 1)
	if up != 1300 {
		t.Fatalf("up 应为 1300，实际 %d", up)
	}
	if down != 560 {
		t.Fatalf("down 应为 500+60=560，实际 %d", down)
	}
}

// ⑤ 服务重启（新 Collector 实例、同一个库）后累计继续正确。
func TestQuotaSurvivesRestart(t *testing.T) {
	c, db := newTestCollector(t, map[string]int64{
		"nff_filter_up_1": 1000, "nff_filter_down_1": 500,
	})
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	c.SetClock(func() time.Time { return now })
	if err := c.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}

	// 「重启」：用同一个 db 新建 Collector，counter 继续往上涨。
	c2 := NewCollector(db, mockRunner{out: countersJSON(map[string]int64{
		"nff_filter_up_1": 1600, "nff_filter_down_1": 900,
	})}, "Asia/Shanghai")
	c2.SetClock(func() time.Time { return now.Add(3 * time.Second) })
	if err := c2.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	up, down := totalsOf(t, db, 1)
	// 基线从 counter_state 恢复：增量 600 + 400
	if up != 1600 || down != 900 {
		t.Fatalf("重启后应继续差分：期望 1600/900，实际 %d/%d", up, down)
	}
	s := c2.LiveSnapshot()
	if used := s.Used(1, map[string]int64{"nff_filter_up_1": 1600, "nff_filter_down_1": 900}); used != 2500 {
		t.Fatalf("重启后实时用量应为 2500，实际 %d", used)
	}
}

// ⑥ 零增量多轮：用量不得漂移。
func TestQuotaStableWithZeroDelta(t *testing.T) {
	cur := map[string]int64{"nff_filter_up_1": 1000, "nff_filter_down_1": 500}
	c, _ := newTestCollector(t, cur)
	base := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 6; i++ {
		c.SetClock(func() time.Time { return base.Add(time.Duration(i) * time.Second) })
		if err := c.Tick(context.Background()); err != nil {
			t.Fatal(err)
		}
		s := c.LiveSnapshot()
		if used := s.Used(1, cur); used != 1500 {
			t.Fatalf("第 %d 轮用量应恒为 1500，实际 %d", i, used)
		}
	}
}

// dbOf 取 collector 内部的 db（测试用）。
func dbOf(c *Collector) *database.DB { return c.db }
