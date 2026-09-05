package traffic

import (
	"context"
	"testing"
	"time"
)

// LiveDelta.Used 的三种情形：正常增量、counter 重置、counter 缺失。
func TestLiveDeltaUsed(t *testing.T) {
	d := LiveDelta{
		Ready:     true,
		Committed: map[int64]int64{1: 1000},
		Baseline:  map[string]int64{"nff_filter_up_1": 400, "nff_filter_down_1": 600},
	}
	// 正常增量：up 500-400=100，down 900-600=300 → 1000+400
	got := d.Used(1, map[string]int64{"nff_filter_up_1": 500, "nff_filter_down_1": 900})
	if got != 1400 {
		t.Fatalf("应为 1400，实际 %d", got)
	}
	// counter 被重置（当前值 < 基线）：新值即未落库增量，绝不出现负数
	got = d.Used(1, map[string]int64{"nff_filter_up_1": 5, "nff_filter_down_1": 7})
	if got != 1012 {
		t.Fatalf("重置后应为 1000+5+7=1012，实际 %d", got)
	}
	// 没有 counter 读数：退回已落库累计
	if got := d.Used(1, nil); got != 1000 {
		t.Fatalf("无 counter 读数应为 1000，实际 %d", got)
	}
	// 未知规则
	if got := d.Used(99, map[string]int64{"nff_filter_up_99": 50}); got != 50 {
		t.Fatalf("未知规则应只算未落库增量，实际 %d", got)
	}
}

// LiveSnapshot 在首轮采集后必须 Ready，且 baseline 等于已落库 counter 读数。
func TestLiveSnapshotAfterTick(t *testing.T) {
	c, db := newTestCollector(t, map[string]int64{
		"nff_filter_up_1": 1000, "nff_filter_down_1": 500,
	})
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	c.SetClock(func() time.Time { return now })

	if s := c.LiveSnapshot(); s.Ready {
		t.Fatal("首轮采集前不应 Ready")
	}
	if err := c.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	s := c.LiveSnapshot()
	if !s.Ready {
		t.Fatal("首轮采集后应 Ready")
	}
	if s.Baseline["nff_filter_up_1"] != 1000 || s.Baseline["nff_filter_down_1"] != 500 {
		t.Fatalf("baseline 应等于已落库 counter 读数，实际 %+v", s.Baseline)
	}
	if s.Committed[1] != 1500 {
		t.Fatalf("committed 应为 1500，实际 %d", s.Committed[1])
	}
	// 此刻「未落库增量」应为 0：baseline 与库内数据自洽，不重复计费。
	if used := s.Used(1, map[string]int64{"nff_filter_up_1": 1000, "nff_filter_down_1": 500}); used != 1500 {
		t.Fatalf("刚提交后实时用量应等于已落库累计，实际 %d", used)
	}
	// 数据库里也确实是 1500
	up, down := totalsOf(t, db, 1)
	if up+down != 1500 {
		t.Fatalf("库内累计应为 1500，实际 %d", up+down)
	}
}

// 高带宽：counter 猛涨但还没到刷盘时刻，实时用量必须立刻体现。
func TestLiveSnapshotReflectsUnflushedBytes(t *testing.T) {
	c, _ := newTestCollector(t, map[string]int64{
		"nff_filter_up_1": 100, "nff_filter_down_1": 100,
	})
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	c.SetClock(func() time.Time { return now })
	if err := c.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	s := c.LiveSnapshot()
	// 模拟 2 秒内 counter 涨到 100MB（尚未 Tick）
	const burst = 100 << 20
	used := s.Used(1, map[string]int64{
		"nff_filter_up_1": 100 + burst, "nff_filter_down_1": 100,
	})
	if used < burst {
		t.Fatalf("未落库的 %d 字节必须计入实时用量，实际 %d", burst, used)
	}
}

// 快照是副本：修改返回值不影响 collector 内部状态。
func TestLiveSnapshotIsCopy(t *testing.T) {
	c, _ := newTestCollector(t, map[string]int64{"nff_filter_up_1": 10, "nff_filter_down_1": 10})
	c.SetClock(func() time.Time { return time.Unix(1_800_000_000, 0) })
	if err := c.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	s := c.LiveSnapshot()
	s.Committed[1] = 999999
	s.Baseline["nff_filter_up_1"] = 999999
	s2 := c.LiveSnapshot()
	if s2.Committed[1] == 999999 || s2.Baseline["nff_filter_up_1"] == 999999 {
		t.Fatal("LiveSnapshot 必须返回副本")
	}
}

// 并发读取快照与 Tick 不得竞态（配合 -race 生效）。
func TestLiveSnapshotConcurrentWithTick(t *testing.T) {
	c, _ := newTestCollector(t, map[string]int64{"nff_filter_up_1": 10, "nff_filter_down_1": 10})
	base := time.Unix(1_800_000_000, 0)
	i := 0
	c.SetClock(func() time.Time { i++; return base.Add(time.Duration(i) * time.Second) })

	done := make(chan struct{})
	go func() {
		defer close(done)
		for k := 0; k < 200; k++ {
			_ = c.LiveSnapshot()
			_ = c.Snapshot()
		}
	}()
	for k := 0; k < 50; k++ {
		if err := c.Tick(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	<-done
}
