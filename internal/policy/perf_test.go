package policy

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/k6nfmm7dbr-commits/nft-forward/internal/connection"
	"github.com/k6nfmm7dbr-commits/nft-forward/internal/forward"
	"github.com/k6nfmm7dbr-commits/nft-forward/internal/traffic"
)

// TestFlowStateGCAfterShortConnections 大量短连接结束后 flow 表必须回落。
//
// 旧实现的问题：flow entry 只在「超过 idle 窗口且字节未变」时才删除。conntrack
// 里流一消失就再也不会被 touch，于是那条 entry 永久残留 —— 高并发短连接场景下
// s.flows 线性增长直到 OOM。现在每轮用 seenFlowKeys 做 GC，消失即回收。
func TestFlowStateGCAfterShortConnections(t *testing.T) {
	svc, store, _ := newTestService(t)
	addRule(t, store, &forward.Rule{
		Name: "r1", Enabled: true, Protocol: "tcp",
		ListenPort: 20000, TargetAddress: "10.0.0.2", TargetPort: 80,
	})

	var flows []connection.Flow
	svc.SetConntrack(func(string) connection.Result {
		return connection.Result{Available: true, Entries: len(flows) + 1, Flows: flows}
	})
	ctx := context.Background()

	// 5 批 × 每批 400 条不同源端口的短连接：每批出现一轮后全部消失。
	const batches, perBatch = 5, 400
	peak := 0
	for b := 0; b < batches; b++ {
		flows = flows[:0]
		for i := 0; i < perBatch; i++ {
			flows = append(flows, connection.Flow{
				Proto: "tcp", State: "ESTABLISHED", OrigDstPort: 20000,
				SrcIP: "203.0.113." + strconv.Itoa(b+1), SrcPort: 20000 + i,
				Bytes: int64(100 + i),
			})
		}
		if err := svc.Reconcile(ctx); err != nil {
			t.Fatal(err)
		}
		if n := svc.FlowStateLen(); n > peak {
			peak = n
		}
		// 本批全部结束：conntrack 里不再出现。
		flows = flows[:0]
		if err := svc.Reconcile(ctx); err != nil {
			t.Fatal(err)
		}
		if n := svc.FlowStateLen(); n != 0 {
			t.Fatalf("第 %d 批短连接消失后 flow 表应回落到 0，实际 %d", b, n)
		}
	}
	if peak > perBatch+10 {
		t.Fatalf("flow 表峰值不应超过单批规模，实际 %d", peak)
	}
	if n := svc.FlowStateLen(); n != 0 {
		t.Fatalf("全部结束后 flow 表应为空，实际 %d", n)
	}
}

// TestFlowStateDoesNotDropActiveFlows GC 不得误删仍活跃的流。
func TestFlowStateDoesNotDropActiveFlows(t *testing.T) {
	svc, store, _ := newTestService(t)
	addRule(t, store, &forward.Rule{
		Name: "r1", Enabled: true, Protocol: "tcp",
		ListenPort: 20000, TargetAddress: "10.0.0.2", TargetPort: 80,
	})

	// 一条长连接 + 每轮换一批短连接。
	long := connection.Flow{Proto: "tcp", State: "ESTABLISHED", OrigDstPort: 20000,
		SrcIP: "203.0.113.1", SrcPort: 1000, Bytes: 1000}
	var flows []connection.Flow
	svc.SetConntrack(func(string) connection.Result {
		return connection.Result{Available: true, Entries: len(flows) + 1, Flows: flows}
	})
	ctx := context.Background()
	for round := 0; round < 6; round++ {
		long.Bytes += 500 // 持续有流量
		flows = []connection.Flow{long}
		for i := 0; i < 50; i++ {
			flows = append(flows, connection.Flow{
				Proto: "tcp", State: "ESTABLISHED", OrigDstPort: 20000,
				SrcIP: "203.0.113.2", SrcPort: 30000 + round*100 + i, Bytes: int64(50 + i),
			})
		}
		if err := svc.Reconcile(ctx); err != nil {
			t.Fatal(err)
		}
	}
	// 只剩长连接。
	flows = []connection.Flow{long}
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if n := svc.FlowStateLen(); n != 1 {
		t.Fatalf("应只剩 1 条活跃流状态，实际 %d", n)
	}
	// 长连接仍在线。
	states := svc.States()
	for _, st := range states {
		if st.IPs.GrantedCount == 0 {
			t.Fatal("活跃长连接被误判离线")
		}
	}
}

// TestIdleFlowStillEventuallyOffline 空闲流超窗后必须真的离线。
//
// 旧实现在超窗时删除 entry，下一轮同一条流又被当成「首次见到」判定为有流量，
// 结果空闲连接永远在线。修复后 entry 保留、只按 LastChange 判活。
func TestIdleFlowStillEventuallyOffline(t *testing.T) {
	svc, store, _ := newTestService(t)
	id := addRule(t, store, &forward.Rule{
		Name: "r1", Enabled: true, Protocol: "tcp",
		ListenPort: 20000, TargetAddress: "10.0.0.2", TargetPort: 80,
	})
	svc.SetIPIdle(30 * time.Second)
	base := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	clock := base
	svc.SetClock(func() time.Time { return clock })
	// 字节恒定不变的一条流（连接还在 conntrack 里，但没有任何流量）。
	svc.SetConntrack(func(string) connection.Result {
		return connection.Result{Available: true, Entries: 1, Flows: []connection.Flow{
			{Proto: "tcp", State: "ESTABLISHED", OrigDstPort: 20000,
				SrcIP: "203.0.113.7", SrcPort: 5000, Bytes: 777},
		}}
	})
	ctx := context.Background()
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if svc.StateOf(id).IPs.GrantedCount != 1 {
		t.Fatal("首轮应在线")
	}
	// 窗口内多轮：仍在线。
	for i := 1; i <= 3; i++ {
		clock = base.Add(time.Duration(i) * 5 * time.Second)
		if err := svc.Reconcile(ctx); err != nil {
			t.Fatal(err)
		}
		if svc.StateOf(id).IPs.GrantedCount != 1 {
			t.Fatalf("第 %d 轮（窗口内）应仍在线", i)
		}
	}
	// 超窗：必须离线。
	clock = base.Add(90 * time.Second)
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if got := svc.StateOf(id).IPs.GrantedCount; got != 0 {
		t.Fatalf("空闲超过 ipIdle 应离线，实际 %d", got)
	}
}

// TestManyRulesManyFlowsScales 大量规则 + 大量 flow 时一轮 reconcile 不应退化。
//
// 复杂度从 O(R×F) 降到 O(R+F) 的行为验证：200 条规则 × 4000 条流，
// 一轮必须在合理时间内完成（旧实现是 80 万次比较）。
func TestManyRulesManyFlowsScales(t *testing.T) {
	svc, store, _ := newTestService(t)
	const rules, flowsPerRule = 200, 20
	for i := 0; i < rules; i++ {
		addRule(t, store, &forward.Rule{
			Name: "r" + strconv.Itoa(i), Enabled: true, Protocol: "tcp",
			ListenPort: 20000 + i, TargetAddress: "10.0.0.2", TargetPort: 80,
		})
	}
	var flows []connection.Flow
	for i := 0; i < rules; i++ {
		for j := 0; j < flowsPerRule; j++ {
			flows = append(flows, connection.Flow{
				Proto: "tcp", State: "ESTABLISHED", OrigDstPort: 20000 + i,
				SrcIP:   "203.0." + strconv.Itoa(i%250+1) + "." + strconv.Itoa(j%250+1),
				SrcPort: 40000 + j, Bytes: int64(1000 + j),
			})
		}
	}
	svc.SetConntrack(func(string) connection.Result {
		return connection.Result{Available: true, Entries: len(flows), Flows: flows}
	})
	ctx := context.Background()
	start := time.Now()
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)
	if elapsed > 20*time.Second {
		t.Fatalf("200 规则 × %d 流一轮耗时 %v，疑似退化", rules*flowsPerRule, elapsed)
	}
	if n := svc.FlowStateLen(); n != rules*flowsPerRule {
		t.Fatalf("flow 状态数应等于流数，实际 %d", n)
	}
}

// BenchmarkReconcileManyRulesFlows 给出 reconcile 在大规模下的基准。
func BenchmarkReconcileManyRulesFlows(b *testing.B) {
	t := &testing.T{}
	svc, store, _ := newTestService(t)
	const rules, flowsPerRule = 100, 20
	for i := 0; i < rules; i++ {
		if _, err := store.Create(context.Background(), &forward.Rule{
			Name: "r" + strconv.Itoa(i), Enabled: true, Protocol: "tcp",
			ListenPort: 20000 + i, TargetAddress: "10.0.0.2", TargetPort: 80,
		}); err != nil {
			b.Fatal(err)
		}
	}
	var flows []connection.Flow
	for i := 0; i < rules; i++ {
		for j := 0; j < flowsPerRule; j++ {
			flows = append(flows, connection.Flow{
				Proto: "tcp", State: "ESTABLISHED", OrigDstPort: 20000 + i,
				SrcIP:   "203.0." + strconv.Itoa(i%250+1) + "." + strconv.Itoa(j%250+1),
				SrcPort: 40000 + j, Bytes: int64(1000 + j),
			})
		}
	}
	svc.SetConntrack(func(string) connection.Result {
		return connection.Result{Available: true, Entries: len(flows), Flows: flows}
	})
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := svc.Reconcile(ctx); err != nil {
			b.Fatal(err)
		}
	}
}

// TestQuotaUsesLiveDeltaNotOnlySQLite 配额必须计入尚未落库的 nft counter 增量。
//
// 场景：SQLite 里只记了 100 字节（collector 上一轮刷的），但 nft counter 已经
// 涨到 5000 —— 真实用量早已超过 1000 的配额。旧实现只看 SQLite，会一直放行到
// 下次刷盘（高带宽下就是几百 MB 超额）。
func TestQuotaUsesLiveDeltaNotOnlySQLite(t *testing.T) {
	svc, store, fake := newTestService(t)
	id := addRule(t, store, &forward.Rule{
		Name: "r1", Enabled: true, Protocol: "tcp",
		ListenPort: 20000, TargetAddress: "10.0.0.2", TargetPort: 80,
		QuotaEnabled: true, QuotaLimitBytes: 1000,
	})
	ctx := context.Background()
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}

	// 已落库：50 + 50 = 100 字节，counter 基线同为 50/50。
	if _, err := svc.db.Exec(
		"INSERT INTO traffic_totals(rule_id,upload_bytes,download_bytes) VALUES(?,?,?)",
		id, 50, 50); err != nil {
		t.Fatal(err)
	}
	up, down := counterNames(id)
	fake.bumpCounter(up, 50)
	fake.bumpCounter(down, 50)
	svc.SetQuotaSource(func() traffic.LiveDelta {
		return traffic.LiveDelta{
			Ready:     true,
			Committed: map[int64]int64{id: 100},
			Baseline:  map[string]int64{up: 50, down: 50},
		}
	})
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if st := svc.StateOf(id); st.Quota.State != "ok" {
		t.Fatalf("100/1000 不应超限，实际 %+v", st.Quota)
	}

	// 高带宽突发：counter 直冲 5000，SQLite 仍是 100。
	fake.bumpCounter(up, 2500)
	fake.bumpCounter(down, 2400)
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	st := svc.StateOf(id)
	if st.Quota.State != "exceeded" {
		t.Fatalf("实时用量已超配额，必须立即判 exceeded（实际 %+v）", st.Quota)
	}
	if st.Quota.UsedBytes < 5000 {
		t.Fatalf("已用字节应含未落库增量，实际 %d", st.Quota.UsedBytes)
	}
	if got := fake.elementsOf("inet", "nff_filter", "nff_filter_qblock"); len(got) != 1 {
		t.Fatalf("应立即下发配额阻断元素，实际 %v", got)
	}
}

// TestQuotaResetBaselineRespectedWithLiveDelta 重置配额后实时判定同样按新基线计算。
func TestQuotaResetBaselineRespectedWithLiveDelta(t *testing.T) {
	svc, store, fake := newTestService(t)
	id := addRule(t, store, &forward.Rule{
		Name: "r1", Enabled: true, Protocol: "tcp",
		ListenPort: 20000, TargetAddress: "10.0.0.2", TargetPort: 80,
		QuotaEnabled: true, QuotaLimitBytes: 1000,
		QuotaResetBaseline: 5000, // 用户已重置：前 5000 字节不算
	})
	ctx := context.Background()
	up, down := counterNames(id)
	fake.bumpCounter(up, 3000)
	fake.bumpCounter(down, 2200)
	svc.SetQuotaSource(func() traffic.LiveDelta {
		return traffic.LiveDelta{
			Ready:     true,
			Committed: map[int64]int64{id: 0},
			Baseline:  map[string]int64{up: 0, down: 0},
		}
	})
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	st := svc.StateOf(id)
	// 实时总量 5200，减去基线 5000 = 200 → 未超 1000。
	if st.Quota.UsedBytes != 200 {
		t.Fatalf("已用应为 200（5200-5000），实际 %d", st.Quota.UsedBytes)
	}
	if st.Quota.State != "ok" {
		t.Fatalf("不应超限，实际 %s", st.Quota.State)
	}
}

// counterNames 返回某规则的 up/down counter 名。
func counterNames(id int64) (string, string) {
	return "nff_filter_up_" + strconv.FormatInt(id, 10),
		"nff_filter_down_" + strconv.FormatInt(id, 10)
}

// ★ 配额重置必须与配额判定同口径（v0.3.2）。
//
// 重置的实现是 QuotaResetBaseline = 当时的累计总量，之后 used = 总量 - baseline。
// 若 baseline 只取 SQLite 里的数字、而 used 用实时口径，重置瞬间「尚未落库的
// 那部分字节」会立刻重新算成已用 —— 用户点了重置却看到用量不为 0，
// 高带宽下甚至会立刻又被阻断。
func TestLifetimeUsesRealtimeTotal(t *testing.T) {
	svc, store, fake := newTestService(t)
	id := addRule(t, store, &forward.Rule{
		Name: "r1", Enabled: true, Protocol: forward.ProtoTCP,
		ListenPort: 20000, TargetAddress: "10.0.0.2", TargetPort: 80,
		QuotaEnabled: true, QuotaLimitBytes: 100 << 20,
	})
	ctx := context.Background()
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}

	// 已落库 1000；nft counter 已涨到 1000 + 50000（未落库）。
	if _, err := svc.db.Exec(
		"INSERT INTO traffic_totals(rule_id,upload_bytes,download_bytes) VALUES(?,?,?)",
		id, 600, 400); err != nil {
		t.Fatal(err)
	}
	up, down := counterNames(id)
	fake.bumpCounter(up, 600+30000)
	fake.bumpCounter(down, 400+20000)
	svc.SetQuotaSource(func() traffic.LiveDelta {
		return traffic.LiveDelta{
			Ready:     true,
			Committed: map[int64]int64{id: 1000},
			Baseline:  map[string]int64{up: 600, down: 400},
		}
	})
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}

	st := svc.StateOf(id)
	if st.Quota.UsedBytes != 51000 {
		t.Fatalf("实时已用应为 1000+50000=51000，实际 %d", st.Quota.UsedBytes)
	}

	// Lifetime（重置基线来源）必须给出同样的实时总量，而不是库里的 1000。
	life, err := svc.Lifetime(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if life != 51000 {
		t.Fatalf("Lifetime 应返回实时总量 51000（否则重置后未落库部分会重新计入），实际 %d", life)
	}

	// 模拟重置：baseline = life，随后同一轮读数下已用必须归零。
	r, err := store.Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	r.QuotaResetBaseline = life
	if err := store.Update(ctx, r); err != nil {
		t.Fatal(err)
	}
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if got := svc.StateOf(id).Quota.UsedBytes; got != 0 {
		t.Fatalf("重置后已用应为 0，实际 %d（未落库部分被重新计入）", got)
	}
	if svc.StateOf(id).Quota.State == "exceeded" {
		t.Fatal("重置后不应仍处于超限状态")
	}
}

// 首轮 reconcile 之前 Lifetime 退回 SQLite 口径（没有实时数据可用）。
func TestLifetimeFallsBackBeforeFirstReconcile(t *testing.T) {
	svc, store, _ := newTestService(t)
	id := addRule(t, store, &forward.Rule{
		Name: "r1", Enabled: true, Protocol: forward.ProtoTCP,
		ListenPort: 20000, TargetAddress: "10.0.0.2", TargetPort: 80,
	})
	if _, err := svc.db.Exec(
		"INSERT INTO traffic_totals(rule_id,upload_bytes,download_bytes) VALUES(?,?,?)",
		id, 700, 300); err != nil {
		t.Fatal(err)
	}
	life, err := svc.Lifetime(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if life != 1000 {
		t.Fatalf("首轮前应返回库内累计 1000，实际 %d", life)
	}
}
