package policy

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/k6nfmm7dbr-commits/nft-forward/internal/connection"
	"github.com/k6nfmm7dbr-commits/nft-forward/internal/database"
	"github.com/k6nfmm7dbr-commits/nft-forward/internal/forward"
	"github.com/k6nfmm7dbr-commits/nft-forward/internal/nft"
)

func testDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := database.Open(t.TempDir() + "/t.db")
	if err != nil {
		t.Fatalf("打开测试库失败: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db.DB
}

// newTestService 构造带 nft 模拟器的策略服务。
//
// 模拟器会真的维护表/链/set/counter 的存在性与 counter 值，因此
// 「稳定期不重建」「删对象后自愈」「元素增量不碰链」都能被真实断言。
func newTestService(t *testing.T) (*Service, *forward.Store, *fakeNFT) {
	t.Helper()
	db := testDB(t)
	store := forward.NewStore(db)
	fake := newFakeNFT()
	svc := New(db, store, nil, t.TempDir()+"/nft.conf", "")
	svc.SetNFTApply(fake.apply)
	svc.SetNFTReadState(fake.readState)
	svc.SetConntrack(func(string) connection.Result {
		// 默认：conntrack 可用且当前无流（Complete 由 Partial/Err 派生）。
		return connection.Result{Available: true, Entries: 1}
	})
	svc.SetLocalIPs(func() (map[string]bool, error) {
		return map[string]bool{"127.0.0.1": true}, nil
	})
	return svc, store, fake
}

func addRule(t *testing.T, store *forward.Store, r *forward.Rule) int64 {
	t.Helper()
	id, err := store.Create(context.Background(), r)
	if err != nil {
		t.Fatalf("创建规则失败: %v", err)
	}
	return id
}

// ★ 本项目最关键的回归测试：多轮 reconcile 不得反复重建结构。
// 曾经的 bug：每轮都 delete+create table，导致 counter 被清零、流量几乎全丢。
func TestRepeatedReconcileDoesNotRebuildStructure(t *testing.T) {
	svc, store, fake := newTestService(t)
	id := addRule(t, store, &forward.Rule{
		Name: "r1", Enabled: true, Protocol: "tcp",
		ListenPort:    20000,
		TargetAddress: "10.0.0.2", TargetPort: 80,
	})

	ctx := context.Background()
	for i := 0; i < 10; i++ {
		if err := svc.Reconcile(ctx); err != nil {
			t.Fatalf("第 %d 轮 reconcile 失败: %v", i, err)
		}
		if i == 0 {
			// 首轮建好结构后灌入流量，验证后续轮次不会清零。
			fake.bumpCounter(nft.CounterUp(id), 123456)
			fake.bumpCounter(nft.CounterDown(id), 654321)
		}
	}
	if got := fake.structRebuilds(); got != 1 {
		t.Fatalf("10 轮 reconcile 只应重建结构 1 次（首轮），实际 %d 次 —— 会清零流量 counter", got)
	}
	if v := fake.counterOf(nft.CounterUp(id)); v != 123456 {
		t.Fatalf("upload counter 被改动: %d", v)
	}
	if v := fake.counterOf(nft.CounterDown(id)); v != 654321 {
		t.Fatalf("download counter 被改动: %d", v)
	}
}

// 结构真的变化时必须重建。
func TestStructChangeTriggersRebuild(t *testing.T) {
	svc, store, fake := newTestService(t)
	id := addRule(t, store, &forward.Rule{
		Name: "r1", Enabled: true, Protocol: "tcp",
		ListenPort:    20000,
		TargetAddress: "10.0.0.2", TargetPort: 80,
	})
	ctx := context.Background()
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	before := fake.structRebuilds()

	// 改监听端口 → 结构变化。
	r, _ := store.Get(ctx, id)
	r.ListenPort = 20001
	if err := store.Update(ctx, r); err != nil {
		t.Fatal(err)
	}
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if fake.structRebuilds() != before+1 {
		t.Fatal("结构变化应触发一次重建")
	}
}

// 配额从 ok 翻到 exceeded 只应产生元素操作，不得重建结构。
func TestQuotaFlipUsesElementsOnly(t *testing.T) {
	svc, store, fake := newTestService(t)
	id := addRule(t, store, &forward.Rule{
		Name: "r1", Enabled: true, Protocol: "tcp",
		ListenPort:    20000,
		TargetAddress: "10.0.0.2", TargetPort: 80,
		QuotaEnabled: true, QuotaLimitBytes: 1000,
	})
	ctx := context.Background()
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}

	// 写入超额流量。
	if _, err := svc.db.Exec(
		"INSERT INTO traffic_totals(rule_id,upload_bytes,download_bytes) VALUES(?,?,?)",
		id, 800, 800); err != nil {
		t.Fatal(err)
	}
	fake.resetScripts()
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if fake.structRebuilds() != 0 {
		t.Fatal("配额翻转不应重建结构（会清零 counter）")
	}
	if fake.elementOps() == 0 {
		t.Fatal("配额翻转应产生 qblock 元素操作")
	}
	st := svc.StateOf(id)
	if st == nil || st.Quota.State != "exceeded" {
		t.Fatalf("配额应判定为 exceeded，实际 %+v", st)
	}
	if got := fake.elementsOf("inet", nft.TableFilter, nft.SetQuotaBlock); len(got) != 1 {
		t.Fatalf("qblock 应含该规则 ID，实际 %v", got)
	}
}

// 在线 IP 变化只走元素增量。
func TestIPChangeUsesElementsOnly(t *testing.T) {
	svc, store, fake := newTestService(t)
	id := addRule(t, store, &forward.Rule{
		Name: "r1", Enabled: true, Protocol: "tcp",
		ListenPort:    20000,
		TargetAddress: "10.0.0.2", TargetPort: 80,
		IPLimitEnabled: true, IPLimitMax: 3,
	})

	flows := []connection.Flow{}
	svc.SetConntrack(func(string) connection.Result {
		return connection.Result{Available: true, Entries: 1, Flows: flows}
	})
	ctx := context.Background()
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	fake.resetScripts()

	// 新 IP 上线。
	flows = []connection.Flow{
		{Proto: "tcp", State: "ESTABLISHED", OrigDstPort: 20000, SrcIP: "203.0.113.5", SrcPort: 5000, Bytes: 100},
	}
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if fake.structRebuilds() != 0 {
		t.Fatal("IP 上线不应重建结构")
	}
	found := false
	for _, s := range fake.allScripts() {
		if strings.Contains(s, "add element") && strings.Contains(s, "203.0.113.5") {
			found = true
		}
	}
	if !found {
		t.Fatalf("应通过 add element 加入 allow set，实际脚本: %v", fake.allScripts())
	}
	if got := fake.elementsOf("inet", nft.TableFilter, nft.AllowSetV4(id)); len(got) != 1 || got[0] != "203.0.113.5" {
		t.Fatalf("allow set 元素错误: %v", got)
	}
}

// UDP 用 udpIdle 判活；TCP 用 ipIdle。
func TestUDPUsesLongerIdleWindow(t *testing.T) {
	svc, store, _ := newTestService(t)
	id := addRule(t, store, &forward.Rule{
		Name: "r1", Enabled: true, Protocol: "udp",
		ListenPort:    20000,
		TargetAddress: "10.0.0.2", TargetPort: 80,
	})
	svc.SetIPIdle(10 * time.Second)
	svc.SetUDPIdle(120 * time.Second)

	base := time.Date(2026, 8, 29, 10, 0, 0, 0, time.UTC)
	clock := base
	svc.SetClock(func() time.Time { return clock })
	svc.SetConntrack(func(string) connection.Result {
		return connection.Result{Available: true, Entries: 1, Flows: []connection.Flow{
			{Proto: "udp", State: "udp", OrigDstPort: 20000, SrcIP: "203.0.113.9", SrcPort: 6000, Bytes: 50},
		}}
	})
	ctx := context.Background()
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if svc.StateOf(id).ConnUDP != 1 {
		t.Fatalf("应统计 1 个 UDP 会话，实际 %d", svc.StateOf(id).ConnUDP)
	}

	// 过 60 秒（> ipIdle 10s，< udpIdle 120s）且字节不变 → UDP 仍应在线。
	clock = base.Add(60 * time.Second)
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if svc.StateOf(id).IPs.GrantedCount != 1 {
		t.Fatal("UDP 在 udpIdle 窗口内应保持在线")
	}

	// 过 200 秒 → 超 udpIdle，应离线。
	clock = base.Add(200 * time.Second)
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if svc.StateOf(id).IPs.GrantedCount != 0 {
		t.Fatal("UDP 超 udpIdle 应离线")
	}
}

// TCP 连接数与 UDP 会话数应真实上报（此前恒为 0）。
func TestConnCountsReported(t *testing.T) {
	svc, store, _ := newTestService(t)
	id := addRule(t, store, &forward.Rule{
		Name: "r1", Enabled: true, Protocol: "tcp+udp",
		ListenPort:    20000,
		TargetAddress: "10.0.0.2", TargetPort: 80,
	})
	svc.SetConntrack(func(string) connection.Result {
		return connection.Result{Available: true, Entries: 3, Flows: []connection.Flow{
			{Proto: "tcp", State: "ESTABLISHED", OrigDstPort: 20000, SrcIP: "203.0.113.5", SrcPort: 5000, Bytes: 100},
			{Proto: "tcp", State: "ESTABLISHED", OrigDstPort: 20000, SrcIP: "203.0.113.5", SrcPort: 5001, Bytes: 200},
			{Proto: "udp", State: "udp", OrigDstPort: 20000, SrcIP: "203.0.113.5", SrcPort: 6000, Bytes: 50},
		}}
	})
	if err := svc.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	st := svc.StateOf(id)
	if st.ConnTCP != 2 {
		t.Fatalf("应统计 2 个 TCP 连接，实际 %d", st.ConnTCP)
	}
	if st.ConnUDP != 1 {
		t.Fatalf("应统计 1 个 UDP 会话，实际 %d", st.ConnUDP)
	}
	if st.IPs.GrantedCount != 1 {
		t.Fatalf("同一 IP 多连接应只算 1 个在线，实际 %d", st.IPs.GrantedCount)
	}
}

// 规则删除后流跟踪状态应被清理（避免内存泄漏）。
func TestDeletedRuleFlowsCleaned(t *testing.T) {
	svc, store, _ := newTestService(t)
	id := addRule(t, store, &forward.Rule{
		Name: "r1", Enabled: true, Protocol: "tcp",
		ListenPort:    20000,
		TargetAddress: "10.0.0.2", TargetPort: 80,
	})
	svc.SetConntrack(func(string) connection.Result {
		return connection.Result{Available: true, Entries: 1, Flows: []connection.Flow{
			{Proto: "tcp", State: "ESTABLISHED", OrigDstPort: 20000, SrcIP: "203.0.113.5", SrcPort: 5000, Bytes: 100},
		}}
	})
	ctx := context.Background()
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if svc.FlowStateLen() == 0 {
		t.Fatal("应有流跟踪记录")
	}
	if err := store.SoftDelete(ctx, id); err != nil {
		t.Fatal(err)
	}
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if n := svc.FlowStateLen(); n != 0 {
		t.Fatalf("规则删除后应清理流跟踪，剩余 %d", n)
	}
}
