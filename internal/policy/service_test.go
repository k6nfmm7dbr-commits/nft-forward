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

// applyRecorder 记录每次 nft 应用的脚本，用于断言「结构未变时不重写链」。
type applyRecorder struct {
	scripts []string
}

func (a *applyRecorder) apply(ctx context.Context, r nft.Runner, path, script string) error {
	a.scripts = append(a.scripts, script)
	return nil
}

func (a *applyRecorder) structRebuilds() int {
	n := 0
	for _, s := range a.scripts {
		if strings.Contains(s, "flush chain") {
			n++
		}
	}
	return n
}

func (a *applyRecorder) elementOps() int {
	n := 0
	for _, s := range a.scripts {
		if strings.Contains(s, "element") && !strings.Contains(s, "flush chain") {
			n++
		}
	}
	return n
}

func testDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := database.Open(t.TempDir() + "/t.db")
	if err != nil {
		t.Fatalf("打开测试库失败: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db.DB
}

func newTestService(t *testing.T, rec *applyRecorder, state *nft.State) (*Service, *forward.Store) {
	t.Helper()
	db := testDB(t)
	store := forward.NewStore(db)
	svc := New(db, store, nil, t.TempDir()+"/nft.conf", "")
	svc.SetNFTApply(rec.apply)
	svc.SetNFTReadState(func(ctx context.Context, r nft.Runner) (*nft.State, error) {
		return state, nil
	})
	svc.SetConntrack(func(string) connection.Result {
		return connection.Result{Available: true}
	})
	return svc, store
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
	rec := &applyRecorder{}
	state := &nft.State{SetElements: map[string][]string{}}
	svc, store := newTestService(t, rec, state)
	addRule(t, store, &forward.Rule{
		Name: "r1", Enabled: true, Protocol: "tcp",
		ListenAddress: "0.0.0.0", ListenPort: 20000,
		TargetAddress: "10.0.0.2", TargetPort: 80,
	})

	ctx := context.Background()
	for i := 0; i < 10; i++ {
		// 首轮之后模拟表已建立。
		if i == 1 {
			state.FilterTableExists = true
			state.Counters = []string{nft.CounterUp(1), nft.CounterDown(1)}
		}
		if err := svc.Reconcile(ctx); err != nil {
			t.Fatalf("第 %d 轮 reconcile 失败: %v", i, err)
		}
	}
	if got := rec.structRebuilds(); got != 1 {
		t.Fatalf("10 轮 reconcile 只应重建结构 1 次（首轮），实际 %d 次 —— 会清零流量 counter", got)
	}
}

// 结构真的变化时必须重建。
func TestStructChangeTriggersRebuild(t *testing.T) {
	rec := &applyRecorder{}
	state := &nft.State{SetElements: map[string][]string{}}
	svc, store := newTestService(t, rec, state)
	id := addRule(t, store, &forward.Rule{
		Name: "r1", Enabled: true, Protocol: "tcp",
		ListenAddress: "0.0.0.0", ListenPort: 20000,
		TargetAddress: "10.0.0.2", TargetPort: 80,
	})
	ctx := context.Background()
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	state.FilterTableExists = true
	state.Counters = []string{nft.CounterUp(id), nft.CounterDown(id)}
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	before := rec.structRebuilds()

	// 改监听端口 → 结构变化。
	r, _ := store.Get(ctx, id)
	r.ListenPort = 20001
	if err := store.Update(ctx, r); err != nil {
		t.Fatal(err)
	}
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if rec.structRebuilds() != before+1 {
		t.Fatal("结构变化应触发一次重建")
	}
}

// 配额从 ok 翻到 exceeded 只应产生元素操作，不得重建结构。
func TestQuotaFlipUsesElementsOnly(t *testing.T) {
	rec := &applyRecorder{}
	state := &nft.State{SetElements: map[string][]string{}}
	svc, store := newTestService(t, rec, state)
	id := addRule(t, store, &forward.Rule{
		Name: "r1", Enabled: true, Protocol: "tcp",
		ListenAddress: "0.0.0.0", ListenPort: 20000,
		TargetAddress: "10.0.0.2", TargetPort: 80,
		QuotaEnabled: true, QuotaLimitBytes: 1000,
	})
	ctx := context.Background()
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	state.FilterTableExists = true
	state.Counters = []string{nft.CounterUp(id), nft.CounterDown(id)}
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}

	// 写入超额流量。
	if _, err := svc.db.Exec(
		"INSERT INTO traffic_totals(rule_id,upload_bytes,download_bytes) VALUES(?,?,?)",
		id, 800, 800); err != nil {
		t.Fatal(err)
	}
	rec.scripts = nil
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if rec.structRebuilds() != 0 {
		t.Fatal("配额翻转不应重建结构（会清零 counter）")
	}
	if rec.elementOps() == 0 {
		t.Fatal("配额翻转应产生 qblock 元素操作")
	}
	st := svc.StateOf(id)
	if st == nil || st.Quota.State != "exceeded" {
		t.Fatalf("配额应判定为 exceeded，实际 %+v", st)
	}
}

// 在线 IP 变化只走元素增量。
func TestIPChangeUsesElementsOnly(t *testing.T) {
	rec := &applyRecorder{}
	state := &nft.State{FilterTableExists: true, SetElements: map[string][]string{}}
	svc, store := newTestService(t, rec, state)
	id := addRule(t, store, &forward.Rule{
		Name: "r1", Enabled: true, Protocol: "tcp",
		ListenAddress: "0.0.0.0", ListenPort: 20000,
		TargetAddress: "10.0.0.2", TargetPort: 80,
		IPLimitEnabled: true, IPLimitMax: 3,
	})
	state.Counters = []string{nft.CounterUp(id), nft.CounterDown(id)}
	state.Sets = []string{nft.AllowSetV4(id), nft.AllowSetV6(id), nft.SetQuotaBlock}

	flows := []connection.Flow{}
	svc.SetConntrack(func(string) connection.Result {
		return connection.Result{Available: true, Flows: flows}
	})
	ctx := context.Background()
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	rec.scripts = nil

	// 新 IP 上线。
	flows = []connection.Flow{
		{Proto: "tcp", State: "ESTABLISHED", OrigDstPort: 20000, SrcIP: "203.0.113.5", SrcPort: 5000, Bytes: 100},
	}
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if rec.structRebuilds() != 0 {
		t.Fatal("IP 上线不应重建结构")
	}
	found := false
	for _, s := range rec.scripts {
		if strings.Contains(s, "add element") && strings.Contains(s, "203.0.113.5") {
			found = true
		}
	}
	if !found {
		t.Fatalf("应通过 add element 加入 allow set，实际脚本: %v", rec.scripts)
	}
}

// conntrack 读取不完整时进入 fail-safe：不改 nft、不释放 slot。
func TestPartialConntrackFailSafe(t *testing.T) {
	rec := &applyRecorder{}
	state := &nft.State{FilterTableExists: true, SetElements: map[string][]string{}}
	svc, store := newTestService(t, rec, state)
	id := addRule(t, store, &forward.Rule{
		Name: "r1", Enabled: true, Protocol: "tcp",
		ListenAddress: "0.0.0.0", ListenPort: 20000,
		TargetAddress: "10.0.0.2", TargetPort: 80,
		IPLimitEnabled: true, IPLimitMax: 2,
	})
	state.Counters = []string{nft.CounterUp(id), nft.CounterDown(id)}
	svc.SetConntrack(func(string) connection.Result {
		return connection.Result{Available: true, Flows: []connection.Flow{
			{Proto: "tcp", State: "ESTABLISHED", OrigDstPort: 20000, SrcIP: "203.0.113.5", SrcPort: 5000, Bytes: 100},
		}}
	})
	ctx := context.Background()
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	granted := svc.StateOf(id).IPs.GrantedCount
	if granted != 1 {
		t.Fatalf("应有 1 个授权 IP，实际 %d", granted)
	}

	// conntrack 读取失败（不完整）。
	rec.scripts = nil
	svc.SetConntrack(func(string) connection.Result {
		return connection.Result{Available: false, Partial: true, Err: context.DeadlineExceeded}
	})
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatalf("fail-safe 不应返回错误: %v", err)
	}
	if len(rec.scripts) != 0 {
		t.Fatal("conntrack 不完整时不应改动 nft")
	}
	if svc.StateOf(id).IPs.GrantedCount != 1 {
		t.Fatal("fail-safe 期间不得释放已授权 slot（会误踢在线用户）")
	}
}

// UDP 用 udpIdle 判活；TCP 用 ipIdle。
func TestUDPUsesLongerIdleWindow(t *testing.T) {
	rec := &applyRecorder{}
	state := &nft.State{FilterTableExists: true, SetElements: map[string][]string{}}
	svc, store := newTestService(t, rec, state)
	id := addRule(t, store, &forward.Rule{
		Name: "r1", Enabled: true, Protocol: "udp",
		ListenAddress: "0.0.0.0", ListenPort: 20000,
		TargetAddress: "10.0.0.2", TargetPort: 80,
	})
	state.Counters = []string{nft.CounterUp(id), nft.CounterDown(id)}
	svc.SetIPIdle(10 * time.Second)
	svc.SetUDPIdle(120 * time.Second)

	base := time.Date(2026, 8, 29, 10, 0, 0, 0, time.UTC)
	clock := base
	svc.SetClock(func() time.Time { return clock })
	svc.SetConntrack(func(string) connection.Result {
		return connection.Result{Available: true, Flows: []connection.Flow{
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
	rec := &applyRecorder{}
	state := &nft.State{FilterTableExists: true, SetElements: map[string][]string{}}
	svc, store := newTestService(t, rec, state)
	id := addRule(t, store, &forward.Rule{
		Name: "r1", Enabled: true, Protocol: "tcp+udp",
		ListenAddress: "0.0.0.0", ListenPort: 20000,
		TargetAddress: "10.0.0.2", TargetPort: 80,
	})
	state.Counters = []string{nft.CounterUp(id), nft.CounterDown(id)}
	svc.SetConntrack(func(string) connection.Result {
		return connection.Result{Available: true, Flows: []connection.Flow{
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
	rec := &applyRecorder{}
	state := &nft.State{FilterTableExists: true, SetElements: map[string][]string{}}
	svc, store := newTestService(t, rec, state)
	id := addRule(t, store, &forward.Rule{
		Name: "r1", Enabled: true, Protocol: "tcp",
		ListenAddress: "0.0.0.0", ListenPort: 20000,
		TargetAddress: "10.0.0.2", TargetPort: 80,
	})
	state.Counters = []string{nft.CounterUp(id), nft.CounterDown(id)}
	svc.SetConntrack(func(string) connection.Result {
		return connection.Result{Available: true, Flows: []connection.Flow{
			{Proto: "tcp", State: "ESTABLISHED", OrigDstPort: 20000, SrcIP: "203.0.113.5", SrcPort: 5000, Bytes: 100},
		}}
	})
	ctx := context.Background()
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if len(svc.flows) == 0 {
		t.Fatal("应有流跟踪记录")
	}
	if err := store.SoftDelete(ctx, id); err != nil {
		t.Fatal(err)
	}
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if len(svc.flows) != 0 {
		t.Fatalf("规则删除后应清理流跟踪，剩余 %d", len(svc.flows))
	}
}
