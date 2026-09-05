package policy

import (
	"context"
	"errors"
	"testing"

	"github.com/k6nfmm7dbr-commits/nft-forward/internal/connection"
	"github.com/k6nfmm7dbr-commits/nft-forward/internal/forward"
	"github.com/k6nfmm7dbr-commits/nft-forward/internal/nft"
)

// ipLimitRule 是一条启用 IP 限制的规则（fail-safe 测试共用）。
func ipLimitRule(port int, maxIPs int) *forward.Rule {
	return &forward.Rule{
		Name: "r", Enabled: true, Protocol: "tcp",
		ListenPort: port, TargetAddress: "10.0.0.2", TargetPort: 80,
		IPLimitEnabled: true, IPLimitMax: maxIPs,
	}
}

// oneFlow 返回一条 ESTABLISHED 流。
func oneFlow(port int, ip string, sport int, bytes int64) connection.Flow {
	return connection.Flow{Proto: "tcp", State: "ESTABLISHED",
		OrigDstPort: port, SrcIP: ip, SrcPort: sport, Bytes: bytes}
}

// grantAndFreeze 先让一个 IP 上线，再切到给定的「异常」conntrack 结果。
func grantAndFreeze(t *testing.T, bad connection.Result) (*Service, *forward.Store, *fakeNFT, int64) {
	t.Helper()
	svc, store, fake := newTestService(t)
	id := addRule(t, store, ipLimitRule(20000, 2))
	flows := []connection.Flow{oneFlow(20000, "203.0.113.5", 5000, 100)}
	svc.SetConntrack(func(string) connection.Result {
		return connection.Result{Available: true, Entries: 1, Flows: flows}
	})
	ctx := context.Background()
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if got := svc.StateOf(id).IPs.GrantedCount; got != 1 {
		t.Fatalf("前置条件失败：应有 1 个授权 IP，实际 %d", got)
	}
	svc.SetConntrack(func(string) connection.Result { return bad })
	fake.resetScripts()
	return svc, store, fake, id
}

// conntrack 读取不完整（Partial）时：不释放 slot、不清空 allow set。
func TestPartialConntrackKeepsSlots(t *testing.T) {
	svc, _, fake, id := grantAndFreeze(t, connection.Result{
		Available: false, Partial: true, Err: errors.New("read error")})
	if err := svc.Reconcile(context.Background()); err != nil {
		t.Fatalf("fail-safe 不应返回错误: %v", err)
	}
	if got := svc.StateOf(id).IPs.GrantedCount; got != 1 {
		t.Fatalf("Partial 时不得释放已授权 slot（会误踢在线用户），实际 %d", got)
	}
	if !svc.StateOf(id).IPs.Frozen {
		t.Fatal("应标记为冻结状态")
	}
	if got := fake.elementsOf("inet", nft.TableFilter, nft.AllowSetV4(id)); len(got) != 1 {
		t.Fatalf("allow set 不得被清空，实际 %v", got)
	}
	if !svc.HealthSnapshot().IPStateFrozen {
		t.Fatal("健康快照应报告冻结")
	}
}

// conntrack 完全不可用（文件不存在 / 模块未加载）时同样冻结。
func TestUnavailableConntrackKeepsSlots(t *testing.T) {
	svc, _, fake, id := grantAndFreeze(t, connection.Result{Available: false})
	if err := svc.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := svc.StateOf(id).IPs.GrantedCount; got != 1 {
		t.Fatalf("unavailable 时不得释放 slot，实际 %d", got)
	}
	if got := fake.elementsOf("inet", nft.TableFilter, nft.AllowSetV4(id)); len(got) != 1 {
		t.Fatalf("allow set 不得被清空，实际 %v", got)
	}
}

// conntrack 不可用时也**不得新增** slot（无法确认真实连接状态）。
func TestUnavailableConntrackDoesNotGrant(t *testing.T) {
	svc, store, fake := newTestService(t)
	id := addRule(t, store, ipLimitRule(20000, 2))
	// conntrack 不可用，但（假设）有流：不可用意味着这些流不可信，必须忽略。
	svc.SetConntrack(func(string) connection.Result {
		return connection.Result{Available: false, Inactive: true,
			Flows: []connection.Flow{oneFlow(20000, "203.0.113.9", 5100, 500)}}
	})
	if err := svc.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := svc.StateOf(id).IPs.GrantedCount; got != 0 {
		t.Fatalf("conntrack 不可用时不得新增 slot，实际 %d", got)
	}
	if got := fake.elementsOf("inet", nft.TableFilter, nft.AllowSetV4(id)); len(got) != 0 {
		t.Fatalf("allow set 不应有元素，实际 %v", got)
	}
}

// 只有「成功读取且真实为空」才允许释放 slot。
func TestSuccessfulEmptyConntrackReleasesSlots(t *testing.T) {
	svc, _, fake, id := grantAndFreeze(t, connection.Result{
		Available: true, Entries: 5, Flows: nil}) // 读取成功、无相关流
	if err := svc.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := svc.StateOf(id).IPs.GrantedCount; got != 0 {
		t.Fatalf("成功读取到 0 flows 时应释放 slot，实际 %d", got)
	}
	if svc.StateOf(id).IPs.Frozen {
		t.Fatal("正常读取不应标记冻结")
	}
	if got := fake.elementsOf("inet", nft.TableFilter, nft.AllowSetV4(id)); len(got) != 0 {
		t.Fatalf("allow set 应被清空，实际 %v", got)
	}
}

// ★ conntrack 异常期间规则 CRUD 必须真正改动 nft（不能假成功）。
//
// 这是旧实现最严重的缺陷：conntrack 异常 → sync 直接 return nil →
// nft 什么都没改 → DB 已删除 → API 返回成功 → 旧 DNAT 还在转发。
func TestRuleCRUDWorksWhileConntrackBroken(t *testing.T) {
	svc, store, fake := newTestService(t)
	svc.SetConntrack(func(string) connection.Result {
		return connection.Result{Available: false, Partial: true, Err: errors.New("boom")}
	})
	ctx := context.Background()

	// 新增规则：DNAT 必须真的下发。
	id := addRule(t, store, &forward.Rule{
		Name: "r1", Enabled: true, Protocol: "tcp",
		ListenPort: 20000, TargetAddress: "10.0.0.2", TargetPort: 80,
	})
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatalf("conntrack 异常不应让 reconcile 失败: %v", err)
	}
	if !fake.hasTable("ip", nft.TableNAT4) {
		t.Fatal("conntrack 异常时 DNAT 表仍必须建立")
	}
	if fake.ruleCount("ip", nft.TableNAT4, nft.ChainPrerouting(nft.TableNAT4)) == 0 {
		t.Fatal("conntrack 异常时 DNAT 规则仍必须下发")
	}
	if fake.counterOf(nft.CounterUp(id)) < 0 {
		t.Fatal("counter 必须建立")
	}

	// 删除规则：nft 侧必须真的撤销，绝不能「DB 删了 nft 还在」。
	if err := store.SoftDelete(ctx, id); err != nil {
		t.Fatal(err)
	}
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if n := fake.ruleCount("ip", nft.TableNAT4, nft.ChainPrerouting(nft.TableNAT4)); n != 0 {
		t.Fatalf("规则删除后 DNAT 必须被撤销，剩余 %d 条", n)
	}
	if fake.counterOf(nft.CounterUp(id)) >= 0 {
		t.Fatal("规则删除后遗留 counter 应被清理")
	}
}

// conntrack 异常期间配额判定与阻断仍然生效（A 层不依赖 conntrack）。
func TestQuotaEnforcedWhileConntrackBroken(t *testing.T) {
	svc, store, fake := newTestService(t)
	id := addRule(t, store, &forward.Rule{
		Name: "r1", Enabled: true, Protocol: "tcp",
		ListenPort: 20000, TargetAddress: "10.0.0.2", TargetPort: 80,
		QuotaEnabled: true, QuotaLimitBytes: 1000,
	})
	svc.SetConntrack(func(string) connection.Result {
		return connection.Result{Available: false, Partial: true, Err: errors.New("boom")}
	})
	ctx := context.Background()
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.db.Exec(
		"INSERT INTO traffic_totals(rule_id,upload_bytes,download_bytes) VALUES(?,?,?)",
		id, 900, 900); err != nil {
		t.Fatal(err)
	}
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	st := svc.StateOf(id)
	if st == nil || st.Quota.State != "exceeded" {
		t.Fatalf("conntrack 异常不应影响配额判定，实际 %+v", st)
	}
	if got := fake.elementsOf("inet", nft.TableFilter, nft.SetQuotaBlock); len(got) != 1 {
		t.Fatalf("配额阻断元素必须下发，实际 %v", got)
	}
}
