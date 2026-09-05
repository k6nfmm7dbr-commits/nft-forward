package policy

import (
	"context"
	"strings"
	"testing"

	"github.com/k6nfmm7dbr-commits/nft-forward/internal/connection"
	"github.com/k6nfmm7dbr-commits/nft-forward/internal/forward"
	"github.com/k6nfmm7dbr-commits/nft-forward/internal/nft"
)

// healSetup 建立一条双栈域名规则 + IP 限制的完整对象集合，用于自愈破坏测试。
//
// 选双栈域名规则的原因：一次性覆盖 nff_nat4 / nff_nat6 / nff_filter 三张表、
// 各自的链与 set、以及 up/down counter 与 v4/v6 allow set。
func healSetup(t *testing.T) (*Service, *forward.Store, *fakeNFT, int64) {
	t.Helper()
	svc, store, fake := newTestService(t)
	id := addRule(t, store, &forward.Rule{
		Name: "dual", Enabled: true, Protocol: "tcp+udp",
		ListenPort: 20000, TargetAddress: "dual.example.com", TargetPort: 443,
		ResolvedV4: "1.2.3.4", ResolvedV6: "2001:db8::1",
		ResolveStatus:  forward.ResolveOK,
		IPLimitEnabled: true, IPLimitMax: 2,
	})
	svc.SetConntrack(func(string) connection.Result {
		return connection.Result{Available: true, Entries: 1, Flows: []connection.Flow{
			oneFlow(20000, "203.0.113.5", 5000, 100),
		}}
	})
	ctx := context.Background()
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	// 灌入流量，后续断言自愈时 counter 是否被无谓清零。
	fake.bumpCounter(nft.CounterUp(id), 4242)
	fake.bumpCounter(nft.CounterDown(id), 2424)
	fake.resetScripts()
	return svc, store, fake, id
}

// assertHealed 断言一次 reconcile 后期望对象已恢复，且脚本没有 flush ruleset / delete table。
func assertHealed(t *testing.T, svc *Service, fake *fakeNFT) {
	t.Helper()
	if err := svc.Reconcile(context.Background()); err != nil {
		t.Fatalf("自愈 reconcile 失败: %v", err)
	}
	for _, s := range fake.allScripts() {
		if strings.Contains(s, "flush ruleset") || strings.Contains(s, "delete table") {
			t.Fatalf("自愈脚本不得出现 flush ruleset / delete table:\n%s", s)
		}
	}
}

// 人为删除 nff_nat4 → 下一轮必须恢复 IPv4 转发。
func TestHealDeletedNAT4Table(t *testing.T) {
	svc, _, fake, id := healSetup(t)
	fake.dropTable("ip", nft.TableNAT4)
	assertHealed(t, svc, fake)

	if !fake.hasTable("ip", nft.TableNAT4) {
		t.Fatal("nff_nat4 未恢复")
	}
	if !fake.hasChain("ip", nft.TableNAT4, nft.ChainPrerouting(nft.TableNAT4)) {
		t.Fatal("nat4 prerouting 链未恢复")
	}
	if n := fake.ruleCount("ip", nft.TableNAT4, nft.ChainPrerouting(nft.TableNAT4)); n < 2 {
		t.Fatalf("IPv4 DNAT 规则未恢复（tcp+udp 应有 2 条），实际 %d", n)
	}
	// filter 表未被破坏，counter 累计值必须保留。
	if v := fake.counterOf(nft.CounterUp(id)); v != 4242 {
		t.Fatalf("自愈不应清零未受损的 counter，实际 %d", v)
	}
}

// 人为删除 nff_nat6 → 下一轮必须恢复 IPv6 转发。
func TestHealDeletedNAT6Table(t *testing.T) {
	svc, _, fake, _ := healSetup(t)
	fake.dropTable("ip6", nft.TableNAT6)
	assertHealed(t, svc, fake)

	if !fake.hasTable("ip6", nft.TableNAT6) {
		t.Fatal("nff_nat6 未恢复")
	}
	if n := fake.ruleCount("ip6", nft.TableNAT6, nft.ChainPrerouting(nft.TableNAT6)); n < 2 {
		t.Fatalf("IPv6 DNAT 规则未恢复，实际 %d", n)
	}
}

// 人为删除 nff_filter → 表/链/counter/set 全部重建。
func TestHealDeletedFilterTable(t *testing.T) {
	svc, _, fake, id := healSetup(t)
	fake.dropTable("inet", nft.TableFilter)
	assertHealed(t, svc, fake)

	if !fake.hasTable("inet", nft.TableFilter) {
		t.Fatal("nff_filter 未恢复")
	}
	if !fake.hasChain("inet", nft.TableFilter, nft.ChainForward()) {
		t.Fatal("forward 链未恢复")
	}
	if fake.counterOf(nft.CounterUp(id)) < 0 || fake.counterOf(nft.CounterDown(id)) < 0 {
		t.Fatal("up/down counter 未恢复")
	}
	if !fake.hasSet("inet", nft.TableFilter, nft.SetQuotaBlock) {
		t.Fatal("qblock set 未恢复")
	}
	if !fake.hasSet("inet", nft.TableFilter, nft.AllowSetV4(id)) {
		t.Fatal("IPv4 allow set 未恢复")
	}
	if !fake.hasSet("inet", nft.TableFilter, nft.AllowSetV6(id)) {
		t.Fatal("IPv6 allow set 未恢复")
	}
}

// 人为删除 forward 链 → 必须恢复（表还在，旧实现完全察觉不到）。
func TestHealDeletedForwardChain(t *testing.T) {
	svc, _, fake, id := healSetup(t)
	fake.dropChain("inet", nft.TableFilter, nft.ChainForward())
	assertHealed(t, svc, fake)

	if !fake.hasChain("inet", nft.TableFilter, nft.ChainForward()) {
		t.Fatal("forward 链未恢复")
	}
	if n := fake.ruleCount("inet", nft.TableFilter, nft.ChainForward()); n < 5 {
		t.Fatalf("forward 链规则未恢复（qblock + 2 counter + 2 iplimit），实际 %d", n)
	}
	if v := fake.counterOf(nft.CounterUp(id)); v != 4242 {
		t.Fatalf("链重建不应清零 counter，实际 %d", v)
	}
}

// 人为删除 NAT 链 → 必须恢复。
func TestHealDeletedNATChain(t *testing.T) {
	svc, _, fake, _ := healSetup(t)
	fake.dropChain("ip", nft.TableNAT4, nft.ChainPostrouting(nft.TableNAT4))
	assertHealed(t, svc, fake)

	if !fake.hasChain("ip", nft.TableNAT4, nft.ChainPostrouting(nft.TableNAT4)) {
		t.Fatal("nat4 postrouting 链未恢复")
	}
	if n := fake.ruleCount("ip", nft.TableNAT4, nft.ChainPostrouting(nft.TableNAT4)); n < 1 {
		t.Fatal("masquerade 规则未恢复")
	}
}

// 人为删除 upload counter → 必须恢复。
func TestHealDeletedUploadCounter(t *testing.T) {
	svc, _, fake, id := healSetup(t)
	fake.dropCounter(nft.CounterUp(id))
	assertHealed(t, svc, fake)
	if fake.counterOf(nft.CounterUp(id)) < 0 {
		t.Fatal("upload counter 未恢复")
	}
	// download counter 未被删，累计值必须保留（尽可能保留仍存在的 counter 数值）。
	if v := fake.counterOf(nft.CounterDown(id)); v != 2424 {
		t.Fatalf("未受损的 download counter 被清零: %d", v)
	}
}

// ★ 人为删除 download counter → 必须恢复（旧实现只检查 up counter，完全漏掉）。
func TestHealDeletedDownloadCounter(t *testing.T) {
	svc, _, fake, id := healSetup(t)
	fake.dropCounter(nft.CounterDown(id))
	assertHealed(t, svc, fake)
	if fake.counterOf(nft.CounterDown(id)) < 0 {
		t.Fatal("download counter 未恢复")
	}
	if v := fake.counterOf(nft.CounterUp(id)); v != 4242 {
		t.Fatalf("未受损的 upload counter 被清零: %d", v)
	}
}

// 人为删除 IPv4 allow set → 必须恢复。
func TestHealDeletedAllowSetV4(t *testing.T) {
	svc, _, fake, id := healSetup(t)
	fake.dropSet(nft.AllowSetV4(id))
	assertHealed(t, svc, fake)
	if !fake.hasSet("inet", nft.TableFilter, nft.AllowSetV4(id)) {
		t.Fatal("IPv4 allow set 未恢复")
	}
	// 恢复后元素也要重新灌入（在线 IP 仍然在线）。
	if got := fake.elementsOf("inet", nft.TableFilter, nft.AllowSetV4(id)); len(got) != 1 {
		t.Fatalf("allow set 元素未重新同步，实际 %v", got)
	}
}

// ★ 人为删除 IPv6 allow set → 必须恢复（旧实现只检查 v4）。
func TestHealDeletedAllowSetV6(t *testing.T) {
	svc, _, fake, id := healSetup(t)
	fake.dropSet(nft.AllowSetV6(id))
	assertHealed(t, svc, fake)
	if !fake.hasSet("inet", nft.TableFilter, nft.AllowSetV6(id)) {
		t.Fatal("IPv6 allow set 未恢复")
	}
}

// ★ 人为删除 quota block set → 必须恢复。
func TestHealDeletedQuotaSet(t *testing.T) {
	svc, _, fake, _ := healSetup(t)
	fake.dropSet(nft.SetQuotaBlock)
	assertHealed(t, svc, fake)
	if !fake.hasSet("inet", nft.TableFilter, nft.SetQuotaBlock) {
		t.Fatal("qblock set 未恢复")
	}
}

// 人为清空链内规则（对象都在、规则没了）→ 必须恢复。
func TestHealFlushedChainRules(t *testing.T) {
	svc, _, fake, _ := healSetup(t)
	fake.flushChainRules("inet", nft.TableFilter, nft.ChainForward())
	assertHealed(t, svc, fake)
	if n := fake.ruleCount("inet", nft.TableFilter, nft.ChainForward()); n < 5 {
		t.Fatalf("forward 链规则未恢复，实际 %d", n)
	}
}

// 自愈只碰自有对象：模拟器里放一张用户自有表，自愈后必须原样存在。
func TestHealDoesNotTouchForeignTables(t *testing.T) {
	svc, _, fake, _ := healSetup(t)
	fake.mu.Lock()
	fake.tables["inet/user_own_table"] = true
	fake.chains["inet/user_own_table/user_chain"] = nft.ChainAttrs{
		Type: "filter", Hook: "input", Priority: 0, Policy: "accept",
	}
	fake.chainExprs["inet/user_own_table/user_chain"] = [][]any{
		{map[string]any{"accept": nil}},
		{map[string]any{"accept": nil}},
		{map[string]any{"accept": nil}},
	}
	fake.mu.Unlock()

	fake.dropTable("ip", nft.TableNAT4)
	assertHealed(t, svc, fake)

	if !fake.hasTable("inet", "user_own_table") {
		t.Fatal("自愈不得删除用户自有表")
	}
	if fake.ruleCount("inet", "user_own_table", "user_chain") != 3 {
		t.Fatal("自愈不得改动用户自有链内的规则")
	}
}

// 自愈事件会被记录到健康快照（LastHealOK / LastHealMissing）。
func TestHealRecordedInHealth(t *testing.T) {
	svc, _, fake, _ := healSetup(t)
	fake.dropCounter(nft.CounterDown(1))
	if err := svc.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	h := svc.HealthSnapshot()
	if h.LastHealOK == 0 {
		t.Fatal("自愈时间未记录")
	}
	if h.LastHealMissing == "" {
		t.Fatal("自愈缺失对象描述未记录")
	}
}
