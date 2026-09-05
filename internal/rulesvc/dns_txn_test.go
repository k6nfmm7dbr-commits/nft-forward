package rulesvc

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/k6nfmm7dbr-commits/nft-forward/internal/forward"
)

// ---- DNS Refresh 的 DB + nft 事务一致性（v0.3.2）----
//
// 旧实现顺序是「先 ApplyRules 到 nft → 再逐条 UpdateResolved 写库 →
// 写失败只打 warning」。任一条写库失败就会留下
// 「nft 用新地址、DB 记旧地址」的长期不一致（下一轮解析结果相同时甚至
// 不会再触发同步，不一致会一直存在）。
//
// 现在改为 BEGIN → 批量写解析列 → ApplyRules → COMMIT，
// 并按失败阶段区分善后：commit 阶段失败必须把 nft 回滚。

// dnsRule 返回一条域名规则的创建入参。
func dnsRule(name string, port int, host string) CreateInput {
	return CreateInput{Name: name, Protocol: forward.ProtoTCP, ListenPort: port,
		TargetAddress: host, TargetPort: 443}
}

// setupDomainRule 建一条已解析到 1.2.3.4 的域名规则。
func setupDomainRule(t *testing.T) (*Service, *memStore, *fakeEnforcer, *stubResolver, *forward.Rule) {
	t.Helper()
	store := newMemStore()
	enf := &fakeEnforcer{}
	res := &stubResolver{v4: []string{"1.2.3.4"}}
	svc := newSvc(t, store, enf, res, nil)
	r, err := svc.Create(context.Background(), dnsRule("dom", 20000, "hk.example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if r.ResolvedV4 != "1.2.3.4" {
		t.Fatalf("前置条件失败：初始解析应为 1.2.3.4，实际 %q", r.ResolvedV4)
	}
	return svc, store, enf, res, r
}

// ruleOf 从 store 读出当前规则。
func ruleOf(t *testing.T, store *memStore, id int64) *forward.Rule {
	t.Helper()
	rules, err := store.ListActive(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rules {
		if r.ID == id {
			return r
		}
	}
	return nil
}

// ① 解析成功 + DB 成功：DB 与 nft 都是新地址。
func TestRefreshDNSCommitSuccess(t *testing.T) {
	svc, store, enf, res, r := setupDomainRule(t)
	res.set([]string{"5.6.7.8"}, nil, nil, nil)

	n, err := svc.RefreshDNS(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("应有 1 条变化，实际 %d", n)
	}
	if got := ruleOf(t, store, r.ID).ResolvedV4; got != "5.6.7.8" {
		t.Fatalf("DB 应记录新地址，实际 %q", got)
	}
	last := enf.lastApplied()
	if last == nil {
		t.Fatal("nft 应被同步")
	}
	for _, ar := range last {
		if ar.ID == r.ID && ar.ResolvedV4 != "5.6.7.8" {
			t.Fatalf("nft 候选集应用新地址，实际 %q", ar.ResolvedV4)
		}
	}
	if store.resolvedCommits != 1 {
		t.Fatalf("一次 refresh 只应提交一次事务，实际 %d", store.resolvedCommits)
	}
}

// ② 解析成功 + nft apply 失败：DB 必须保持旧地址（事务回滚）。
func TestRefreshDNSNFTApplyFailureRollsBackDB(t *testing.T) {
	svc, store, enf, res, r := setupDomainRule(t)
	res.set([]string{"5.6.7.8"}, nil, nil, nil)
	enf.failApply = true

	_, err := svc.RefreshDNS(context.Background())
	if err == nil {
		t.Fatal("nft apply 失败时 RefreshDNS 必须返回错误")
	}
	if got := ruleOf(t, store, r.ID).ResolvedV4; got != "1.2.3.4" {
		t.Fatalf("nft 失败时 DB 必须保持旧地址，实际 %q", got)
	}
	if store.resolvedCommits != 0 {
		t.Fatalf("不应提交任何事务，实际 %d", store.resolvedCommits)
	}
}

// ③ 解析成功 + 写解析列失败：nft 不得被改动。
func TestRefreshDNSWriteFailureDoesNotTouchNFT(t *testing.T) {
	svc, store, enf, res, r := setupDomainRule(t)
	before := enf.applyCount()
	res.set([]string{"5.6.7.8"}, nil, nil, nil)
	store.failResolvedWrite = true

	_, err := svc.RefreshDNS(context.Background())
	if err == nil {
		t.Fatal("写库失败时必须返回错误")
	}
	if enf.applyCount() != before {
		t.Fatalf("写库失败阶段不应调用 nft apply（before=%d after=%d）", before, enf.applyCount())
	}
	if got := ruleOf(t, store, r.ID).ResolvedV4; got != "1.2.3.4" {
		t.Fatalf("DB 应保持旧地址，实际 %q", got)
	}
}

// ④ commit 失败：nft 已是新状态，必须回滚到旧规则集；DB 保持旧地址。
func TestRefreshDNSCommitFailureRollsBackNFT(t *testing.T) {
	svc, store, enf, res, r := setupDomainRule(t)
	res.set([]string{"5.6.7.8"}, nil, nil, nil)
	store.failResolvedCommit = true

	_, err := svc.RefreshDNS(context.Background())
	if err == nil {
		t.Fatal("commit 失败时必须返回错误")
	}
	if !strings.Contains(err.Error(), "提交") {
		t.Fatalf("错误信息应指出提交失败，实际 %v", err)
	}
	// DB 保持旧地址
	if got := ruleOf(t, store, r.ID).ResolvedV4; got != "1.2.3.4" {
		t.Fatalf("commit 失败时 DB 必须保持旧地址，实际 %q", got)
	}
	// nft 必须被回滚：最后一次 apply 的候选集应是旧地址
	last := enf.lastApplied()
	if last == nil {
		t.Fatal("应有 nft 回滚调用")
	}
	found := false
	for _, ar := range last {
		if ar.ID == r.ID {
			found = true
			if ar.ResolvedV4 != "1.2.3.4" {
				t.Fatalf("nft 应被回滚到旧地址，实际 %q", ar.ResolvedV4)
			}
		}
	}
	if !found {
		t.Fatal("回滚的规则集里应含该规则")
	}
}

// ⑤ 解析期间用户改了目标：过期结果必须丢弃，不得覆盖用户的新值。
func TestRefreshDNSStaleResultDoesNotOverwriteUserEdit(t *testing.T) {
	store := newMemStore()
	enf := &fakeEnforcer{}
	res := &stubResolver{v4: []string{"1.2.3.4"}}
	svc := newSvc(t, store, enf, res, nil)
	r, err := svc.Create(context.Background(), dnsRule("dom", 20000, "hk.example.com"))
	if err != nil {
		t.Fatal(err)
	}

	// 用 gate 让解析卡住，期间修改目标为 IP。
	gate := make(chan struct{})
	res.gate = gate
	done := make(chan error, 1)
	go func() { _, e := svc.RefreshDNS(context.Background()); done <- e }()
	waitResolveStarted(t, res)

	newTarget := "10.0.0.9"
	if _, err := svc.Update(context.Background(), r.ID,
		UpdateInput{TargetAddress: &newTarget}); err != nil {
		t.Fatalf("并发编辑失败: %v", err)
	}
	close(gate)
	if err := <-done; err != nil {
		t.Fatalf("RefreshDNS 不应因过期结果失败: %v", err)
	}

	got := ruleOf(t, store, r.ID)
	if got.TargetAddress != newTarget {
		t.Fatalf("用户的新目标被覆盖: %q", got.TargetAddress)
	}
	if got.ResolvedV4 != "" {
		t.Fatalf("IP 目标不应有解析结果，实际 %q", got.ResolvedV4)
	}
}

// ⑥ 解析期间用户删除规则：不得复活，也不得报错。
func TestRefreshDNSDeletedRuleNotResurrected(t *testing.T) {
	store := newMemStore()
	enf := &fakeEnforcer{}
	res := &stubResolver{v4: []string{"1.2.3.4"}}
	svc := newSvc(t, store, enf, res, nil)
	r, err := svc.Create(context.Background(), dnsRule("dom", 20000, "hk.example.com"))
	if err != nil {
		t.Fatal(err)
	}

	gate := make(chan struct{})
	res.gate = gate
	done := make(chan error, 1)
	go func() { _, e := svc.RefreshDNS(context.Background()); done <- e }()
	waitResolveStarted(t, res)

	if err := svc.Delete(context.Background(), r.ID); err != nil {
		t.Fatalf("并发删除失败: %v", err)
	}
	close(gate)
	if err := <-done; err != nil {
		t.Fatalf("规则已删除时 RefreshDNS 不应报错: %v", err)
	}
	if ruleOf(t, store, r.ID) != nil {
		t.Fatal("已删除的规则不得复活")
	}
}

// ⑦ 多条域名规则一次 refresh：只有一次 apply + 一次 commit。
func TestRefreshDNSMultipleRulesSingleTransaction(t *testing.T) {
	store := newMemStore()
	enf := &fakeEnforcer{}
	res := &stubResolver{v4: []string{"1.2.3.4"}}
	svc := newSvc(t, store, enf, res, nil)
	var ids []int64
	for i := 0; i < 4; i++ {
		r, err := svc.Create(context.Background(),
			dnsRule("d"+itoa(i), 21000+i, "h"+itoa(i)+".example.com"))
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, r.ID)
	}
	applyBefore := enf.applyCount()
	res.set([]string{"9.9.9.9"}, nil, nil, nil)

	n, err := svc.RefreshDNS(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n != 4 {
		t.Fatalf("应有 4 条变化，实际 %d", n)
	}
	if got := enf.applyCount() - applyBefore; got != 1 {
		t.Fatalf("多条规则变化只应 apply 一次，实际 %d 次", got)
	}
	if store.resolvedCommits != 1 {
		t.Fatalf("只应提交一次事务，实际 %d", store.resolvedCommits)
	}
	for _, id := range ids {
		if got := ruleOf(t, store, id).ResolvedV4; got != "9.9.9.9" {
			t.Fatalf("规则 %d 应更新到 9.9.9.9，实际 %q", id, got)
		}
	}
}

// ⑧ last-known-good：DNS 临时失败不清空已有地址，且不触发 nft 重写。
func TestRefreshDNSLastKnownGoodPreserved(t *testing.T) {
	svc, store, enf, res, r := setupDomainRule(t)
	applyBefore := enf.applyCount()
	res.set(nil, nil, errDNSTimeout, errDNSTimeout)

	n, err := svc.RefreshDNS(context.Background())
	if err != nil {
		t.Fatalf("临时失败不应让 refresh 报错: %v", err)
	}
	if n != 0 {
		t.Fatalf("地址未变化，应返回 0，实际 %d", n)
	}
	got := ruleOf(t, store, r.ID)
	if got.ResolvedV4 != "1.2.3.4" {
		t.Fatalf("last-known-good 被清空: %q", got.ResolvedV4)
	}
	if got.ResolveStatus != forward.ResolveStale {
		t.Fatalf("应标记为 stale，实际 %q", got.ResolveStatus)
	}
	if enf.applyCount() != applyBefore {
		t.Fatal("地址未变化时不应重写 nft")
	}
	if store.resolvedCommits != 1 {
		t.Fatalf("状态文本仍需落库（一次事务），实际 %d", store.resolvedCommits)
	}
}

// ⑨ commit 失败且 nft 回滚也失败：必须返回错误（不能假装成功）。
func TestRefreshDNSCommitFailureWithRollbackFailure(t *testing.T) {
	svc, store, enf, res, _ := setupDomainRule(t)
	res.set([]string{"5.6.7.8"}, nil, nil, nil)
	store.failResolvedCommit = true
	// 让回滚那次 apply 也失败
	enf.failApplyAfter = enf.applyCount() + 2

	_, err := svc.RefreshDNS(context.Background())
	if err == nil {
		t.Fatal("commit 失败必须返回错误，即使回滚也失败")
	}
}

// ⑩ 解析结果与上次相同：不写 nft，但状态仍落库（一次事务）。
func TestRefreshDNSUnchangedAddressSkipsNFT(t *testing.T) {
	svc, _, enf, res, _ := setupDomainRule(t)
	applyBefore := enf.applyCount()
	res.set([]string{"1.2.3.4"}, nil, nil, nil)

	n, err := svc.RefreshDNS(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("地址未变，应返回 0，实际 %d", n)
	}
	if enf.applyCount() != applyBefore {
		t.Fatal("地址未变时不应调用 nft apply")
	}
}

// ⑪ IP 目标残留的解析状态会被清理（不需要 DNS）。
func TestRefreshDNSClearsResolveStateOnIPRules(t *testing.T) {
	store := newMemStore()
	enf := &fakeEnforcer{}
	svc := newSvc(t, store, enf, &stubResolver{}, nil)
	r, err := svc.Create(context.Background(),
		CreateInput{Name: "ip", Protocol: forward.ProtoTCP, ListenPort: 20000,
			TargetAddress: "10.0.0.1", TargetPort: 80})
	if err != nil {
		t.Fatal(err)
	}
	// 人为塞入残留解析状态（模拟历史数据）。
	if err := store.UpdateResolved(context.Background(), r.ID,
		"1.2.3.4", "", 100, forward.ResolveOK, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RefreshDNS(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := ruleOf(t, store, r.ID)
	if got.ResolvedV4 != "" || got.ResolveStatus != "" {
		t.Fatalf("IP 目标的残留解析状态应被清理，实际 v4=%q status=%q",
			got.ResolvedV4, got.ResolveStatus)
	}
}

// waitResolveStarted 等解析真正开始（stubResolver 记录了调用）。
func waitResolveStarted(t *testing.T, res *stubResolver) {
	t.Helper()
	for i := 0; i < 400; i++ {
		if res.callCount() > 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("解析未开始")
}
