package rulesvc

import (
	"context"
	"strings"
	"testing"

	"github.com/k6nfmm7dbr-commits/nft-forward/internal/forward"
)

func domainInput(name string, port int, host string) CreateInput {
	return CreateInput{Name: name, Protocol: forward.ProtoTCPUDP, ListenPort: port,
		TargetAddress: host, TargetPort: 443}
}

// TestCreateDomainRuleResolvesFirst 创建域名规则时先解析，解析结果进运行时字段。
//
// 强制行为：数据库保存用户原始域名，绝不用解析出的 IP 覆盖它。
func TestCreateDomainRuleResolvesFirst(t *testing.T) {
	store, enf := newMemStore(), &fakeEnforcer{}
	res := &stubResolver{v4: []string{"1.2.3.4"}, v6: []string{"2001:db8::9"}}
	svc := newSvc(t, store, enf, res, nil)

	r, err := svc.Create(context.Background(), domainInput("hk", 20000, "hk.example.com"))
	if err != nil {
		t.Fatalf("创建失败: %v", err)
	}
	if r.TargetAddress != "hk.example.com" {
		t.Fatalf("必须保存用户原始域名，实际 %q", r.TargetAddress)
	}
	if r.ResolvedV4 != "1.2.3.4" || r.ResolvedV6 != "2001:db8::9" {
		t.Fatalf("解析结果未写入: v4=%q v6=%q", r.ResolvedV4, r.ResolvedV6)
	}
	if r.ResolveStatus != forward.ResolveOK {
		t.Fatalf("解析状态=%q，期望 ok", r.ResolveStatus)
	}
	// 落库的也必须是域名。
	if store.get(r.ID).TargetAddress != "hk.example.com" {
		t.Fatal("落库值被解析结果污染")
	}
	// nft 侧拿到的是解析后的地址（由 DialV4/DialV6 提供）。
	applied := enf.lastApplied()
	if len(applied) != 1 {
		t.Fatalf("nft 应收到 1 条规则: %+v", applied)
	}
	if applied[0].DialV4() != "1.2.3.4" || applied[0].DialV6() != "2001:db8::9" {
		t.Fatalf("nft 数据面目标错误: v4=%q v6=%q", applied[0].DialV4(), applied[0].DialV6())
	}
}

// TestDomainInitialResolveFailureRejectsCreate 首次解析失败必须拒绝创建。
//
// 不给用户留下一条一开始就完全不工作的规则。
func TestDomainInitialResolveFailureRejectsCreate(t *testing.T) {
	store, enf := newMemStore(), &fakeEnforcer{}
	res := &stubResolver{err4: errDNSTimeout, err6: errDNSTimeout}
	svc := newSvc(t, store, enf, res, nil)

	_, err := svc.Create(context.Background(), domainInput("bad", 20000, "down.example.com"))
	if err == nil {
		t.Fatal("解析失败时创建应失败")
	}
	if !strings.Contains(err.Error(), "无法解析目标域名 down.example.com") {
		t.Fatalf("错误文案应指出无法解析: %q", err.Error())
	}
	if store.count() != 0 {
		t.Fatal("不应留下规则")
	}
	if enf.applyCount() != 0 {
		t.Fatal("不应触碰 nft")
	}
}

// TestDomainNoRecordsRejectsCreate 域名存在但无 A/AAAA 记录同样拒绝。
func TestDomainNoRecordsRejectsCreate(t *testing.T) {
	store, enf := newMemStore(), &fakeEnforcer{}
	svc := newSvc(t, store, enf, &stubResolver{}, nil)
	if _, err := svc.Create(context.Background(), domainInput("x", 20000, "empty.example.com")); err == nil {
		t.Fatal("无 A/AAAA 记录应拒绝创建")
	}
	if store.count() != 0 {
		t.Fatal("不应留下规则")
	}
}

// TestDomainRefreshUpdatesTarget DNS 地址变化 → 刷新并同步 nft。
func TestDomainRefreshUpdatesTarget(t *testing.T) {
	store, enf := newMemStore(), &fakeEnforcer{}
	res := &stubResolver{v4: []string{"1.2.3.4"}}
	svc := newSvc(t, store, enf, res, nil)
	r, err := svc.Create(context.Background(), domainInput("hk", 20000, "hk.example.com"))
	if err != nil {
		t.Fatal(err)
	}
	baseApply := enf.applyCount()

	// 地址变化。
	res.set([]string{"5.6.7.8"}, nil, nil, nil)
	changed, err := svc.RefreshDNS(context.Background())
	if err != nil {
		t.Fatalf("RefreshDNS 失败: %v", err)
	}
	if changed != 1 {
		t.Fatalf("应有 1 条规则变化，实际 %d", changed)
	}
	if got := store.get(r.ID); got.ResolvedV4 != "5.6.7.8" {
		t.Fatalf("解析结果未落库: %q", got.ResolvedV4)
	}
	if got := store.get(r.ID); got.TargetAddress != "hk.example.com" {
		t.Fatal("用户域名被改写")
	}
	if enf.applyCount() != baseApply+1 {
		t.Fatalf("地址变化应触发一次 nft 同步，apply 次数 %d → %d", baseApply, enf.applyCount())
	}
	applied := enf.lastApplied()
	if applied[0].DialV4() != "5.6.7.8" {
		t.Fatalf("nft 目标未更新: %q", applied[0].DialV4())
	}
}

// TestDomainRefreshNoChangeSkipsNFT 地址没变时不得触碰 nft。
//
// 这是「域名刷新不影响其它规则 counter」的第一道保障：无变化就完全不动 nft。
func TestDomainRefreshNoChangeSkipsNFT(t *testing.T) {
	store, enf := newMemStore(), &fakeEnforcer{}
	res := &stubResolver{v4: []string{"1.2.3.4"}}
	svc := newSvc(t, store, enf, res, nil)
	if _, err := svc.Create(context.Background(), domainInput("hk", 20000, "hk.example.com")); err != nil {
		t.Fatal(err)
	}
	base := enf.applyCount()
	for i := 0; i < 5; i++ {
		changed, err := svc.RefreshDNS(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if changed != 0 {
			t.Fatalf("第 %d 轮地址未变却报告变化", i)
		}
	}
	if enf.applyCount() != base {
		t.Fatalf("地址未变不应调用 nft，apply 次数 %d → %d", base, enf.applyCount())
	}
}

// TestDomainRefreshKeepsCurrentAddressWhenStillValid 多 A 顺序变化不得抖动。
func TestDomainRefreshKeepsCurrentAddressWhenStillValid(t *testing.T) {
	store, enf := newMemStore(), &fakeEnforcer{}
	res := &stubResolver{v4: []string{"1.1.1.2"}}
	svc := newSvc(t, store, enf, res, nil)
	r, err := svc.Create(context.Background(), domainInput("hk", 20000, "hk.example.com"))
	if err != nil {
		t.Fatal(err)
	}
	base := enf.applyCount()
	// 返回集合扩大且顺序变化，但当前地址仍在其中。
	res.set([]string{"1.1.1.3", "1.1.1.2", "1.1.1.1"}, nil, nil, nil)
	changed, err := svc.RefreshDNS(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if changed != 0 {
		t.Fatal("当前地址仍有效时不应视为变化")
	}
	if store.get(r.ID).ResolvedV4 != "1.1.1.2" {
		t.Fatalf("地址发生了抖动: %q", store.get(r.ID).ResolvedV4)
	}
	if enf.applyCount() != base {
		t.Fatal("不应触碰 nft")
	}
}

// TestDomainRefreshChangesWhenAddressRemoved 当前地址消失后确定性选新地址。
func TestDomainRefreshChangesWhenAddressRemoved(t *testing.T) {
	store, enf := newMemStore(), &fakeEnforcer{}
	res := &stubResolver{v4: []string{"1.1.1.2"}}
	svc := newSvc(t, store, enf, res, nil)
	r, _ := svc.Create(context.Background(), domainInput("hk", 20000, "hk.example.com"))
	res.set([]string{"1.1.1.9", "1.1.1.3"}, nil, nil, nil)
	if _, err := svc.RefreshDNS(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := store.get(r.ID).ResolvedV4; got != "1.1.1.3" {
		t.Fatalf("应选字典序最小的 1.1.1.3，实际 %q", got)
	}
}

// TestDomainTemporaryFailureKeepsForwarding DNS 临时失败：保留旧地址、状态 stale、nft 不动。
//
// 这是最关键的可用性保证：绝不能因为一次 timeout 就删规则或写假地址。
func TestDomainTemporaryFailureKeepsForwarding(t *testing.T) {
	store, enf := newMemStore(), &fakeEnforcer{}
	res := &stubResolver{v4: []string{"1.2.3.4"}}
	svc := newSvc(t, store, enf, res, nil)
	r, err := svc.Create(context.Background(), domainInput("hk", 20000, "hk.example.com"))
	if err != nil {
		t.Fatal(err)
	}
	base := enf.applyCount()

	res.set(nil, nil, errDNSTimeout, errDNSTimeout)
	changed, err := svc.RefreshDNS(context.Background())
	if err != nil {
		t.Fatalf("临时失败不应让 RefreshDNS 报错: %v", err)
	}
	if changed != 0 {
		t.Fatal("临时失败不应视为地址变化")
	}
	got := store.get(r.ID)
	if got.ResolvedV4 != "1.2.3.4" {
		t.Fatalf("必须保留 last-known-good，实际 %q", got.ResolvedV4)
	}
	if got.ResolveStatus != forward.ResolveStale {
		t.Fatalf("状态应为 stale，实际 %q", got.ResolveStatus)
	}
	if got.ResolveError == "" {
		t.Fatal("应记录失败原因")
	}
	if enf.applyCount() != base {
		t.Fatal("临时失败不应触碰 nft（转发必须继续工作）")
	}
	// 恢复后回到 ok。
	res.set([]string{"1.2.3.4"}, nil, nil, nil)
	if _, err := svc.RefreshDNS(context.Background()); err != nil {
		t.Fatal(err)
	}
	if store.get(r.ID).ResolveStatus != forward.ResolveOK {
		t.Fatalf("恢复后状态应为 ok，实际 %q", store.get(r.ID).ResolveStatus)
	}
}

// TestDomainUpdateDoesNotResetOtherCounters DNS 刷新时其它规则的字段完全不动。
//
// counter 本体在 nft 侧，这里断言的是「刷新不会连带改写其它规则的任何状态」，
// 与 nft 层的 counter 幂等声明共同构成完整保证。
func TestDomainUpdateDoesNotResetOtherCounters(t *testing.T) {
	store, enf := newMemStore(), &fakeEnforcer{}
	res := &stubResolver{v4: []string{"1.2.3.4"}}
	svc := newSvc(t, store, enf, res, nil)

	// 一条 IP 规则（带配额与 IP 限制状态）+ 一条域名规则。
	ipRule, err := svc.Create(context.Background(), createInput("ip", 20000, "9.9.9.9"))
	if err != nil {
		t.Fatal(err)
	}
	on := true
	limit := int64(1 << 30)
	max := 2
	if _, err := svc.UpdatePolicy(context.Background(), ipRule.ID, PolicyInput{
		QuotaEnabled: &on, QuotaLimitBytes: &limit, IPLimitEnabled: &on, IPLimitMax: &max,
	}); err != nil {
		t.Fatal(err)
	}
	baseline := int64(12345)
	if _, err := svc.UpdatePolicy(context.Background(), ipRule.ID,
		PolicyInput{QuotaResetTo: &baseline}); err != nil {
		t.Fatal(err)
	}
	before := store.get(ipRule.ID)

	if _, err := svc.Create(context.Background(), domainInput("dom", 20001, "hk.example.com")); err != nil {
		t.Fatal(err)
	}
	// 域名地址变化 → 触发 nft 同步。
	res.set([]string{"5.6.7.8"}, nil, nil, nil)
	if _, err := svc.RefreshDNS(context.Background()); err != nil {
		t.Fatal(err)
	}

	after := store.get(ipRule.ID)
	if after.QuotaEnabled != before.QuotaEnabled ||
		after.QuotaLimitBytes != before.QuotaLimitBytes ||
		after.QuotaResetBaseline != before.QuotaResetBaseline ||
		after.IPLimitEnabled != before.IPLimitEnabled ||
		after.IPLimitMax != before.IPLimitMax ||
		after.ListenPort != before.ListenPort ||
		after.TargetAddress != before.TargetAddress ||
		after.UpdatedAt != before.UpdatedAt {
		t.Fatalf("DNS 刷新污染了其它规则:\n前 %+v\n后 %+v", before, after)
	}
	// 且两条规则都还在 nft 里。
	applied := enf.lastApplied()
	if len(applied) != 2 {
		t.Fatalf("nft 应包含 2 条规则，实际 %d", len(applied))
	}
}

// TestDomainRefreshDoesNotBumpUpdatedAt 解析状态写入不得抬高 updated_at。
func TestDomainRefreshDoesNotBumpUpdatedAt(t *testing.T) {
	store, enf := newMemStore(), &fakeEnforcer{}
	res := &stubResolver{v4: []string{"1.2.3.4"}}
	svc := newSvc(t, store, enf, res, nil)
	r, _ := svc.Create(context.Background(), domainInput("hk", 20000, "hk.example.com"))
	before := store.get(r.ID).UpdatedAt
	res.set([]string{"5.6.7.8"}, nil, nil, nil)
	if _, err := svc.RefreshDNS(context.Background()); err != nil {
		t.Fatal(err)
	}
	if store.get(r.ID).UpdatedAt != before {
		t.Fatal("解析状态写入不应抬高 updated_at")
	}
}

// TestDomainRuleMutationRollback 编辑域名目标时 nft 失败 → DB 与 nft 都回到原状。
func TestDomainRuleMutationRollback(t *testing.T) {
	store, enf := newMemStore(), &fakeEnforcer{}
	res := &stubResolver{v4: []string{"1.2.3.4"}}
	svc := newSvc(t, store, enf, res, nil)
	r, err := svc.Create(context.Background(), domainInput("hk", 20000, "hk.example.com"))
	if err != nil {
		t.Fatal(err)
	}
	before := store.get(r.ID)

	// 新目标能解析，但 nft 应用失败。
	res.set([]string{"7.7.7.7"}, nil, nil, nil)
	enf.mu.Lock()
	enf.failNext = 1
	enf.mu.Unlock()
	newTarget := "us.example.com"
	if _, err := svc.Update(context.Background(), r.ID, UpdateInput{TargetAddress: &newTarget}); err == nil {
		t.Fatal("nft 失败时编辑应失败")
	}
	after := store.get(r.ID)
	if after.TargetAddress != before.TargetAddress || after.ResolvedV4 != before.ResolvedV4 {
		t.Fatalf("DB 不应被修改:\n前 %+v\n后 %+v", before, after)
	}
	last := enf.lastApplied()
	if len(last) != 1 || last[0].TargetAddress != "hk.example.com" {
		t.Fatalf("nft 应回滚到旧域名: %+v", last)
	}
}

// TestDomainRuleEditNewTargetUnresolvable 新域名无法解析 → 拒绝编辑，旧规则不动。
func TestDomainRuleEditNewTargetUnresolvable(t *testing.T) {
	store, enf := newMemStore(), &fakeEnforcer{}
	res := &stubResolver{v4: []string{"1.2.3.4"}}
	svc := newSvc(t, store, enf, res, nil)
	r, _ := svc.Create(context.Background(), domainInput("hk", 20000, "hk.example.com"))
	base := enf.applyCount()

	res.set(nil, nil, errDNSTimeout, errDNSTimeout)
	bad := "dead.example.com"
	if _, err := svc.Update(context.Background(), r.ID, UpdateInput{TargetAddress: &bad}); err == nil {
		t.Fatal("新域名无法解析时应拒绝编辑")
	}
	got := store.get(r.ID)
	if got.TargetAddress != "hk.example.com" || got.ResolvedV4 != "1.2.3.4" {
		t.Fatalf("旧规则被破坏: %+v", got)
	}
	if enf.applyCount() != base {
		t.Fatal("被拒编辑不应触碰 nft")
	}
}

// TestDomainToIPClearsResolveState 域名改成 IP 后解析状态必须清空。
func TestDomainToIPClearsResolveState(t *testing.T) {
	store, enf := newMemStore(), &fakeEnforcer{}
	res := &stubResolver{v4: []string{"1.2.3.4"}}
	svc := newSvc(t, store, enf, res, nil)
	r, _ := svc.Create(context.Background(), domainInput("hk", 20000, "hk.example.com"))
	ip := "8.8.8.8"
	got, err := svc.Update(context.Background(), r.ID, UpdateInput{TargetAddress: &ip})
	if err != nil {
		t.Fatalf("改为 IP 目标失败: %v", err)
	}
	if got.ResolvedV4 != "" || got.ResolveStatus != "" {
		t.Fatalf("IP 目标不应保留解析状态: %+v", got)
	}
	if got.DialV4() != "8.8.8.8" {
		t.Fatalf("数据面目标错误: %q", got.DialV4())
	}
}

// TestDomainRuleDelete 删除域名规则后 nft 不再包含它。
func TestDomainRuleDelete(t *testing.T) {
	store, enf := newMemStore(), &fakeEnforcer{}
	res := &stubResolver{v4: []string{"1.2.3.4"}}
	svc := newSvc(t, store, enf, res, nil)
	r, _ := svc.Create(context.Background(), domainInput("hk", 20000, "hk.example.com"))
	if err := svc.Delete(context.Background(), r.ID); err != nil {
		t.Fatal(err)
	}
	if len(enf.lastApplied()) != 0 {
		t.Fatalf("nft 不应再包含该规则: %+v", enf.lastApplied())
	}
	// 删除后 RefreshDNS 不应再处理它。
	res.set([]string{"9.9.9.9"}, nil, nil, nil)
	changed, err := svc.RefreshDNS(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if changed != 0 {
		t.Fatal("已删除规则不应参与 DNS 刷新")
	}
}

// TestRefreshDNSIgnoresIPRules IP 目标规则不参与解析。
func TestRefreshDNSIgnoresIPRules(t *testing.T) {
	store, enf := newMemStore(), &fakeEnforcer{}
	res := &stubResolver{v4: []string{"1.2.3.4"}}
	svc := newSvc(t, store, enf, res, nil)
	if _, err := svc.Create(context.Background(), createInput("ip", 20000, "9.9.9.9")); err != nil {
		t.Fatal(err)
	}
	base := enf.applyCount()
	changed, err := svc.RefreshDNS(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if changed != 0 {
		t.Fatal("IP 规则不应产生 DNS 变化")
	}
	if enf.applyCount() != base {
		t.Fatal("IP 规则不应触发 nft 同步")
	}
}

// TestDomainDualStackRefresh 双栈域名单族变化也能正确更新。
func TestDomainDualStackRefresh(t *testing.T) {
	store, enf := newMemStore(), &fakeEnforcer{}
	res := &stubResolver{v4: []string{"1.2.3.4"}, v6: []string{"2001:db8::1"}}
	svc := newSvc(t, store, enf, res, nil)
	r, err := svc.Create(context.Background(), domainInput("dual", 20000, "dual.example.com"))
	if err != nil {
		t.Fatal(err)
	}
	// 只改 IPv6。
	res.set([]string{"1.2.3.4"}, []string{"2001:db8::99"}, nil, nil)
	changed, err := svc.RefreshDNS(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if changed != 1 {
		t.Fatalf("应有 1 条变化，实际 %d", changed)
	}
	got := store.get(r.ID)
	if got.ResolvedV4 != "1.2.3.4" || got.ResolvedV6 != "2001:db8::99" {
		t.Fatalf("双栈更新错误: v4=%q v6=%q", got.ResolvedV4, got.ResolvedV6)
	}
}
