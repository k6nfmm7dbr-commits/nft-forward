package policy

import (
	"context"
	"errors"
	"testing"

	"github.com/k6nfmm7dbr-commits/nft-forward/internal/connection"
	"github.com/k6nfmm7dbr-commits/nft-forward/internal/forward"
	"github.com/k6nfmm7dbr-commits/nft-forward/internal/nft"
)

// ---- reconcile 原子性（v0.3.2）----
//
// 核心不变量：**只有内核真正 apply 成功，才更新内部缓存（lastStructSig）**。
// `nft -c` 通过但 `nft -f` 失败时若提前更新签名，下一轮会认为「结构已是最新」
// 而不再尝试修复，数据面会一直坏着。

// apply 失败后必须继续尝试重建，且失败期间不得把签名当成已应用。
func TestApplyFailureDoesNotCacheSuccess(t *testing.T) {
	svc, store, fake := newTestService(t)
	id := addRule(t, store, &forward.Rule{
		Name: "r1", Enabled: true, Protocol: forward.ProtoTCP,
		ListenPort: 20000, TargetAddress: "10.0.0.2", TargetPort: 80,
	})
	ctx := context.Background()

	// 首轮：apply 失败
	fake.failNextApply(errors.New("nft 规则应用失败: kernel rejected"))
	if err := svc.Reconcile(ctx); err == nil {
		t.Fatal("apply 失败时 Reconcile 必须返回错误")
	}
	if fake.hasTable("inet", nft.TableFilter) {
		t.Fatal("apply 失败时不应有任何对象落地")
	}
	if svc.Ready() {
		t.Fatal("首轮 apply 失败时不得标记 ready")
	}

	// 第二轮：apply 恢复正常 → 必须重新尝试并成功
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatalf("第二轮应重试并成功: %v", err)
	}
	if !fake.hasTable("inet", nft.TableFilter) {
		t.Fatal("第二轮应真正建立结构（说明失败没有被缓存成成功）")
	}
	if fake.counterOf(nft.CounterUp(id)) < 0 {
		t.Fatal("counter 应已建立")
	}
	if !svc.Ready() {
		t.Fatal("成功后应标记 ready")
	}
}

// 自愈路径 apply 失败：漂移必须在下一轮继续被检测并修复。
func TestHealApplyFailureRetriesNextRound(t *testing.T) {
	svc, _, fake, id := healSetup(t)

	// 制造内容漂移（改 DNAT 目标），并让本次修复 apply 失败。
	f, tb, ch := natPre()
	rules := fake.rulesOf(f, tb, ch)
	fake.replaceRule(f, tb, ch, 0, tamperDNATAddr(rules[0], "8.8.8.8"))
	fake.failNextApply(errors.New("nft 规则应用失败: transient"))

	if err := svc.Reconcile(context.Background()); err == nil {
		t.Fatal("apply 失败时应返回错误")
	}
	// 篡改仍在
	found := false
	for _, e := range fake.rulesOf(f, tb, ch) {
		if dnatAddrOf(e) == "8.8.8.8" {
			found = true
		}
	}
	if !found {
		t.Fatal("apply 失败时篡改不应被修复（前置条件）")
	}

	// 下一轮必须继续修复
	fake.resetScripts()
	if err := svc.Reconcile(context.Background()); err != nil {
		t.Fatalf("下一轮应重试成功: %v", err)
	}
	if fake.structRebuilds() == 0 {
		t.Fatal("下一轮必须继续尝试重建（说明失败没有被缓存成成功）")
	}
	for _, e := range fake.rulesOf(f, tb, ch) {
		if dnatAddrOf(e) == "8.8.8.8" {
			t.Fatal("篡改未被修复")
		}
	}
	// counter 累计值必须保留
	if v := fake.counterOf(nft.CounterUp(id)); v != 4242 {
		t.Fatalf("修复不应清零 counter，实际 %d", v)
	}
}

// 元素增量 apply 失败不得让整轮被视为成功（allow set 未同步必须暴露）。
func TestElementApplyFailurePropagates(t *testing.T) {
	svc, store, fake := newTestService(t)
	id := addRule(t, store, ipLimitRule(20000, 2))
	svc.SetConntrack(func(string) connection.Result {
		return connection.Result{Status: connection.StatusOK, Entries: 1,
			Flows: []connection.Flow{oneFlow(20000, "203.0.113.5", 5000, 100)}}
	})
	ctx := context.Background()
	// 首轮建结构
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	// 让下一次（元素增量）apply 失败
	fake.resetScripts()
	fake.failNextApply(errors.New("nft 规则应用失败: element"))
	// 新 IP 上线 → 需要元素增量
	svc.SetConntrack(func(string) connection.Result {
		return connection.Result{Status: connection.StatusOK, Entries: 2,
			Flows: []connection.Flow{
				oneFlow(20000, "203.0.113.5", 5000, 200),
				oneFlow(20000, "203.0.113.6", 5001, 300),
			}}
	})
	if err := svc.Reconcile(ctx); err == nil {
		t.Fatal("元素 apply 失败必须返回错误（否则 allow set 与状态不一致被隐藏）")
	}
	h := svc.HealthSnapshot()
	if h.LastApplyError == "" {
		t.Fatal("健康快照应记录 apply 错误")
	}
	_ = id

	// 恢复后必须补齐
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatalf("恢复后应成功: %v", err)
	}
	if got := fake.elementsOf("inet", nft.TableFilter, nft.AllowSetV4(id)); len(got) != 2 {
		t.Fatalf("恢复后 allow set 应含 2 个 IP，实际 %v", got)
	}
}

// 读 nft 状态失败：整轮失败，且不得更新 ready/签名。
func TestReadStateFailureFailsRound(t *testing.T) {
	svc, store, _ := newTestService(t)
	addRule(t, store, &forward.Rule{
		Name: "r1", Enabled: true, Protocol: forward.ProtoTCP,
		ListenPort: 20000, TargetAddress: "10.0.0.2", TargetPort: 80,
	})
	svc.SetNFTReadState(func(context.Context, nft.Runner) (*nft.State, error) {
		return nil, errors.New("读取 nft 状态失败: netlink busy")
	})
	if err := svc.Reconcile(context.Background()); err == nil {
		t.Fatal("读状态失败必须返回错误")
	}
	if svc.Ready() {
		t.Fatal("读状态失败时不得标记 ready")
	}
}
