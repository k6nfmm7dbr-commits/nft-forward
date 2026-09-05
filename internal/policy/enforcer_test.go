package policy

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/k6nfmm7dbr-commits/nft-forward/internal/connection"
	"github.com/k6nfmm7dbr-commits/nft-forward/internal/forward"
	"github.com/k6nfmm7dbr-commits/nft-forward/internal/nft"
)

// TestSelfOriginatedConnectionsIgnored 服务器自身发起的出站连接不得占用 IP 名额。
//
// 场景：本机 curl https://example.com，conntrack 里 src=本机地址、dport=443。
// 若不排除，它会被当成「443 转发规则的客户端」，IP 限制开启时挤掉真实用户。
func TestSelfOriginatedConnectionsIgnored(t *testing.T) {
	svc, store, _ := newTestService(t)
	id := addRule(t, store, &forward.Rule{
		Name: "r1", Enabled: true, Protocol: "tcp",
		ListenPort: 443, TargetAddress: "10.0.0.2", TargetPort: 443,
		IPLimitEnabled: true, IPLimitMax: 1,
	})

	svc.SetLocalIPs(func() (map[string]bool, error) {
		return map[string]bool{"192.0.2.10": true, "127.0.0.1": true}, nil
	})
	svc.SetConntrack(func(string) connection.Result {
		return connection.Result{Available: true, Entries: 2, Flows: []connection.Flow{
			// 本机自己发起的出站（源=本机地址）—— 必须忽略。
			{Proto: "tcp", State: "ESTABLISHED", OrigDstPort: 443, SrcIP: "192.0.2.10", SrcPort: 40000, Bytes: 500},
			// 真实客户端。
			{Proto: "tcp", State: "ESTABLISHED", OrigDstPort: 443, SrcIP: "203.0.113.7", SrcPort: 50000, Bytes: 800},
		}}
	})
	ctx := context.Background()
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	st := svc.StateOf(id)
	if st == nil {
		t.Fatal("缺少规则状态")
	}
	if st.IPs.GrantedCount != 1 {
		t.Fatalf("在线 IP 应为 1（只有真实客户端），实际 %d", st.IPs.GrantedCount)
	}
	for _, e := range st.IPs.IPs {
		if e.IP == "192.0.2.10" {
			t.Fatal("服务器自身地址不应占用 IP 名额")
		}
	}
	if len(st.IPs.IPs) != 1 || st.IPs.IPs[0].IP != "203.0.113.7" {
		t.Fatalf("在线 IP 列表错误: %+v", st.IPs.IPs)
	}
	// max_ips=1 时真实客户端必须拿到名额而不是被本机连接挤掉。
	if len(st.IPs.Rejected) != 0 {
		t.Fatalf("不应有被拒 IP: %+v", st.IPs.Rejected)
	}
}

// TestApplyRulesUsedByMutationPath ApplyRules 直接接受规则集，不读库。
//
// 这是 rulesvc 的 candidate 语义基础：变更服务先用「候选规则集」应用 nft，
// 成功后才落库。
func TestApplyRulesUsedByMutationPath(t *testing.T) {
	svc, _, fake := newTestService(t)

	cand := []*forward.Rule{{
		ID: 42, Name: "cand", Enabled: true, Protocol: "tcp",
		ListenPort: 12345, TargetAddress: "1.2.3.4", TargetPort: 443,
	}}
	if err := svc.ApplyRules(context.Background(), cand); err != nil {
		t.Fatalf("ApplyRules 失败: %v", err)
	}
	joined := strings.Join(fake.allScripts(), "\n")
	if !strings.Contains(joined, "dport 12345") {
		t.Fatalf("候选规则未进入 nft 脚本:\n%s", joined)
	}
	if !strings.Contains(joined, "fib daddr type local") {
		t.Fatal("候选脚本必须带本机匹配")
	}
}

// TestHoldSerializesWithReconcile Hold 期间 reconcile 必须等待。
//
// 这消除了「nft 已应用、DB 未提交」窗口里 reconcile 按旧数据重建 nft 的竞态。
func TestHoldSerializesWithReconcile(t *testing.T) {
	svc, _, _ := newTestService(t)

	release := svc.Hold()
	done := make(chan struct{})
	go func() {
		_ = svc.Reconcile(context.Background())
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("Hold 期间 Reconcile 不应完成")
	case <-time.After(80 * time.Millisecond):
		// 预期：被阻塞。
	}
	release()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("释放后 Reconcile 应当完成")
	}
}

// TestCounterContinuityAfterDNSRefresh 域名解析结果变化只重写链，counter 累计值保留。
//
// 「counter 不清零」的机制是：结构脚本永不 delete table，counter 用幂等
// `table {...}` 声明；因此即使链被 flush 重建，累计字节也保留。
func TestCounterContinuityAfterDNSRefresh(t *testing.T) {
	svc, store, fake := newTestService(t)
	id := addRule(t, store, &forward.Rule{
		Name: "dom", Enabled: true, Protocol: "tcp",
		ListenPort: 20000, TargetAddress: "hk.example.com", TargetPort: 443,
		ResolvedV4: "1.2.3.4", ResolveStatus: forward.ResolveOK,
	})
	ctx := context.Background()
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	// 灌入真实流量。
	fake.bumpCounter(nft.CounterUp(id), 999)
	fake.bumpCounter(nft.CounterDown(id), 111)

	// DNS 目标变化。
	r, _ := store.Get(ctx, id)
	r.ResolvedV4 = "5.6.7.8"
	if err := store.Update(ctx, r); err != nil {
		t.Fatal(err)
	}
	fake.resetScripts()
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if fake.structRebuilds() != 1 {
		t.Fatalf("DNS 目标变化应触发 1 次链重写，实际 %d", fake.structRebuilds())
	}
	joined := strings.Join(fake.allScripts(), "\n")
	if strings.Contains(joined, "delete table") {
		t.Fatal("DNS 更新绝不能 delete table（会清零 counter）")
	}
	if !strings.Contains(joined, "dnat to 5.6.7.8:443") {
		t.Fatalf("新目标未生效:\n%s", joined)
	}
	if strings.Contains(joined, "delete counter inet "+nft.TableFilter+" "+nft.CounterUp(id)) {
		t.Fatal("DNS 更新不应删除本规则 counter")
	}
	// 关键断言：累计字节必须原样保留。
	if v := fake.counterOf(nft.CounterUp(id)); v != 999 {
		t.Fatalf("DNS 更新后 upload counter 被清零/改动: %d", v)
	}
	if v := fake.counterOf(nft.CounterDown(id)); v != 111 {
		t.Fatalf("DNS 更新后 download counter 被清零/改动: %d", v)
	}
}

// TestUnresolvedDomainDoesNotBreakOtherRules 一条域名规则解析失败不得影响其它规则。
func TestUnresolvedDomainDoesNotBreakOtherRules(t *testing.T) {
	svc, store, fake := newTestService(t)
	okID := addRule(t, store, &forward.Rule{
		Name: "ip-rule", Enabled: true, Protocol: "tcp",
		ListenPort: 20000, TargetAddress: "1.2.3.4", TargetPort: 443,
	})
	badID := addRule(t, store, &forward.Rule{
		Name: "dead-domain", Enabled: true, Protocol: "tcp",
		ListenPort: 20001, TargetAddress: "down.example.com", TargetPort: 443,
		ResolveStatus: forward.ResolveFailed, ResolveError: "timeout",
	})
	ctx := context.Background()
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatalf("解析失败的规则不应让整轮 reconcile 失败: %v", err)
	}
	joined := strings.Join(fake.allScripts(), "\n")
	if !strings.Contains(joined, "dnat to 1.2.3.4:443") {
		t.Fatal("正常规则应继续工作")
	}
	if !strings.Contains(joined, "counter "+nft.CounterUp(badID)) {
		t.Fatal("解析失败的规则 counter 也必须保留")
	}
	if svc.StateOf(okID) == nil {
		t.Fatal("正常规则状态缺失")
	}
	if fake.counterOf(nft.CounterUp(badID)) < 0 {
		t.Fatal("解析失败的规则 counter 应真实存在")
	}
}

// TestHealthSnapshot 健康快照反映 apply / reconcile / conntrack 状态。
func TestHealthSnapshot(t *testing.T) {
	svc, _, _ := newTestService(t)
	h := svc.HealthSnapshot()
	if h.Ready {
		t.Fatal("首轮前不应 ready")
	}
	if err := svc.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	h = svc.HealthSnapshot()
	if !h.Ready {
		t.Fatal("首轮后应 ready")
	}
	if h.LastApplyOK == 0 || h.LastReconcileOK == 0 {
		t.Fatalf("应记录最近成功时间: %+v", h)
	}
	if !h.ConntrackOK {
		t.Fatal("conntrack 可用时应报告 OK")
	}
	if h.IPStateFrozen {
		t.Fatal("conntrack 可用时不应处于冻结")
	}
}

// TestConntrackInactiveReported conntrack 未激活时健康快照给出说明。
func TestConntrackInactiveReported(t *testing.T) {
	svc, _, _ := newTestService(t)
	svc.SetConntrack(func(string) connection.Result {
		return connection.Result{Available: false, Inactive: true}
	})
	if err := svc.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	h := svc.HealthSnapshot()
	if h.ConntrackOK {
		t.Fatal("conntrack 未激活时不应报 OK")
	}
	if h.ConntrackNote == "" {
		t.Fatal("应给出 conntrack 说明")
	}
	if !h.IPStateFrozen {
		t.Fatal("conntrack 未激活时在线 IP 状态应冻结")
	}
}
