package rulesvc

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/k6nfmm7dbr-commits/nft-forward/internal/forward"
	"github.com/k6nfmm7dbr-commits/nft-forward/internal/resolve"
)

// slowResolver 是可控延迟的解析器：用来验证 DNS 查询不在全局锁内进行。
type slowResolver struct {
	delay time.Duration
	// gate 非 nil 时，解析会阻塞直到该通道被关闭（精确控制时序）。
	gate  chan struct{}
	mu    sync.Mutex
	calls int
	// peak 记录同时进行中的解析数（验证并发上限）。
	inFlight int
	peak     int
}

func (s *slowResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	s.mu.Lock()
	s.calls++
	s.inFlight++
	if s.inFlight > s.peak {
		s.peak = s.inFlight
	}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.inFlight--
		s.mu.Unlock()
	}()

	if s.gate != nil {
		select {
		case <-s.gate:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if s.delay > 0 {
		select {
		case <-time.After(s.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if network == "ip4" {
		return []netip.Addr{netip.MustParseAddr("1.2.3.4")}, nil
	}
	return nil, nil
}

func (s *slowResolver) stats() (calls, peak int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls, s.peak
}

// newSvcWith 构造使用任意 Resolver 的测试服务（newSvc 只接受 *stubResolver）。
func newSvcWith(t *testing.T, store RuleStore, enf Enforcer, res resolve.Resolver) *Service {
	t.Helper()
	s := New(store, enf, res, func() forward.GuardPorts { return forward.GuardPorts{} })
	a := forward.NewAllocator(&fixedRand{}, allFree{})
	a.SetRange(30000, 30099)
	a.SetAvoidEphemeral(false)
	s.SetAllocator(a)
	s.SetClock(func() time.Time { return time.Unix(1000, 0) })
	return s
}

// ★ 慢 DNS 期间其它规则 CRUD 不得被阻塞。
//
// 旧实现：RefreshDNS 全程持有 mu + enforcer 锁，一次 5s 超时就让所有
// 增删改查排队。修复后 DNS 查询在锁外进行，CRUD 只需等极短的临界区。
func TestSlowDNSDoesNotBlockRuleCRUD(t *testing.T) {
	store := newMemStore()
	enf := &fakeEnforcer{}
	res := &slowResolver{gate: make(chan struct{})}
	svc := newSvcWith(t, store, enf, res)

	// 先建一条域名规则（此时 gate 已开，避免创建被卡住）。
	close(res.gate)
	res.gate = nil
	domID, err := svc.Create(context.Background(), createInput("dom", 20000, "hk.example.com"))
	if err != nil {
		t.Fatal(err)
	}
	_ = domID

	// 现在让解析卡住，启动一轮 RefreshDNS。
	res.gate = make(chan struct{})
	refreshDone := make(chan struct{})
	go func() {
		_, _ = svc.RefreshDNS(context.Background())
		close(refreshDone)
	}()

	// 等 RefreshDNS 真正进入解析阶段。
	deadline := time.Now().Add(2 * time.Second)
	for {
		if calls, _ := res.stats(); calls > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("RefreshDNS 未开始解析")
		}
		time.Sleep(5 * time.Millisecond)
	}

	// 关键断言：此刻创建一条 IP 规则必须迅速完成（不被 DNS 卡住）。
	start := time.Now()
	created := make(chan error, 1)
	go func() {
		_, cerr := svc.Create(context.Background(), createInput("ip-rule", 20001, "10.0.0.9"))
		created <- cerr
	}()
	select {
	case cerr := <-created:
		if cerr != nil {
			t.Fatalf("并发创建失败: %v", cerr)
		}
		if d := time.Since(start); d > 1500*time.Millisecond {
			t.Fatalf("DNS 解析期间 CRUD 被阻塞了 %v", d)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("DNS 解析期间 CRUD 被完全阻塞（超过 2s）")
	}

	close(res.gate)
	select {
	case <-refreshDone:
	case <-time.After(5 * time.Second):
		t.Fatal("RefreshDNS 未收尾")
	}
}

// 并发上限：大量域名规则时同时进行的解析数不超过 dnsConcurrency。
func TestDNSRefreshConcurrencyBounded(t *testing.T) {
	store := newMemStore()
	enf := &fakeEnforcer{}
	res := &slowResolver{delay: 30 * time.Millisecond}
	svc := newSvcWith(t, store, enf, res)

	for i := 0; i < 40; i++ {
		if _, err := svc.Create(context.Background(),
			createInput("d"+itoa(i), 21000+i, "h"+itoa(i)+".example.com")); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := svc.RefreshDNS(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, peak := res.stats()
	if peak > dnsConcurrency*2 { // ip4+ip6 各一次查询，故上限翻倍
		t.Fatalf("并发解析峰值 %d 超过上限（dnsConcurrency=%d，每规则 2 次查询）", peak, dnsConcurrency)
	}
	if peak <= 1 {
		t.Fatalf("解析应并发进行，实际峰值 %d", peak)
	}
}

// 解析期间用户改了目标 → 过期结果必须丢弃，绝不覆盖新值。
func TestStaleResolveResultDiscarded(t *testing.T) {
	store := newMemStore()
	enf := &fakeEnforcer{}
	res := &slowResolver{}
	svc := newSvcWith(t, store, enf, res)

	id, err := svc.Create(context.Background(), createInput("dom", 20000, "hk.example.com"))
	if err != nil {
		t.Fatal(err)
	}

	// 卡住解析。
	res.gate = make(chan struct{})
	refreshDone := make(chan struct{})
	go func() {
		_, _ = svc.RefreshDNS(context.Background())
		close(refreshDone)
	}()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if calls, _ := res.stats(); calls > 2 {
			break
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	// 解析进行中，用户把目标改成 IP。
	newTarget := "10.0.0.5"
	if _, err := svc.Update(context.Background(), id.ID,
		UpdateInput{TargetAddress: &newTarget}); err != nil {
		t.Fatalf("并发编辑失败: %v", err)
	}

	close(res.gate)
	select {
	case <-refreshDone:
	case <-time.After(5 * time.Second):
		t.Fatal("RefreshDNS 未收尾")
	}

	// 目标必须还是用户刚设的 IP，解析状态必须已清空。
	rules, _ := store.ListActive(context.Background())
	var got *forward.Rule
	for _, r := range rules {
		if r.ID == id.ID {
			got = r
		}
	}
	if got == nil {
		t.Fatal("规则丢失")
	}
	if got.TargetAddress != newTarget {
		t.Fatalf("用户的新目标被过期 DNS 结果覆盖: %q", got.TargetAddress)
	}
	if got.ResolvedV4 != "" {
		t.Fatalf("IP 目标不应有解析结果，实际 %q", got.ResolvedV4)
	}
}

// 并发 CRUD + DNS 刷新（配合 -race 检测数据竞争）。
func TestConcurrentCRUDAndDNSRefresh(t *testing.T) {
	store := newMemStore()
	enf := &fakeEnforcer{}
	res := &slowResolver{delay: 2 * time.Millisecond}
	svc := newSvcWith(t, store, enf, res)

	for i := 0; i < 5; i++ {
		if _, err := svc.Create(context.Background(),
			createInput("d"+itoa(i), 22000+i, "h"+itoa(i)+".example.com")); err != nil {
			t.Fatal(err)
		}
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})
	// DNS 刷新循环
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				_, _ = svc.RefreshDNS(context.Background())
			}
		}
	}()
	// CRUD 循环
	for w := 0; w < 3; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 10; i++ {
				r, err := svc.Create(context.Background(),
					createInput("t"+itoa(w)+"-"+itoa(i), 0, "10.0.0.1"))
				if err != nil {
					continue
				}
				_, _ = svc.SetEnabled(context.Background(), r.ID, false)
				_ = svc.Delete(context.Background(), r.ID)
			}
		}(w)
	}
	// 让 CRUD 跑完
	time.Sleep(300 * time.Millisecond)
	close(stop)
	wg.Wait()
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var b [12]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
