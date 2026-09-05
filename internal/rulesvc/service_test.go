package rulesvc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/k6nfmm7dbr-commits/nft-forward/internal/forward"
)

// ---- 测试替身 ----

// memStore 是内存版 RuleStore，可注入写入失败（故障注入）。
type memStore struct {
	mu     sync.Mutex
	rules  map[int64]*forward.Rule
	nextID int64

	failCreate bool
	failUpdate bool
	failDelete bool
	// createdIDs 记录曾经插入过的 ID（用于断言回滚是否物理删除）。
	createdIDs []int64
}

func newMemStore() *memStore {
	return &memStore{rules: map[int64]*forward.Rule{}, nextID: 1}
}

func (m *memStore) ListActive(context.Context) ([]*forward.Rule, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	// 按 ID 升序返回副本，避免调用方改到内部状态。
	ids := make([]int64, 0, len(m.rules))
	for id := range m.rules {
		ids = append(ids, id)
	}
	for i := 0; i < len(ids); i++ {
		for j := i + 1; j < len(ids); j++ {
			if ids[j] < ids[i] {
				ids[i], ids[j] = ids[j], ids[i]
			}
		}
	}
	out := make([]*forward.Rule, 0, len(ids))
	for _, id := range ids {
		r := *m.rules[id]
		out = append(out, &r)
	}
	return out, nil
}

func (m *memStore) Create(_ context.Context, r *forward.Rule) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failCreate {
		return 0, errors.New("disk I/O error")
	}
	id := m.nextID
	m.nextID++
	cp := *r
	cp.ID = id
	m.rules[id] = &cp
	m.createdIDs = append(m.createdIDs, id)
	return id, nil
}

func (m *memStore) Update(_ context.Context, r *forward.Rule) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failUpdate {
		return errors.New("database is locked")
	}
	if _, ok := m.rules[r.ID]; !ok {
		return fmt.Errorf("规则 %d 不存在", r.ID)
	}
	cp := *r
	m.rules[r.ID] = &cp
	return nil
}

func (m *memStore) SoftDelete(_ context.Context, id int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failDelete {
		return errors.New("database is locked")
	}
	r, ok := m.rules[id]
	if !ok {
		return fmt.Errorf("规则 %d 不存在", id)
	}
	r.Deleted = true
	delete(m.rules, id) // ListActive 只返回未删除
	return nil
}

func (m *memStore) HardDelete(_ context.Context, id int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.rules, id)
	return nil
}

func (m *memStore) UpdateResolved(_ context.Context, id int64, v4, v6 string, at int64, status, errMsg string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.rules[id]
	if !ok {
		return fmt.Errorf("规则 %d 不存在", id)
	}
	r.ResolvedV4, r.ResolvedV6, r.ResolvedAt = v4, v6, at
	r.ResolveStatus, r.ResolveError = status, errMsg
	return nil
}

func (m *memStore) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.rules)
}

func (m *memStore) get(id int64) *forward.Rule {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r, ok := m.rules[id]; ok {
		cp := *r
		return &cp
	}
	return nil
}

// fakeEnforcer 记录每次 apply 的规则集，可注入失败。
type fakeEnforcer struct {
	mu       sync.Mutex
	applied  [][]*forward.Rule
	failNext int // >0 时接下来 N 次 apply 失败
	failAll  bool
	holdN    int
}

func (f *fakeEnforcer) ApplyRules(_ context.Context, rules []*forward.Rule) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failAll || f.failNext > 0 {
		if f.failNext > 0 {
			f.failNext--
		}
		return errors.New("nft 规则检查失败: syntax error")
	}
	cp := make([]*forward.Rule, 0, len(rules))
	for _, r := range rules {
		c := *r
		cp = append(cp, &c)
	}
	f.applied = append(f.applied, cp)
	return nil
}

func (f *fakeEnforcer) Hold() func() {
	f.mu.Lock()
	f.holdN++
	f.mu.Unlock()
	return func() {}
}

func (f *fakeEnforcer) lastApplied() []*forward.Rule {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.applied) == 0 {
		return nil
	}
	return f.applied[len(f.applied)-1]
}

func (f *fakeEnforcer) applyCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.applied)
}

// stubResolver 是可控解析器。
type stubResolver struct {
	mu   sync.Mutex
	v4   []string
	v6   []string
	err4 error
	err6 error
}

func (s *stubResolver) LookupNetIP(_ context.Context, network, _ string) ([]netip.Addr, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var list []string
	var err error
	if network == "ip4" {
		list, err = s.v4, s.err4
	} else {
		list, err = s.v6, s.err6
	}
	if err != nil {
		return nil, err
	}
	out := make([]netip.Addr, 0, len(list))
	for _, s := range list {
		if a, perr := netip.ParseAddr(s); perr == nil {
			out = append(out, a)
		}
	}
	return out, nil
}

func (s *stubResolver) set(v4, v6 []string, err4, err6 error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.v4, s.v6, s.err4, s.err6 = v4, v6, err4, err6
}

var errDNSTimeout = &net.DNSError{Err: "i/o timeout", IsTimeout: true}

// newSvc 构造测试用变更服务（确定随机源 + 全空闲端口探测）。
func newSvc(t *testing.T, store RuleStore, enf Enforcer, res *stubResolver, guard forward.GuardPorts) *Service {
	t.Helper()
	if res == nil {
		res = &stubResolver{}
	}
	s := New(store, enf, res, func() forward.GuardPorts { return guard })
	a := forward.NewAllocator(&fixedRand{}, allFree{})
	a.SetRange(30000, 30099)
	// 关闭 ephemeral 避让：测试要的是确定端口序列，而内核区间因环境而异
	// （CI 与开发机不同会让断言飘）。真实分配路径仍然启用该避让。
	a.SetAvoidEphemeral(false)
	s.SetAllocator(a)
	s.SetClock(func() time.Time { return time.Unix(1000, 0) })
	return s
}

// fixedRand 依次返回 0,1,2,... （确定性端口序列）。
type fixedRand struct {
	mu sync.Mutex
	i  int
}

func (f *fixedRand) Intn(n int) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	v := f.i
	f.i++
	if n <= 0 {
		return 0
	}
	return v % n
}

type allFree struct{}

func (allFree) Busy(int, bool, bool) bool { return false }

func createInput(name string, port int, target string) CreateInput {
	return CreateInput{Name: name, Protocol: forward.ProtoTCP, ListenPort: port,
		TargetAddress: target, TargetPort: 443}
}

// ---- 创建 ----

// TestCreateIPRule 基本创建：DB 与 nft 都拿到规则。
func TestCreateIPRule(t *testing.T) {
	store, enf := newMemStore(), &fakeEnforcer{}
	svc := newSvc(t, store, enf, nil, nil)
	r, err := svc.Create(context.Background(), createInput("hk", 20000, "1.2.3.4"))
	if err != nil {
		t.Fatalf("创建失败: %v", err)
	}
	if r.ID == 0 || r.ListenPort != 20000 {
		t.Fatalf("规则不正确: %+v", r)
	}
	if !r.Enabled {
		t.Fatal("默认应启用")
	}
	if store.count() != 1 {
		t.Fatal("规则应落库")
	}
	applied := enf.lastApplied()
	if len(applied) != 1 || applied[0].ID != r.ID {
		t.Fatalf("nft 未收到新规则: %+v", applied)
	}
}

// TestCreateAutoAssignsPortWhenEmpty listen_port=0 → 后端安全随机分配。
func TestCreateAutoAssignsPortWhenEmpty(t *testing.T) {
	store, enf := newMemStore(), &fakeEnforcer{}
	svc := newSvc(t, store, enf, nil, nil)
	r, err := svc.Create(context.Background(), createInput("rand", 0, "1.2.3.4"))
	if err != nil {
		t.Fatalf("创建失败: %v", err)
	}
	if r.ListenPort < 30000 || r.ListenPort > 30099 {
		t.Fatalf("随机端口 %d 不在区间内", r.ListenPort)
	}
}

// TestRandomPortConcurrentCreate 并发创建不得拿到同一端口。
func TestRandomPortConcurrentCreate(t *testing.T) {
	store, enf := newMemStore(), &fakeEnforcer{}
	svc := newSvc(t, store, enf, nil, nil)
	const n = 12
	var wg sync.WaitGroup
	ports := make([]int, n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r, err := svc.Create(context.Background(),
				createInput(fmt.Sprintf("r%d", i), 0, "1.2.3.4"))
			if err != nil {
				errs[i] = err
				return
			}
			ports[i] = r.ListenPort
		}(i)
	}
	wg.Wait()
	seen := map[int]bool{}
	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Fatalf("第 %d 个创建失败: %v", i, errs[i])
		}
		if ports[i] == 0 {
			t.Fatalf("第 %d 个未分配端口", i)
		}
		if seen[ports[i]] {
			t.Fatalf("端口 %d 被重复分配", ports[i])
		}
		seen[ports[i]] = true
	}
	if store.count() != n {
		t.Fatalf("落库规则数=%d，期望 %d", store.count(), n)
	}
}

// TestCreateRejectsGuardPort 保留端口必须拒绝，且不落库。
func TestCreateRejectsGuardPort(t *testing.T) {
	store, enf := newMemStore(), &fakeEnforcer{}
	svc := newSvc(t, store, enf, nil, forward.GuardPorts{8090: "面板"})
	_, err := svc.Create(context.Background(), createInput("bad", 8090, "1.2.3.4"))
	if err == nil {
		t.Fatal("应拒绝面板端口")
	}
	if store.count() != 0 {
		t.Fatal("被拒规则不应落库")
	}
	if enf.applyCount() != 0 {
		t.Fatal("被拒规则不应触碰 nft")
	}
}

// TestCreateRejectsConflict 端口冲突必须拒绝。
func TestCreateRejectsConflict(t *testing.T) {
	store, enf := newMemStore(), &fakeEnforcer{}
	svc := newSvc(t, store, enf, nil, nil)
	if _, err := svc.Create(context.Background(), createInput("a", 20000, "1.2.3.4")); err != nil {
		t.Fatal(err)
	}
	_, err := svc.Create(context.Background(), createInput("b", 20000, "5.6.7.8"))
	if err == nil {
		t.Fatal("同端口同协议应冲突")
	}
	if store.count() != 1 {
		t.Fatal("冲突规则不应落库")
	}
}

// TestCreateRejectsInvalidTargets 非法目标（含 URL、带端口）必须拒绝。
func TestCreateRejectsInvalidTargets(t *testing.T) {
	store, enf := newMemStore(), &fakeEnforcer{}
	svc := newSvc(t, store, enf, nil, nil)
	for _, target := range []string{
		"http://example.com", "https://example.com", "example.com/path",
		"example.com:443", "38.54.32.199:443", "[2001:db8::1]:443",
		"not an ip", "", "0.0.0.0",
	} {
		if _, err := svc.Create(context.Background(), createInput("x", 0, target)); err == nil {
			t.Fatalf("目标 %q 应被拒绝", target)
		}
	}
	if store.count() != 0 || enf.applyCount() != 0 {
		t.Fatal("非法输入不应产生任何副作用")
	}
}

// TestMutationRollbackOnNFTCheckFailure nft 校验失败 → 不留半成功规则。
func TestMutationRollbackOnNFTCheckFailure(t *testing.T) {
	store := newMemStore()
	enf := &fakeEnforcer{failAll: true}
	svc := newSvc(t, store, enf, nil, nil)
	_, err := svc.Create(context.Background(), createInput("hk", 20000, "1.2.3.4"))
	if err == nil {
		t.Fatal("nft 失败时创建应失败")
	}
	if store.count() != 0 {
		t.Fatalf("nft 失败后不得留下规则，实际 %d 条", store.count())
	}
}

// TestMutationRollbackOnDBFailure DB 写入失败 → 不留 nft 规则。
func TestMutationRollbackOnDBFailure(t *testing.T) {
	store := newMemStore()
	store.failCreate = true
	enf := &fakeEnforcer{}
	svc := newSvc(t, store, enf, nil, nil)
	_, err := svc.Create(context.Background(), createInput("hk", 20000, "1.2.3.4"))
	if err == nil {
		t.Fatal("DB 失败时创建应失败")
	}
	if enf.applyCount() != 0 {
		t.Fatal("DB 写入失败时不应已应用 nft")
	}
	if store.count() != 0 {
		t.Fatal("不应留下规则")
	}
}

// TestMutationRollbackOnNFTApplyFailure 编辑时 nft 应用失败 → DB 保持原值，nft 回滚。
func TestMutationRollbackOnNFTApplyFailure(t *testing.T) {
	store, enf := newMemStore(), &fakeEnforcer{}
	svc := newSvc(t, store, enf, nil, nil)
	r, err := svc.Create(context.Background(), createInput("hk", 20000, "1.2.3.4"))
	if err != nil {
		t.Fatal(err)
	}
	before := store.get(r.ID)

	enf.mu.Lock()
	enf.failNext = 1 // 只让下一次 apply 失败，回滚那次成功
	enf.mu.Unlock()

	newPort := 20001
	if _, err := svc.Update(context.Background(), r.ID, UpdateInput{ListenPort: &newPort}); err == nil {
		t.Fatal("nft 应用失败时编辑应失败")
	}
	after := store.get(r.ID)
	if after.ListenPort != before.ListenPort {
		t.Fatalf("DB 不应被修改: %d → %d", before.ListenPort, after.ListenPort)
	}
	// 回滚必须用变更前的规则集重新应用。
	last := enf.lastApplied()
	if len(last) != 1 || last[0].ListenPort != before.ListenPort {
		t.Fatalf("nft 未回滚到变更前状态: %+v", last)
	}
}

// TestUpdateDBFailureRollsBackNFT 编辑时 DB 失败 → nft 回滚到旧状态。
func TestUpdateDBFailureRollsBackNFT(t *testing.T) {
	store, enf := newMemStore(), &fakeEnforcer{}
	svc := newSvc(t, store, enf, nil, nil)
	r, err := svc.Create(context.Background(), createInput("hk", 20000, "1.2.3.4"))
	if err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	store.failUpdate = true
	store.mu.Unlock()

	newPort := 20002
	if _, err := svc.Update(context.Background(), r.ID, UpdateInput{ListenPort: &newPort}); err == nil {
		t.Fatal("DB 失败时编辑应失败")
	}
	last := enf.lastApplied()
	if len(last) != 1 || last[0].ListenPort != 20000 {
		t.Fatalf("nft 应回滚到 20000，实际 %+v", last)
	}
	if store.get(r.ID).ListenPort != 20000 {
		t.Fatal("DB 应保持原值")
	}
}

// TestUpdateEmptyPortRejected 编辑时端口留空必须报错，不得静默随机。
func TestUpdateEmptyPortRejected(t *testing.T) {
	store, enf := newMemStore(), &fakeEnforcer{}
	svc := newSvc(t, store, enf, nil, nil)
	r, err := svc.Create(context.Background(), createInput("hk", 20000, "1.2.3.4"))
	if err != nil {
		t.Fatal(err)
	}
	zero := 0
	_, err = svc.Update(context.Background(), r.ID, UpdateInput{ListenPort: &zero})
	if err == nil {
		t.Fatal("编辑时端口为 0 应报错")
	}
	if err.Error() != "请输入监听端口" {
		t.Fatalf("错误文案=%q，期望「请输入监听端口」", err.Error())
	}
	if store.get(r.ID).ListenPort != 20000 {
		t.Fatal("端口不应被改动")
	}
}

// TestDeleteKeepsHistory 删除走软删除（历史流量保留）。
func TestDeleteKeepsHistory(t *testing.T) {
	store, enf := newMemStore(), &fakeEnforcer{}
	svc := newSvc(t, store, enf, nil, nil)
	r, err := svc.Create(context.Background(), createInput("hk", 20000, "1.2.3.4"))
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Delete(context.Background(), r.ID); err != nil {
		t.Fatalf("删除失败: %v", err)
	}
	if store.count() != 0 {
		t.Fatal("规则应从活跃列表移除")
	}
	if len(enf.lastApplied()) != 0 {
		t.Fatalf("nft 应不再包含该规则: %+v", enf.lastApplied())
	}
}

// TestDeleteDBFailureRollsBackNFT 删除时 DB 失败 → nft 恢复该规则。
func TestDeleteDBFailureRollsBackNFT(t *testing.T) {
	store, enf := newMemStore(), &fakeEnforcer{}
	svc := newSvc(t, store, enf, nil, nil)
	r, err := svc.Create(context.Background(), createInput("hk", 20000, "1.2.3.4"))
	if err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	store.failDelete = true
	store.mu.Unlock()
	if err := svc.Delete(context.Background(), r.ID); err == nil {
		t.Fatal("DB 失败时删除应失败")
	}
	last := enf.lastApplied()
	if len(last) != 1 || last[0].ID != r.ID {
		t.Fatalf("nft 应回滚为仍包含该规则: %+v", last)
	}
	if store.count() != 1 {
		t.Fatal("规则应仍在库中")
	}
}

// TestDeleteNotFound 删除不存在的规则返回 ErrNotFound。
func TestDeleteNotFound(t *testing.T) {
	store, enf := newMemStore(), &fakeEnforcer{}
	svc := newSvc(t, store, enf, nil, nil)
	if err := svc.Delete(context.Background(), 999); !errors.Is(err, ErrNotFound) {
		t.Fatalf("期望 ErrNotFound，实际 %v", err)
	}
}

// ---- 策略 ----

// TestQuotaDoesNotResetCounters 配额变更不触碰 counter，只重设基线。
func TestQuotaDoesNotResetCounters(t *testing.T) {
	store, enf := newMemStore(), &fakeEnforcer{}
	svc := newSvc(t, store, enf, nil, nil)
	r, err := svc.Create(context.Background(), createInput("hk", 20000, "1.2.3.4"))
	if err != nil {
		t.Fatal(err)
	}
	on := true
	limit := int64(1024 * 1024 * 1024)
	got, err := svc.UpdatePolicy(context.Background(), r.ID,
		PolicyInput{QuotaEnabled: &on, QuotaLimitBytes: &limit})
	if err != nil {
		t.Fatalf("配额设置失败: %v", err)
	}
	if !got.QuotaEnabled || got.QuotaLimitBytes != limit {
		t.Fatalf("配额未生效: %+v", got)
	}
	// 重置只改基线。
	base := int64(5000)
	got2, err := svc.UpdatePolicy(context.Background(), r.ID, PolicyInput{QuotaResetTo: &base})
	if err != nil {
		t.Fatal(err)
	}
	if got2.QuotaResetBaseline != base {
		t.Fatalf("基线=%d，期望 %d", got2.QuotaResetBaseline, base)
	}
	// 规则的其它字段不得被动。
	if got2.ListenPort != 20000 || got2.TargetAddress != "1.2.3.4" {
		t.Fatalf("配额操作污染了转发设置: %+v", got2)
	}
}

// TestIPLimitDoesNotResetCounters IP 限制变更同样不动 counter 与转发设置。
func TestIPLimitDoesNotResetCounters(t *testing.T) {
	store, enf := newMemStore(), &fakeEnforcer{}
	svc := newSvc(t, store, enf, nil, nil)
	r, err := svc.Create(context.Background(), createInput("hk", 20000, "1.2.3.4"))
	if err != nil {
		t.Fatal(err)
	}
	on := true
	max := 3
	got, err := svc.UpdatePolicy(context.Background(), r.ID,
		PolicyInput{IPLimitEnabled: &on, IPLimitMax: &max})
	if err != nil {
		t.Fatal(err)
	}
	if !got.IPLimitEnabled || got.IPLimitMax != 3 {
		t.Fatalf("IP 限制未生效: %+v", got)
	}
	if got.ListenPort != 20000 || got.TargetPort != 443 {
		t.Fatal("IP 限制操作污染了转发设置")
	}
}

// TestPolicyValidation 配额/IP 限制的非法值必须拒绝。
func TestPolicyValidation(t *testing.T) {
	store, enf := newMemStore(), &fakeEnforcer{}
	svc := newSvc(t, store, enf, nil, nil)
	r, _ := svc.Create(context.Background(), createInput("hk", 20000, "1.2.3.4"))
	on := true
	zero := int64(0)
	if _, err := svc.UpdatePolicy(context.Background(), r.ID,
		PolicyInput{QuotaEnabled: &on, QuotaLimitBytes: &zero}); err == nil {
		t.Fatal("启用配额但额度为 0 应报错")
	}
	badMax := 0
	if _, err := svc.UpdatePolicy(context.Background(), r.ID,
		PolicyInput{IPLimitEnabled: &on, IPLimitMax: &badMax}); err == nil {
		t.Fatal("IP 上限 0 应报错")
	}
}

// TestSetEnabled 启停走同一条流水线。
func TestSetEnabled(t *testing.T) {
	store, enf := newMemStore(), &fakeEnforcer{}
	svc := newSvc(t, store, enf, nil, nil)
	r, _ := svc.Create(context.Background(), createInput("hk", 20000, "1.2.3.4"))
	off, err := svc.SetEnabled(context.Background(), r.ID, false)
	if err != nil {
		t.Fatal(err)
	}
	if off.Enabled {
		t.Fatal("应已停用")
	}
	last := enf.lastApplied()
	if len(last) != 1 || last[0].Enabled {
		t.Fatalf("nft 应收到停用状态: %+v", last)
	}
}
