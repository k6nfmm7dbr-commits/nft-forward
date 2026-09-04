package resolve

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

// fakeResolver 是可注入的假解析器。测试绝不接触真实 DNS。
type fakeResolver struct {
	// v4 / v6 是每次查询返回的地址；err4 / err6 非 nil 时该族返回错误。
	v4, v6     []string
	err4, err6 error
	calls      []string
}

func (f *fakeResolver) LookupNetIP(_ context.Context, network, host string) ([]netip.Addr, error) {
	f.calls = append(f.calls, network+":"+host)
	var list []string
	var err error
	if network == "ip4" {
		list, err = f.v4, f.err4
	} else {
		list, err = f.v6, f.err6
	}
	if err != nil {
		return nil, err
	}
	out := make([]netip.Addr, 0, len(list))
	for _, s := range list {
		a, perr := netip.ParseAddr(s)
		if perr != nil {
			continue
		}
		out = append(out, a)
	}
	return out, nil
}

var (
	errTimeout  = &net.DNSError{Err: "i/o timeout", Name: "hk.example.com", IsTimeout: true}
	errServFail = errors.New("server misbehaving")
	errNotFound = &net.DNSError{Err: "no such host", Name: "nope.example.com", IsNotFound: true}
)

func at(sec int64) time.Time { return time.Unix(sec, 0) }

// TestResolveDomainIPv4 只有 A 记录时只填 V4。
func TestResolveDomainIPv4(t *testing.T) {
	r := &fakeResolver{v4: []string{"1.2.3.4"}}
	st := Resolve(context.Background(), r, "hk.example.com", State{}, at(100))
	if st.V4 != "1.2.3.4" || st.V6 != "" {
		t.Fatalf("解析结果错误: v4=%q v6=%q", st.V4, st.V6)
	}
	if st.Status != StatusOK {
		t.Fatalf("状态=%q，期望 ok", st.Status)
	}
	if st.At != 100 {
		t.Fatalf("At=%d，期望 100", st.At)
	}
}

// TestResolveDomainIPv6 只有 AAAA 记录时只填 V6。
func TestResolveDomainIPv6(t *testing.T) {
	r := &fakeResolver{v6: []string{"2001:db8::1"}}
	st := Resolve(context.Background(), r, "v6.example.com", State{}, at(100))
	if st.V6 != "2001:db8::1" || st.V4 != "" {
		t.Fatalf("解析结果错误: v4=%q v6=%q", st.V4, st.V6)
	}
	if st.Status != StatusOK {
		t.Fatalf("状态=%q，期望 ok", st.Status)
	}
}

// TestResolveDualStackDomain A + AAAA 同时存在时两族都填。
func TestResolveDualStackDomain(t *testing.T) {
	r := &fakeResolver{v4: []string{"1.2.3.4"}, v6: []string{"2001:db8::1"}}
	st := Resolve(context.Background(), r, "dual.example.com", State{}, at(100))
	if st.V4 != "1.2.3.4" || st.V6 != "2001:db8::1" {
		t.Fatalf("双栈解析错误: v4=%q v6=%q", st.V4, st.V6)
	}
	if st.Status != StatusOK {
		t.Fatalf("状态=%q，期望 ok", st.Status)
	}
}

// TestDomainInitialResolveFailure 首次解析失败（无历史地址）→ failed 且地址为空。
func TestDomainInitialResolveFailure(t *testing.T) {
	cases := map[string]*fakeResolver{
		"NXDOMAIN": {err4: errNotFound, err6: errNotFound},
		"timeout":  {err4: errTimeout, err6: errTimeout},
		"SERVFAIL": {err4: errServFail, err6: errServFail},
		"无记录":      {}, // 查询成功但两族都空
	}
	for name, r := range cases {
		st := Resolve(context.Background(), r, "nope.example.com", State{}, at(100))
		if !st.Empty() {
			t.Fatalf("%s: 应当无地址，得到 v4=%q v6=%q", name, st.V4, st.V6)
		}
		if st.Status != StatusFailed {
			t.Fatalf("%s: 状态=%q，期望 failed", name, st.Status)
		}
		if st.Err == "" {
			t.Fatalf("%s: 应当记录失败原因", name)
		}
	}
}

// TestDomainTemporaryFailureKeepsLastKnownGood DNS 临时失败必须保留上次有效地址。
//
// 这是强制行为：绝不能因为一次 timeout 就删除 nft 规则或写入假地址。
func TestDomainTemporaryFailureKeepsLastKnownGood(t *testing.T) {
	prev := State{V4: "1.2.3.4", V6: "2001:db8::1", At: 50, Status: StatusOK}
	for _, r := range []*fakeResolver{
		{err4: errTimeout, err6: errTimeout},
		{err4: errServFail, err6: errServFail},
		{}, // 两族都"成功但无记录"
	} {
		st := Resolve(context.Background(), r, "hk.example.com", prev, at(200))
		if st.V4 != "1.2.3.4" || st.V6 != "2001:db8::1" {
			t.Fatalf("临时失败丢弃了 last-known-good: v4=%q v6=%q", st.V4, st.V6)
		}
		if st.Status != StatusStale {
			t.Fatalf("状态=%q，期望 stale", st.Status)
		}
		if st.At != 50 {
			t.Fatalf("At=%d，期望保持上次成功时间 50", st.At)
		}
		if st.Err == "" {
			t.Fatal("应当记录 warning 原因")
		}
		// 绝不能出现假地址。
		if st.V4 == "0.0.0.0" || st.V6 == "::" {
			t.Fatal("绝不允许写入通配/假地址")
		}
	}
}

// TestDomainSingleFamilyFailureKeepsThatFamily 单族失败只保留该族旧地址，另一族正常更新。
func TestDomainSingleFamilyFailureKeepsThatFamily(t *testing.T) {
	prev := State{V4: "1.2.3.4", V6: "2001:db8::1", At: 50, Status: StatusOK}
	r := &fakeResolver{v4: []string{"9.9.9.9"}, err6: errTimeout}
	st := Resolve(context.Background(), r, "hk.example.com", prev, at(200))
	if st.V4 != "9.9.9.9" {
		t.Fatalf("IPv4 应当更新为 9.9.9.9，得到 %q", st.V4)
	}
	if st.V6 != "2001:db8::1" {
		t.Fatalf("IPv6 查询失败应保留旧地址，得到 %q", st.V6)
	}
	if st.Status != StatusStale {
		t.Fatalf("状态=%q，期望 stale", st.Status)
	}
}

// TestDomainRefresh 地址变化时必须更新。
func TestDomainRefresh(t *testing.T) {
	prev := State{V4: "1.2.3.4", At: 50, Status: StatusOK}
	r := &fakeResolver{v4: []string{"5.6.7.8"}}
	st := Resolve(context.Background(), r, "hk.example.com", prev, at(200))
	if st.V4 != "5.6.7.8" {
		t.Fatalf("地址未更新: %q", st.V4)
	}
	if !st.Changed(prev) {
		t.Fatal("Changed 应当为 true")
	}
	if st.At != 200 {
		t.Fatalf("At=%d，期望刷新为 200", st.At)
	}
}

// TestDomainRefreshKeepsCurrentAddressIfStillValid 多 A 记录顺序变化不得导致目标抖动。
func TestDomainRefreshKeepsCurrentAddressIfStillValid(t *testing.T) {
	prev := State{V4: "1.1.1.2", At: 50, Status: StatusOK}
	// DNS 返回顺序变了，但当前地址仍在集合中 → 必须保持不变。
	r := &fakeResolver{v4: []string{"1.1.1.3", "1.1.1.2", "1.1.1.1"}}
	st := Resolve(context.Background(), r, "hk.example.com", prev, at(200))
	if st.V4 != "1.1.1.2" {
		t.Fatalf("当前地址仍有效时不应更换: 得到 %q", st.V4)
	}
	if st.Changed(prev) {
		t.Fatal("地址未变，Changed 应当为 false")
	}
	// 多次调用结果必须稳定。
	for i := 0; i < 5; i++ {
		st = Resolve(context.Background(), r, "hk.example.com", st, at(int64(300+i)))
		if st.V4 != "1.1.1.2" {
			t.Fatalf("第 %d 轮地址抖动: %q", i, st.V4)
		}
	}
}

// TestDomainRefreshChangesRemovedAddress 当前地址从 DNS 集合消失后必须确定性选新地址。
func TestDomainRefreshChangesRemovedAddress(t *testing.T) {
	prev := State{V4: "1.1.1.2", At: 50, Status: StatusOK}
	r := &fakeResolver{v4: []string{"1.1.1.9", "1.1.1.3"}}
	st := Resolve(context.Background(), r, "hk.example.com", prev, at(200))
	if st.V4 != "1.1.1.3" {
		t.Fatalf("应当选字典序最小的 1.1.1.3，得到 %q", st.V4)
	}
	// 确定性：同样输入必须给同样输出。
	st2 := Resolve(context.Background(), r, "hk.example.com", prev, at(201))
	if st2.V4 != st.V4 {
		t.Fatalf("选择不确定: %q vs %q", st.V4, st2.V4)
	}
}

// TestPickStable 直接覆盖稳定选择函数的边界。
func TestPickStable(t *testing.T) {
	if got := pickStable("", nil); got != "" {
		t.Fatalf("空候选应返回空: %q", got)
	}
	if got := pickStable("1.1.1.1", []string{"2.2.2.2", "1.1.1.1"}); got != "1.1.1.1" {
		t.Fatalf("应保持当前地址: %q", got)
	}
	if got := pickStable("9.9.9.9", []string{"2.2.2.2", "1.1.1.1"}); got != "1.1.1.1" {
		t.Fatalf("应取字典序最小: %q", got)
	}
	if got := pickStable("", []string{"2.2.2.2"}); got != "2.2.2.2" {
		t.Fatalf("无当前地址应取候选: %q", got)
	}
}

// TestResolveFiltersBadAddresses 通配/组播/错族地址必须被过滤。
func TestResolveFiltersBadAddresses(t *testing.T) {
	r := &fakeResolver{
		v4: []string{"0.0.0.0", "224.0.0.1", "1.2.3.4"},
		v6: []string{"::", "ff02::1", "2001:db8::5"},
	}
	st := Resolve(context.Background(), r, "x.example.com", State{}, at(10))
	if st.V4 != "1.2.3.4" {
		t.Fatalf("IPv4 过滤失败: %q", st.V4)
	}
	if st.V6 != "2001:db8::5" {
		t.Fatalf("IPv6 过滤失败: %q", st.V6)
	}
}

// TestResolveWrongFamilyIgnored ip4 查询返回 IPv6（异常上游）时必须忽略。
func TestResolveWrongFamilyIgnored(t *testing.T) {
	r := &fakeResolver{v4: []string{"2001:db8::9"}, v6: []string{"2001:db8::1"}}
	st := Resolve(context.Background(), r, "x.example.com", State{}, at(10))
	if st.V4 != "" {
		t.Fatalf("ip4 查询不应产生 IPv6 地址: %q", st.V4)
	}
	if st.V6 != "2001:db8::1" {
		t.Fatalf("IPv6 结果错误: %q", st.V6)
	}
}

// TestStateHelpers Empty / Changed 行为。
func TestStateHelpers(t *testing.T) {
	if !(State{}).Empty() {
		t.Fatal("空状态应当 Empty")
	}
	if (State{V4: "1.2.3.4"}).Empty() {
		t.Fatal("有 V4 不应 Empty")
	}
	a := State{V4: "1.2.3.4", V6: "2001:db8::1"}
	if a.Changed(State{V4: "1.2.3.4", V6: "2001:db8::1"}) {
		t.Fatal("相同地址不应 Changed")
	}
	if !a.Changed(State{V4: "1.2.3.4"}) {
		t.Fatal("V6 不同应当 Changed")
	}
}

// TestResolveQueriesBothFamilies 每轮必须同时查 A 与 AAAA。
func TestResolveQueriesBothFamilies(t *testing.T) {
	r := &fakeResolver{v4: []string{"1.2.3.4"}}
	Resolve(context.Background(), r, "hk.example.com", State{}, at(10))
	if len(r.calls) != 2 {
		t.Fatalf("查询次数=%d，期望 2（ip4+ip6）: %v", len(r.calls), r.calls)
	}
	seen := map[string]bool{}
	for _, c := range r.calls {
		seen[c] = true
	}
	if !seen["ip4:hk.example.com"] || !seen["ip6:hk.example.com"] {
		t.Fatalf("未同时查询两族: %v", r.calls)
	}
}
