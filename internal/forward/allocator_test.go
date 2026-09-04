package forward

import (
	"fmt"
	"sync"
	"testing"
)

// seqRand 是确定序列随机源（测试注入）。
type seqRand struct {
	vals []int
	i    int
	mu   sync.Mutex
}

func (s *seqRand) Intn(n int) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.vals) == 0 {
		return 0
	}
	v := s.vals[s.i%len(s.vals)]
	s.i++
	if n <= 0 {
		return 0
	}
	return v % n
}

// freeProber 认为所有端口都空闲。
type freeProber struct{}

func (freeProber) Busy(int, bool, bool) bool { return false }

// busyProber 按端口集合与协议判定占用（用于验证 TCP/UDP 分别探测）。
type busyProber struct {
	tcpBusy map[int]bool
	udpBusy map[int]bool
	calls   []string
}

func (b *busyProber) Busy(port int, tcp, udp bool) bool {
	b.calls = append(b.calls, fmt.Sprintf("%d/tcp=%t/udp=%t", port, tcp, udp))
	if tcp && b.tcpBusy[port] {
		return true
	}
	if udp && b.udpBusy[port] {
		return true
	}
	return false
}

func newRule(id int64, proto string, port int) *Rule {
	return &Rule{ID: id, Name: "r", Enabled: true, Protocol: proto,
		ListenPort: port, TargetAddress: "1.2.3.4", TargetPort: 443}
}

// TestRandomPortAllocation 随机端口必须落在配置区间内并可用。
func TestRandomPortAllocation(t *testing.T) {
	a := NewAllocator(&seqRand{vals: []int{5}}, freeProber{})
	a.SetRange(20000, 20010)
	r := newRule(0, ProtoTCPUDP, 0)
	p, err := a.Allocate(r, nil, nil)
	if err != nil {
		t.Fatalf("Allocate 失败: %v", err)
	}
	if p != 20005 {
		t.Fatalf("端口=%d，期望 20005（min+rnd）", p)
	}
	if p < 20000 || p > 20010 {
		t.Fatalf("端口 %d 越界", p)
	}
}

// TestRandomPortCollision 已被规则/保留端口/系统占用的端口必须跳过。
func TestRandomPortCollision(t *testing.T) {
	// 序列: 0(=20000 与已有 TCP 规则冲突) → 1(=20001 是 guard) → 2(=20002 系统占用) → 3(=20003 OK)
	prober := &busyProber{tcpBusy: map[int]bool{20002: true}}
	a := NewAllocator(&seqRand{vals: []int{0, 1, 2, 3}}, prober)
	a.SetRange(20000, 20100)
	existing := []*Rule{newRule(1, ProtoTCP, 20000)}
	guard := GuardPorts{20001: "面板"}
	p, err := a.Allocate(newRule(0, ProtoTCP, 0), existing, guard)
	if err != nil {
		t.Fatalf("Allocate 失败: %v", err)
	}
	if p != 20003 {
		t.Fatalf("端口=%d，期望 20003（前三个都应被跳过）", p)
	}
}

// TestRandomPortProtocolAware TCP 规则占用的端口不阻止 UDP 规则使用同端口。
func TestRandomPortProtocolAware(t *testing.T) {
	a := NewAllocator(&seqRand{vals: []int{0}}, freeProber{})
	a.SetRange(30000, 30000)
	existing := []*Rule{newRule(1, ProtoTCP, 30000)}
	p, err := a.Allocate(newRule(0, ProtoUDP, 0), existing, nil)
	if err != nil {
		t.Fatalf("UDP 规则应当能复用 TCP 已占端口: %v", err)
	}
	if p != 30000 {
		t.Fatalf("端口=%d，期望 30000", p)
	}
	// 反之 TCP 规则不能复用。
	if _, err := a.Allocate(newRule(0, ProtoTCP, 0), existing, nil); err == nil {
		t.Fatal("TCP 规则不应复用同端口 TCP 规则")
	}
}

// TestRandomPortProbesBothProtocols TCP+UDP 规则必须两种协议都探测。
func TestRandomPortProbesBothProtocols(t *testing.T) {
	prober := &busyProber{udpBusy: map[int]bool{40000: true}}
	a := NewAllocator(&seqRand{vals: []int{0, 1}}, prober)
	a.SetRange(40000, 40001)
	p, err := a.Allocate(newRule(0, ProtoTCPUDP, 0), nil, nil)
	if err != nil {
		t.Fatalf("Allocate 失败: %v", err)
	}
	if p != 40001 {
		t.Fatalf("端口=%d，期望 40001（40000 的 UDP 被占用）", p)
	}
	if len(prober.calls) == 0 || prober.calls[0] != "40000/tcp=true/udp=true" {
		t.Fatalf("TCP+UDP 规则未同时探测两种协议: %v", prober.calls)
	}
}

// TestRandomPortExhausted 连续碰撞用尽尝试次数后必须返回明确错误。
func TestRandomPortExhausted(t *testing.T) {
	a := NewAllocator(&seqRand{vals: []int{0}}, freeProber{})
	a.SetRange(50000, 50000)
	a.SetTries(5)
	existing := []*Rule{newRule(1, ProtoTCPUDP, 50000)}
	if _, err := a.Allocate(newRule(0, ProtoTCP, 0), existing, nil); err == nil {
		t.Fatal("端口耗尽时应当返回错误，而不是复用已占端口")
	}
}

// TestCryptoRandInRange 默认随机源必须落在 [0,n) 内。
func TestCryptoRandInRange(t *testing.T) {
	for i := 0; i < 200; i++ {
		v := CryptoRand.Intn(100)
		if v < 0 || v >= 100 {
			t.Fatalf("CryptoRand.Intn(100)=%d 越界", v)
		}
	}
	if v := CryptoRand.Intn(0); v != 0 {
		t.Fatalf("CryptoRand.Intn(0)=%d，期望 0", v)
	}
}
