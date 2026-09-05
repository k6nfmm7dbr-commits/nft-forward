package forward

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"github.com/k6nfmm7dbr-commits/nft-forward/internal/portprobe"
)

// 随机监听端口分配区间。取 20000-59999：避开 1-1023 特权端口与常见服务端口段。
//
// 与内核 ephemeral 区间（/proc/sys/net/ipv4/ip_local_port_range，Linux 默认
// 32768-60999）必然有重叠，因此分配时会额外读取该区间并跳过落在其中的端口：
// 转发监听端口若与出站连接的临时端口撞上，会出现「偶发 bind 失败 / 连接被抢」。
// 区间不可读时不做该项排除（只做 bind 探测），绝不因探测失败而拒绝分配。
const (
	randPortMin = 20000
	randPortMax = 59999
	// maxAllocTries 是随机尝试次数上限；用尽即返回明确错误，绝不静默复用端口。
	maxAllocTries = 200
)

// RandSource 抽象随机源，便于测试注入确定序列。
// n > 0；返回 [0, n) 内的整数。
type RandSource interface {
	Intn(n int) int
}

// cryptoRand 是默认随机源，基于 crypto/rand（禁止用 math/rand 决定端口）。
type cryptoRand struct{}

func (cryptoRand) Intn(n int) int {
	if n <= 0 {
		return 0
	}
	// 拒绝取模偏置：丢弃落在尾部不完整区间的样本。
	limit := ^uint64(0) - (^uint64(0) % uint64(n))
	var b [8]byte
	for i := 0; i < 64; i++ {
		if _, err := rand.Read(b[:]); err != nil {
			// crypto/rand 在 Linux 上失败属于极端情况；退回 0 会造成端口聚集，
			// 因此这里 panic 更安全 —— 调用方宁可失败也不能拿到可预测端口。
			panic("crypto/rand 不可用: " + err.Error())
		}
		v := binary.BigEndian.Uint64(b[:])
		if v >= limit {
			continue
		}
		return int(v % uint64(n))
	}
	panic("crypto/rand 连续 64 次未取到无偏样本")
}

// CryptoRand 是导出的默认随机源。
var CryptoRand RandSource = cryptoRand{}

// PortProber 报告某端口在指定协议上是否已被系统进程占用。
type PortProber interface {
	Busy(port int, tcp, udp bool) bool
}

// listenProber 通过实际 bind + /proc 监听表探测端口占用。
//
// 为什么两者都要：bind 到 0.0.0.0 成功并不代表端口空闲 —— 别的进程可能绑在
// 某个具体地址上（bind 到具体地址与通配地址不冲突）。/proc/net 的监听表能看到
// 这种情况，两者结合才可靠。
type listenProber struct{}

func (listenProber) Busy(port int, tcp, udp bool) bool {
	if portprobe.InUse()[port] {
		return true
	}
	return portprobe.BindBusy(port, tcp, udp)
}

// SystemProber 是默认端口占用探测器。
var SystemProber PortProber = listenProber{}

// Allocator 负责为「监听端口留空」的新规则分配安全随机端口。
//
// 分配规则：
//   - 加密安全随机（crypto/rand），绝不由前端决定；
//   - 避开所有未删除规则已占用的同协议端口；
//   - 避开 GuardPorts（面板端口、SSH 端口等）；
//   - 避开内核 ephemeral 区间（/proc/sys/net/ipv4/ip_local_port_range）；
//   - 按规则协议分别探测系统占用：TCP 查 TCP，UDP 查 UDP，TCP+UDP 两者都查；
//   - 多次碰撞后返回明确错误，不复用已占端口、不 fallback 到固定端口。
//
// 并发安全由调用方（RuleMutationService）持有的互斥锁保证：分配与落库在同一
// 临界区内完成，因此两个并发创建不可能拿到同一端口。
type Allocator struct {
	rnd    RandSource
	prober PortProber
	min    int
	max    int
	tries  int
	// avoidEphemeral 控制是否排除内核 ephemeral 区间（测试可关闭）。
	avoidEphemeral bool
}

// NewAllocator 构造分配器，nil 参数使用默认实现。
func NewAllocator(rnd RandSource, prober PortProber) *Allocator {
	if rnd == nil {
		rnd = CryptoRand
	}
	if prober == nil {
		prober = SystemProber
	}
	return &Allocator{rnd: rnd, prober: prober, min: randPortMin, max: randPortMax,
		tries: maxAllocTries, avoidEphemeral: true}
}

// SetRange 覆盖分配区间（测试用；越界或反序参数被忽略）。
func (a *Allocator) SetRange(min, max int) {
	if min >= 1 && max <= 65535 && min <= max {
		a.min = min
		a.max = max
	}
}

// SetTries 覆盖尝试次数上限（测试用）。
func (a *Allocator) SetTries(n int) {
	if n > 0 {
		a.tries = n
	}
}

// SetAvoidEphemeral 控制是否避开内核 ephemeral 区间（测试用）。
func (a *Allocator) SetAvoidEphemeral(v bool) { a.avoidEphemeral = v }

// Allocate 为规则 r 选一个可用监听端口。
//
// existing 是当前未删除规则集合；guard 是保留端口表。
// 返回的端口保证：不在 guard、与 existing 无协议重叠冲突、不在内核 ephemeral
// 区间内、系统层未被占用。
func (a *Allocator) Allocate(r *Rule, existing []*Rule, guard GuardPorts) (int, error) {
	span := a.max - a.min + 1
	if span <= 0 {
		return 0, fmt.Errorf("随机端口区间非法")
	}
	tcp, udp := r.HasTCP(), r.HasUDP()
	elo, ehi, eok := 0, 0, false
	if a.avoidEphemeral {
		elo, ehi, eok = portprobe.EphemeralRange()
	}
	// 若 ephemeral 区间把整个分配区间吞掉，就不能再据它排除（否则永远分配不出）。
	if eok && elo <= a.min && ehi >= a.max {
		eok = false
	}
	for i := 0; i < a.tries; i++ {
		p := a.min + a.rnd.Intn(span)
		if eok && p >= elo && p <= ehi {
			continue
		}
		probe := *r
		probe.ListenPort = p
		if err := CheckPort(&probe, existing, guard); err != nil {
			continue
		}
		if a.prober.Busy(p, tcp, udp) {
			continue
		}
		return p, nil
	}
	return 0, fmt.Errorf("自动分配监听端口失败：连续 %d 次尝试均被占用，请手工指定端口", a.tries)
}
