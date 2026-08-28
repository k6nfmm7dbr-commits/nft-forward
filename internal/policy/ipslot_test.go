package policy

import (
	"testing"
	"time"
)

var testNow = time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)

func act(ip string, tcp, udp int, traffic bool) IPActivity {
	return IPActivity{IP: ip, TCPSessions: tcp, UDPSessions: udp, Traffic: traffic}
}

const (
	hour = time.Hour
	ttl  = time.Hour
	prov = 10 * time.Second
)

func recon(st *NodeIPState, active, cand map[string]IPActivity, max int, now time.Time) (map[string]bool, bool) {
	return st.Reconcile(active, cand, max, now, hour, ttl, prov)
}

// limit=1：A 允许，B 拒绝。
func TestLimitOneRejectsSecond(t *testing.T) {
	st := newIPState()
	recon(st, map[string]IPActivity{"A": act("A", 1, 0, true)}, nil, 1, testNow)
	if st.activeGrantedCount() != 1 {
		t.Fatalf("A 应被允许, got %d", st.activeGrantedCount())
	}
	allow, rejected := recon(st,
		map[string]IPActivity{"A": act("A", 1, 0, true), "B": act("B", 1, 0, true)}, nil, 1, testNow.Add(time.Second))
	if !rejected {
		t.Fatal("B 应被拒绝")
	}
	if _, ok := allow["B"]; ok {
		t.Fatal("B 不应进 allow set")
	}
	if _, ok := allow["A"]; !ok {
		t.Fatal("A 应保持在 allow set")
	}
}

// limit=2：A、B 允许，C 拒绝。
func TestLimitTwoAllowsTwoRejectsThird(t *testing.T) {
	st := newIPState()
	recon(st, map[string]IPActivity{"A": act("A", 1, 0, true)}, nil, 2, testNow)
	allow, rejected := recon(st, map[string]IPActivity{
		"A": act("A", 1, 0, true),
		"B": act("B", 1, 0, true),
		"C": act("C", 1, 0, true),
	}, nil, 2, testNow.Add(time.Second))
	if !rejected {
		t.Fatal("C 应被拒绝")
	}
	if _, ok := allow["C"]; ok {
		t.Fatal("C 不应进 allow set")
	}
	if len(allow) != 2 {
		t.Fatalf("allow set 应只有 2 个, got %d", len(allow))
	}
	if _, ok := st.Rejected["C"]; !ok {
		t.Fatal("C 应记入 Rejected")
	}
}

// A 多个 TCP 连接仍只占 1 个 slot（NAT 多连接）。
func TestMultiConnSingleSlot(t *testing.T) {
	st := newIPState()
	allow, _ := recon(st, map[string]IPActivity{"A": act("A", 5, 2, true)}, nil, 2, testNow)
	if len(allow) != 1 {
		t.Fatalf("A 多连接应只占 1 slot, got %d", len(allow))
	}
	if st.activeGrantedCount() != 1 {
		t.Fatalf("在线应为 1, got %d", st.activeGrantedCount())
	}
}

// NAT：同一公网 IP（多设备）只算 1 个在线。
func TestNATSingleIP(t *testing.T) {
	st := newIPState()
	allow, _ := recon(st, map[string]IPActivity{"223.1.1.1": act("223.1.1.1", 10, 3, true)}, nil, 3, testNow)
	if len(allow) != 1 || st.activeGrantedCount() != 1 {
		t.Fatalf("同一公网 IP 应算 1, got allow=%d active=%d", len(allow), st.activeGrantedCount())
	}
}

// A 断开后释放，C 补位。
func TestReleaseThenFill(t *testing.T) {
	st := newIPState()
	recon(st, map[string]IPActivity{"A": act("A", 1, 0, true), "B": act("B", 1, 0, true)}, nil, 2, testNow)
	// A、B 都断开（不在 active）→ 释放。
	allow, _ := recon(st, map[string]IPActivity{"C": act("C", 1, 0, true)}, nil, 2, testNow.Add(time.Second))
	if _, ok := allow["A"]; ok || st.Slots["A"] != nil {
		t.Fatal("A 断开应被释放")
	}
	if _, ok := allow["C"]; !ok {
		t.Fatal("C 应补位")
	}
}

// candidate（SYN 未建立）有名额时临时授予；超时未建立释放。
func TestCandidateProvisionalGrantAndTimeout(t *testing.T) {
	st := newIPState()
	// A 已在线，B 只是候选（SYN）。
	allow, _ := recon(st, map[string]IPActivity{"A": act("A", 1, 0, true)},
		map[string]IPActivity{"B": act("B", 1, 0, false)}, 2, testNow)
	if _, ok := allow["B"]; !ok {
		t.Fatal("有余位时候选 B 应临时授予进 allow set")
	}
	if !st.Slots["B"].Provisional {
		t.Fatal("B 应是 provisional")
	}
	// B 建立 → 转正。
	allow, _ = recon(st, map[string]IPActivity{"A": act("A", 1, 0, true), "B": act("B", 1, 0, true)},
		nil, 2, testNow.Add(time.Second))
	if st.Slots["B"].Provisional {
		t.Fatal("B 建立后应转正")
	}
	_ = allow
}

func TestCandidateTimeoutRelease(t *testing.T) {
	st := newIPState()
	recon(st, map[string]IPActivity{"A": act("A", 1, 0, true)},
		map[string]IPActivity{"B": act("B", 1, 0, false)}, 2, testNow)
	// B 一直不建立，超过 provisionalTTL 后释放（仍作为候选出现，但本轮已释放不 re-grant）。
	allow, _ := recon(st, map[string]IPActivity{"A": act("A", 1, 0, true)},
		map[string]IPActivity{"B": act("B", 1, 0, false)}, 2, testNow.Add(prov+time.Second))
	if _, ok := st.Slots["B"]; ok {
		t.Fatal("B 超时未建立应释放")
	}
	// B 仍只是候选且名额空出，下一轮可再次临时授予。
	allow, _ = recon(st, map[string]IPActivity{"A": act("A", 1, 0, true)},
		map[string]IPActivity{"B": act("B", 1, 0, false)}, 2, testNow.Add(prov+2*time.Second))
	if _, ok := allow["B"]; !ok {
		t.Fatal("释放后下一轮候选可再授予")
	}
}

// 并发候选不突破 max。
func TestConcurrentCandidatesNoOversell(t *testing.T) {
	st := newIPState()
	// max=2，已有 A，同时 B/C/D/E 候选。
	recon(st, map[string]IPActivity{"A": act("A", 1, 0, true)}, nil, 2, testNow)
	allow, _ := recon(st, map[string]IPActivity{"A": act("A", 1, 0, true)},
		map[string]IPActivity{
			"B": act("B", 1, 0, false),
			"C": act("C", 1, 0, false),
			"D": act("D", 1, 0, false),
			"E": act("E", 1, 0, false),
		}, 2, testNow.Add(time.Second))
	if len(allow) > 2 {
		t.Fatalf("并发候选不得突破 max=2, got %d", len(allow))
	}
	// granted 总数 <= max。
	if st.grantedCount() > 2 {
		t.Fatalf("granted 不得 > max, got %d", st.grantedCount())
	}
}

// IPv6。
func TestIPv6Slot(t *testing.T) {
	st := newIPState()
	allow, _ := recon(st, map[string]IPActivity{"2001:db8::1": act("2001:db8::1", 1, 0, true)}, nil, 2, testNow)
	if len(allow) != 1 {
		t.Fatalf("IPv6 应授予 1, got %d", len(allow))
	}
}

// 不限（max<=0）全部授予。
func TestUnlimitedGrantsAll(t *testing.T) {
	st := newIPState()
	allow, rejected := recon(st, map[string]IPActivity{
		"A": act("A", 1, 0, true), "B": act("B", 1, 0, true), "C": act("C", 1, 0, true),
	}, nil, 0, testNow)
	if rejected {
		t.Fatal("不限时不应有拒绝")
	}
	if len(allow) != 3 {
		t.Fatalf("不限应全授予, got %d", len(allow))
	}
}
