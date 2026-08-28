package forward

import "testing"

func TestValidateBasic(t *testing.T) {
	ok := &Rule{Name: "a", Protocol: "tcp", ListenAddress: "0.0.0.0", ListenPort: 20000, TargetAddress: "1.2.3.4", TargetPort: 443}
	if err := Validate(ok); err != nil {
		t.Fatalf("合法规则应通过: %v", err)
	}
}

func TestValidateInvalidPort(t *testing.T) {
	for _, port := range []int{0, -1, 65536} {
		r := &Rule{Name: "a", Protocol: "tcp", ListenAddress: "0.0.0.0", ListenPort: port, TargetAddress: "1.2.3.4", TargetPort: 443}
		if err := Validate(r); err == nil {
			t.Errorf("listen_port=%d 应非法", port)
		}
		r2 := &Rule{Name: "a", Protocol: "tcp", ListenAddress: "0.0.0.0", ListenPort: 20000, TargetAddress: "1.2.3.4", TargetPort: port}
		if err := Validate(r2); err == nil {
			t.Errorf("target_port=%d 应非法", port)
		}
	}
}

func TestValidateInvalidIP(t *testing.T) {
	r := &Rule{Name: "a", Protocol: "tcp", ListenAddress: "0.0.0.0", ListenPort: 20000, TargetAddress: "not-an-ip", TargetPort: 443}
	if err := Validate(r); err == nil {
		t.Fatal("非法目标地址应拒绝")
	}
	r2 := &Rule{Name: "a", Protocol: "tcp", ListenAddress: "0.0.0.0", ListenPort: 20000, TargetAddress: "0.0.0.0", TargetPort: 443}
	if err := Validate(r2); err == nil {
		t.Fatal("目标地址为 0.0.0.0（unspecified）应拒绝")
	}
}

func TestValidateProtocol(t *testing.T) {
	for _, p := range []string{"tcp", "udp", "tcp+udp"} {
		r := &Rule{Name: "a", Protocol: p, ListenAddress: "0.0.0.0", ListenPort: 20000, TargetAddress: "1.2.3.4", TargetPort: 443}
		if err := Validate(r); err != nil {
			t.Errorf("协议 %q 应合法: %v", p, err)
		}
	}
	r := &Rule{Name: "a", Protocol: "icmp", ListenAddress: "0.0.0.0", ListenPort: 20000, TargetAddress: "1.2.3.4", TargetPort: 443}
	if err := Validate(r); err == nil {
		t.Fatal("icmp 协议应拒绝")
	}
}

func TestValidateFamilyMismatch(t *testing.T) {
	// IPv4 监听 → IPv6 目标：禁止（无 NAT64/46）。
	r := &Rule{Name: "a", Protocol: "tcp", ListenAddress: "0.0.0.0", ListenPort: 20000, TargetAddress: "2001:db8::1", TargetPort: 443}
	if err := Validate(r); err == nil {
		t.Fatal("IPv4 监听→IPv6 目标应拒绝")
	}
	// IPv6 监听 → IPv4 目标：禁止。
	r2 := &Rule{Name: "a", Protocol: "tcp", ListenAddress: "::", ListenPort: 20000, TargetAddress: "1.2.3.4", TargetPort: 443}
	if err := Validate(r2); err == nil {
		t.Fatal("IPv6 监听→IPv4 目标应拒绝")
	}
	// IPv6 监听 → IPv6 目标：合法。
	r3 := &Rule{Name: "a", Protocol: "tcp", ListenAddress: "::", ListenPort: 20000, TargetAddress: "2001:db8::1", TargetPort: 443}
	if err := Validate(r3); err != nil {
		t.Fatalf("IPv6→IPv6 应合法: %v", err)
	}
}

func TestConflictSamePortSameProto(t *testing.T) {
	a := &Rule{ID: 1, Name: "a", Protocol: "tcp", ListenAddress: "0.0.0.0", ListenPort: 20000, TargetAddress: "1.2.3.4", TargetPort: 443}
	b := &Rule{ID: 2, Name: "b", Protocol: "tcp", ListenAddress: "9.9.9.9", ListenPort: 20000, TargetAddress: "5.6.7.8", TargetPort: 8844}
	if err := CheckConflicts(b, []*Rule{a}, GuardPorts{}); err == nil {
		t.Fatal("相同协议+相同端口应冲突（0.0.0.0 覆盖具体地址）")
	}
}

func TestNoConflictTCPvsUDP(t *testing.T) {
	a := &Rule{ID: 1, Name: "a", Protocol: "tcp", ListenAddress: "0.0.0.0", ListenPort: 20000, TargetAddress: "1.2.3.4", TargetPort: 443}
	b := &Rule{ID: 2, Name: "b", Protocol: "udp", ListenAddress: "0.0.0.0", ListenPort: 20000, TargetAddress: "1.2.3.4", TargetPort: 443}
	if err := CheckConflicts(b, []*Rule{a}, GuardPorts{}); err != nil {
		t.Fatalf("TCP 与 UDP 相同端口应允许: %v", err)
	}
}

func TestConflictTCPUDPOverlapsTCP(t *testing.T) {
	a := &Rule{ID: 1, Name: "a", Protocol: "tcp+udp", ListenAddress: "0.0.0.0", ListenPort: 20000, TargetAddress: "1.2.3.4", TargetPort: 443}
	b := &Rule{ID: 2, Name: "b", Protocol: "tcp", ListenAddress: "0.0.0.0", ListenPort: 20000, TargetAddress: "5.6.7.8", TargetPort: 443}
	if err := CheckConflicts(b, []*Rule{a}, GuardPorts{}); err == nil {
		t.Fatal("tcp+udp 与 tcp 相同端口应冲突")
	}
}

func TestGuardPorts(t *testing.T) {
	g := GuardPorts{54321: "SSH 端口", 8090: "面板端口"}
	r := &Rule{ID: 1, Name: "a", Protocol: "tcp", ListenAddress: "0.0.0.0", ListenPort: 54321, TargetAddress: "1.2.3.4", TargetPort: 443}
	if err := CheckConflicts(r, nil, g); err == nil {
		t.Fatal("占用 SSH 端口应拒绝")
	}
	r2 := &Rule{ID: 1, Name: "a", Protocol: "tcp", ListenAddress: "0.0.0.0", ListenPort: 8090, TargetAddress: "1.2.3.4", TargetPort: 443}
	if err := CheckConflicts(r2, nil, g); err == nil {
		t.Fatal("占用面板端口应拒绝")
	}
}

func TestConflictSkipsDeletedAndSelf(t *testing.T) {
	a := &Rule{ID: 1, Name: "a", Protocol: "tcp", ListenAddress: "0.0.0.0", ListenPort: 20000, TargetAddress: "1.2.3.4", TargetPort: 443, Deleted: true}
	b := &Rule{ID: 2, Name: "b", Protocol: "tcp", ListenAddress: "0.0.0.0", ListenPort: 20000, TargetAddress: "5.6.7.8", TargetPort: 443}
	if err := CheckConflicts(b, []*Rule{a}, GuardPorts{}); err != nil {
		t.Fatalf("已删除规则不应参与冲突: %v", err)
	}
	// 编辑自身（相同 ID）不冲突。
	self := &Rule{ID: 1, Name: "a", Protocol: "tcp", ListenAddress: "0.0.0.0", ListenPort: 20000, TargetAddress: "9.9.9.9", TargetPort: 8844}
	if err := CheckConflicts(self, []*Rule{self}, GuardPorts{}); err != nil {
		t.Fatalf("编辑自身不应冲突: %v", err)
	}
}
