package forward

import "testing"

func ruleOf(id int64, proto string, port int, target string, tport int) *Rule {
	return &Rule{ID: id, Name: "r" + string(rune('0'+id)), Enabled: true, Protocol: proto,
		ListenPort: port, TargetAddress: target, TargetPort: tport}
}

// TestValidateBasic 合法规则必须通过校验。
func TestValidateBasic(t *testing.T) {
	ok := ruleOf(1, ProtoTCP, 20000, "1.2.3.4", 443)
	if err := Validate(ok); err != nil {
		t.Fatalf("合法规则被拒: %v", err)
	}
	// 域名与 IPv6 目标同样合法（不再要求与监听地址同族——监听地址已移除）。
	for _, target := range []string{"2001:db8::1", "hk.example.com"} {
		r := ruleOf(1, ProtoTCPUDP, 20000, target, 443)
		if err := Validate(r); err != nil {
			t.Fatalf("目标 %q 被拒: %v", target, err)
		}
	}
}

// TestValidateInvalidPort 端口越界必须被拒。
func TestValidateInvalidPort(t *testing.T) {
	for _, port := range []int{0, -1, 65536, 99999} {
		r := ruleOf(1, ProtoTCP, port, "1.2.3.4", 443)
		if err := Validate(r); err == nil {
			t.Fatalf("监听端口 %d 应当被拒", port)
		}
		r2 := ruleOf(1, ProtoTCP, 20000, "1.2.3.4", port)
		if err := Validate(r2); err == nil {
			t.Fatalf("目标端口 %d 应当被拒", port)
		}
	}
}

// TestValidateInvalidTarget 非法目标地址必须被拒。
func TestValidateInvalidTarget(t *testing.T) {
	for _, target := range []string{"", "not-an-ip", "0.0.0.0", "::", "http://a.com", "a.com:80"} {
		r := ruleOf(1, ProtoTCP, 20000, target, 443)
		if err := Validate(r); err == nil {
			t.Fatalf("目标 %q 应当被拒", target)
		}
	}
}

// TestValidateProtocol 协议白名单。
func TestValidateProtocol(t *testing.T) {
	for _, p := range []string{ProtoTCP, ProtoUDP, ProtoTCPUDP} {
		r := ruleOf(1, p, 20000, "1.2.3.4", 443)
		if err := Validate(r); err != nil {
			t.Fatalf("协议 %q 被拒: %v", p, err)
		}
	}
	for _, p := range []string{"icmp", "sctp", "", "TCP+ICMP"} {
		r := ruleOf(1, p, 20000, "1.2.3.4", 443)
		if err := Validate(r); err == nil {
			t.Fatalf("协议 %q 应当被拒", p)
		}
	}
	// 大写会被归一化。
	r := ruleOf(1, "TCP", 20000, "1.2.3.4", 443)
	if err := Validate(r); err != nil {
		t.Fatalf("大写协议应被归一化: %v", err)
	}
	if r.Protocol != ProtoTCP {
		t.Fatalf("协议未归一化: %q", r.Protocol)
	}
}

// TestRulePortConflictTCP 同端口同 TCP 冲突。
func TestRulePortConflictTCP(t *testing.T) {
	a := ruleOf(1, ProtoTCP, 5000, "1.2.3.4", 443)
	b := ruleOf(2, ProtoTCP, 5000, "5.6.7.8", 80)
	if !a.ConflictsWith(b) {
		t.Fatal("TCP 5000 与 TCP 5000 应当冲突")
	}
	if err := CheckConflicts(a, []*Rule{b}, nil); err == nil {
		t.Fatal("CheckConflicts 应当报冲突")
	}
}

// TestRulePortConflictUDP 同端口同 UDP 冲突。
func TestRulePortConflictUDP(t *testing.T) {
	a := ruleOf(1, ProtoUDP, 5000, "1.2.3.4", 443)
	b := ruleOf(2, ProtoUDP, 5000, "5.6.7.8", 80)
	if !a.ConflictsWith(b) {
		t.Fatal("UDP 5000 与 UDP 5000 应当冲突")
	}
}

// TestNoConflictTCPvsUDP TCP 与 UDP 同端口不冲突。
func TestNoConflictTCPvsUDP(t *testing.T) {
	a := ruleOf(1, ProtoTCP, 5000, "1.2.3.4", 443)
	b := ruleOf(2, ProtoUDP, 5000, "1.2.3.4", 443)
	if a.ConflictsWith(b) {
		t.Fatal("TCP 5000 与 UDP 5000 不应冲突")
	}
	if err := CheckConflicts(a, []*Rule{b}, nil); err != nil {
		t.Fatalf("TCP/UDP 同端口应当允许: %v", err)
	}
}

// TestRulePortConflictTCPUDP tcp+udp 与单协议、与自身都冲突。
func TestRulePortConflictTCPUDP(t *testing.T) {
	both := ruleOf(1, ProtoTCPUDP, 5000, "1.2.3.4", 443)
	tcp := ruleOf(2, ProtoTCP, 5000, "5.6.7.8", 443)
	udp := ruleOf(3, ProtoUDP, 5000, "5.6.7.8", 443)
	both2 := ruleOf(4, ProtoTCPUDP, 5000, "9.9.9.9", 443)
	for _, other := range []*Rule{tcp, udp, both2} {
		if !both.ConflictsWith(other) {
			t.Fatalf("tcp+udp 5000 与 %s 5000 应当冲突", other.Protocol)
		}
	}
}

// TestGuardPort 保留端口必须被拒，且文案要说明占用方。
func TestGuardPort(t *testing.T) {
	guard := GuardPorts{8090: "面板", 22: "系统保护端口（SSH）"}
	r := ruleOf(1, ProtoTCP, 8090, "1.2.3.4", 443)
	err := CheckConflicts(r, nil, guard)
	if err == nil {
		t.Fatal("面板端口应当被拒")
	}
	if got := err.Error(); got == "" || !contains(got, "面板") {
		t.Fatalf("错误文案未说明占用方: %q", got)
	}
	r2 := ruleOf(1, ProtoTCP, 22, "1.2.3.4", 443)
	if err := CheckConflicts(r2, nil, guard); err == nil {
		t.Fatal("SSH 端口应当被拒")
	}
	// 非保留端口正常通过。
	r3 := ruleOf(1, ProtoTCP, 54321, "1.2.3.4", 443)
	if err := CheckConflicts(r3, nil, guard); err != nil {
		t.Fatalf("普通端口被误拒: %v", err)
	}
}

// TestConflictSkipsDeletedAndSelf 已删除规则与自身不参与冲突判定。
func TestConflictSkipsDeletedAndSelf(t *testing.T) {
	deleted := ruleOf(1, ProtoTCP, 20000, "1.2.3.4", 443)
	deleted.Deleted = true
	live := ruleOf(2, ProtoTCP, 20000, "5.6.7.8", 443)
	if err := CheckConflicts(live, []*Rule{deleted}, nil); err != nil {
		t.Fatalf("已删除规则不应参与冲突: %v", err)
	}
	self := ruleOf(2, ProtoTCP, 20000, "9.9.9.9", 8844)
	if err := CheckConflicts(self, []*Rule{live}, nil); err != nil {
		t.Fatalf("编辑自身不应报冲突: %v", err)
	}
}

// TestConflictMessageMentionsRuleName 冲突文案要点名对方规则。
func TestConflictMessageMentionsRuleName(t *testing.T) {
	other := ruleOf(1, ProtoTCP, 5000, "1.2.3.4", 443)
	other.Name = "HK-1"
	r := ruleOf(2, ProtoTCP, 5000, "5.6.7.8", 443)
	err := CheckConflicts(r, []*Rule{other}, nil)
	if err == nil {
		t.Fatal("应当报冲突")
	}
	if !contains(err.Error(), "HK-1") || !contains(err.Error(), "TCP") {
		t.Fatalf("冲突文案不够友好: %q", err.Error())
	}
}

// TestDialAddressesIPTarget IP 目标只出现在对应地址族。
func TestDialAddressesIPTarget(t *testing.T) {
	v4 := ruleOf(1, ProtoTCP, 20000, "1.2.3.4", 443)
	if v4.DialV4() != "1.2.3.4" || v4.DialV6() != "" {
		t.Fatalf("IPv4 目标数据面错误: v4=%q v6=%q", v4.DialV4(), v4.DialV6())
	}
	v6 := ruleOf(2, ProtoTCP, 20001, "2001:db8::1", 443)
	if v6.DialV6() != "2001:db8::1" || v6.DialV4() != "" {
		t.Fatalf("IPv6 目标数据面错误: v4=%q v6=%q", v6.DialV4(), v6.DialV6())
	}
	if !v4.Resolvable() || !v6.Resolvable() {
		t.Fatal("IP 目标应当恒可用")
	}
}

// TestDialAddressesDomainTarget 域名目标使用运行时解析结果。
func TestDialAddressesDomainTarget(t *testing.T) {
	r := ruleOf(1, ProtoTCPUDP, 20000, "hk.example.com", 443)
	if r.DialV4() != "" || r.DialV6() != "" || r.Resolvable() {
		t.Fatal("未解析的域名规则不应有数据面目标")
	}
	r.ResolvedV4 = "1.2.3.4"
	r.ResolvedV6 = "2001:db8::10"
	if r.DialV4() != "1.2.3.4" || r.DialV6() != "2001:db8::10" {
		t.Fatalf("域名解析结果未生效: v4=%q v6=%q", r.DialV4(), r.DialV6())
	}
	if !r.IsDomainTarget() {
		t.Fatal("IsDomainTarget 判定错误")
	}
	// 用户配置的域名不能被解析结果覆盖。
	if r.TargetAddress != "hk.example.com" {
		t.Fatalf("用户配置被污染: %q", r.TargetAddress)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
