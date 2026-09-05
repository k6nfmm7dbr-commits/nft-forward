package connection

import (
	"errors"
	"testing"
)

const sampleConntrack = `ipv4     2 tcp      6 431997 ESTABLISHED src=203.0.113.5 dst=192.0.2.1 sport=54321 dport=20000 packets=10 bytes=1000 src=192.0.2.1 dst=203.0.113.5 sport=20000 dport=54321 packets=8 bytes=800 [ASSURED] mark=0 use=1
ipv4     2 tcp      6 59 SYN_SENT src=203.0.113.6 dst=192.0.2.1 sport=54322 dport=20000 packets=1 bytes=60 [UNREPLIED] src=192.0.2.1 dst=203.0.113.6 sport=20000 dport=54322 packets=0 bytes=0 mark=0 use=1
ipv4     2 tcp      6 30 TIME_WAIT src=203.0.113.7 dst=192.0.2.1 sport=54323 dport=20000 packets=5 bytes=500 src=192.0.2.1 dst=203.0.113.7 sport=20000 dport=54323 packets=5 bytes=500 mark=0 use=1
ipv4     2 udp      17 29 src=203.0.113.8 dst=192.0.2.1 sport=40000 dport=30000 packets=3 bytes=300 src=192.0.2.1 dst=203.0.113.8 sport=30000 dport=40000 packets=2 bytes=200 mark=0 use=1
ipv6     10 tcp      6 431990 ESTABLISHED src=2001:db8::5 dst=2001:db8::1 sport=55555 dport=20000 packets=4 bytes=400 src=2001:db8::1 dst=2001:db8::5 sport=20000 dport=55555 packets=4 bytes=400 [ASSURED] mark=0 use=1
`

// ---- Result 语义：四种状态必须严格区分 ----

// 成功读取到 0 flows = 真的没人在线 → Usable。
func TestResultUsableWhenEmptyButComplete(t *testing.T) {
	r := Result{Available: true, Entries: 5, Flows: nil}
	if !r.Complete() {
		t.Fatal("无错误无截断时应视为完整读取")
	}
	if !r.Usable() {
		t.Fatal("成功读取到 0 条相关流时，必须允许据此释放 slot")
	}
	if r.Note() != "" {
		t.Fatalf("正常状态不应有说明文本，实际 %q", r.Note())
	}
}

// conntrack 不可用（文件不存在 / 模块未加载）→ 不可用于判定。
func TestResultUnavailable(t *testing.T) {
	r := Result{Available: false}
	if r.Usable() {
		t.Fatal("conntrack 不可用时绝不能认为没人在线")
	}
	if r.Note() == "" {
		t.Fatal("应给出说明")
	}
}

// 文件可读但整表 0 条 = 内核没在跟踪 → 不可用。
func TestResultInactive(t *testing.T) {
	r := Result{Available: false, Inactive: true}
	if r.Usable() {
		t.Fatal("conntrack 未跟踪任何连接时不能做在线判定")
	}
	if r.Note() == "" {
		t.Fatal("应给出说明")
	}
}

// 读取失败 / 不完整 → 不可用。
func TestResultPartialOrError(t *testing.T) {
	for _, r := range []Result{
		{Available: false, Partial: true, Err: errors.New("io error")},
		{Available: true, Partial: true},
		{Available: true, Err: errors.New("truncated")},
	} {
		if r.Complete() {
			t.Fatalf("%+v 应判定为不完整", r)
		}
		if r.Usable() {
			t.Fatalf("%+v 不得用于在线判定", r)
		}
		if r.Note() == "" {
			t.Fatalf("%+v 应给出说明", r)
		}
	}
}

// ---- 读取真实文件 ----

func TestReadConntrackMissingFile(t *testing.T) {
	r := ReadConntrack("/nonexistent/nf_conntrack")
	if r.Available {
		t.Fatal("文件不存在时不可用")
	}
	if r.Usable() {
		t.Fatal("文件不存在时不得用于判定")
	}
	if r.Err != nil {
		t.Fatalf("文件不存在不算读取错误，实际 %v", r.Err)
	}
}

// ---- 解析 ----

func TestParseConntrackKeepsOnlyLiveStates(t *testing.T) {
	flows := ParseConntrack(sampleConntrack)
	if len(flows) != 4 {
		t.Fatalf("应保留 4 条（2 tcp est + 1 syn_sent + 1 udp），实际 %d: %+v", len(flows), flows)
	}
	for _, f := range flows {
		if f.State == "TIME_WAIT" {
			t.Fatal("TIME_WAIT 必须被丢弃")
		}
	}
	// 双向字节求和：1000 + 800
	var est *Flow
	for i := range flows {
		if flows[i].SrcIP == "203.0.113.5" {
			est = &flows[i]
		}
	}
	if est == nil {
		t.Fatal("未解析出 ESTABLISHED 流")
	}
	if est.Bytes != 1800 {
		t.Fatalf("双向字节应为 1800，实际 %d", est.Bytes)
	}
	if est.OrigDstPort != 20000 || est.SrcPort != 54321 {
		t.Fatalf("端口解析错误: %+v", est)
	}
}

func TestParseConntrackIPv6(t *testing.T) {
	flows := ParseConntrack(sampleConntrack)
	found := false
	for _, f := range flows {
		if f.SrcIP == "2001:db8::5" {
			found = true
			if f.OrigDstPort != 20000 {
				t.Fatalf("IPv6 流端口错误: %+v", f)
			}
		}
	}
	if !found {
		t.Fatal("IPv6 流未被解析（会导致 IPv6 在线 IP 永远为 0）")
	}
}

// ---- flow 索引 ----

func TestBuildIndexGroupsByProtoAndPort(t *testing.T) {
	flows := ParseConntrack(sampleConntrack)
	idx := BuildIndex(flows)

	tcp20000 := idx.Get("tcp", 20000)
	if len(tcp20000) != 3 { // v4 est + v4 syn_sent + v6 est
		t.Fatalf("tcp/20000 应有 3 条，实际 %d", len(tcp20000))
	}
	udp30000 := idx.Get("udp", 30000)
	if len(udp30000) != 1 {
		t.Fatalf("udp/30000 应有 1 条，实际 %d", len(udp30000))
	}
	if got := idx.Get("tcp", 30000); len(got) != 0 {
		t.Fatalf("协议不匹配不应命中，实际 %d 条", len(got))
	}
	if got := idx.Get("udp", 20000); len(got) != 0 {
		t.Fatalf("协议不匹配不应命中，实际 %d 条", len(got))
	}
	if got := idx.Get("tcp", 65000); len(got) != 0 {
		t.Fatal("未知端口不应命中")
	}
	// nil 索引安全
	var nilIdx Index
	if got := nilIdx.Get("tcp", 20000); got != nil {
		t.Fatal("nil 索引应返回 nil")
	}
}

// 索引规模：F 条流建索引一次遍历（行为验证：所有流都能被找到）。
func TestBuildIndexCoversAllFlows(t *testing.T) {
	var flows []Flow
	for p := 20000; p < 20050; p++ {
		for i := 0; i < 20; i++ {
			flows = append(flows, Flow{Proto: "tcp", State: "ESTABLISHED",
				OrigDstPort: p, SrcIP: "10.0.0.1", SrcPort: 40000 + i, Bytes: 100})
		}
	}
	idx := BuildIndex(flows)
	total := 0
	for p := 20000; p < 20050; p++ {
		total += len(idx.Get("tcp", p))
	}
	if total != len(flows) {
		t.Fatalf("索引丢失流：期望 %d，实得 %d", len(flows), total)
	}
}

func TestCountEntries(t *testing.T) {
	if n := countEntries(sampleConntrack); n != 5 {
		t.Fatalf("应有 5 条非空行，实际 %d", n)
	}
	if n := countEntries("\n\n  \n"); n != 0 {
		t.Fatalf("空白内容应为 0，实际 %d", n)
	}
}
