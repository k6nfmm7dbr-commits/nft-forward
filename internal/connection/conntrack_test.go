package connection

import (
	"errors"
	"io"
	"strconv"
	"strings"
	"testing"
)

const sampleConntrack = `ipv4     2 tcp      6 431997 ESTABLISHED src=203.0.113.5 dst=192.0.2.1 sport=54321 dport=20000 packets=10 bytes=1000 src=192.0.2.1 dst=203.0.113.5 sport=20000 dport=54321 packets=8 bytes=800 [ASSURED] mark=0 use=1
ipv4     2 tcp      6 59 SYN_SENT src=203.0.113.6 dst=192.0.2.1 sport=54322 dport=20000 packets=1 bytes=60 [UNREPLIED] src=192.0.2.1 dst=203.0.113.6 sport=20000 dport=54322 packets=0 bytes=0 mark=0 use=1
ipv4     2 tcp      6 30 TIME_WAIT src=203.0.113.7 dst=192.0.2.1 sport=54323 dport=20000 packets=5 bytes=500 src=192.0.2.1 dst=203.0.113.7 sport=20000 dport=54323 packets=5 bytes=500 mark=0 use=1
ipv4     2 udp      17 29 src=203.0.113.8 dst=192.0.2.1 sport=40000 dport=30000 packets=3 bytes=300 src=192.0.2.1 dst=203.0.113.8 sport=30000 dport=40000 packets=2 bytes=200 mark=0 use=1
ipv6     10 tcp      6 431990 ESTABLISHED src=2001:db8::5 dst=2001:db8::1 sport=55555 dport=20000 packets=4 bytes=400 src=2001:db8::1 dst=2001:db8::5 sport=20000 dport=55555 packets=4 bytes=400 [ASSURED] mark=0 use=1
`

// ---- Status 枚举与四种状态语义 ----

// 情况 1：读取成功、解析成功、0 个相关连接 → 真的没人在线，可释放 slot。
func TestStatusOKWithZeroFlows(t *testing.T) {
	// 只有 icmp 条目：合法读取，但没有本程序关心的流。
	text := "ipv4 2 icmp 1 29 type=8 code=0 id=1 src=1.2.3.4 dst=5.6.7.8 packets=1 bytes=84 mark=0 use=1\n"
	r := scanConntrack(strings.NewReader(text))
	if r.Status != StatusOK {
		t.Fatalf("应为 StatusOK，实际 %s", r.Status)
	}
	if !r.Usable() {
		t.Fatal("完整读取到 0 条相关流时必须可用（允许释放 slot）")
	}
	if len(r.Flows) != 0 {
		t.Fatalf("不应有流，实际 %d", len(r.Flows))
	}
	if r.Entries != 1 {
		t.Fatalf("条目数应为 1，实际 %d", r.Entries)
	}
	if r.Note() != "" {
		t.Fatalf("正常状态不应有说明，实际 %q", r.Note())
	}
}

// 情况 2a：文件不存在 → Unavailable，冻结。
func TestStatusUnavailableFileMissing(t *testing.T) {
	r := ReadConntrack("/nonexistent/dir/nf_conntrack")
	if r.Status != StatusUnavailable {
		t.Fatalf("应为 StatusUnavailable，实际 %s", r.Status)
	}
	if r.Usable() {
		t.Fatal("文件不存在时绝不能认为没人在线")
	}
	if !r.Complete() {
		t.Fatal("「文件不存在」这个结论本身是确定的，Complete 应为 true")
	}
	if r.Note() == "" {
		t.Fatal("应给出说明")
	}
}

// 情况 2b：文件存在但无权限 → Unavailable + Err，冻结。
func TestStatusUnavailableNoPermission(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/nf_conntrack"
	if err := writeFile(path, "ipv4 2 tcp 6 1 ESTABLISHED src=1.2.3.4 dst=2.3.4.5 sport=1 dport=2 bytes=1\n", 0o000); err != nil {
		t.Fatal(err)
	}
	r := ReadConntrack(path)
	// root 下 0000 仍可读，此时应是 OK；非 root 下应是 Unavailable。
	switch r.Status {
	case StatusUnavailable:
		if r.Usable() {
			t.Fatal("无权限时不得可用")
		}
	case StatusOK:
		t.Skip("以 root 运行，0000 权限仍可读，跳过该断言")
	default:
		t.Fatalf("意外状态 %s", r.Status)
	}
}

// 情况 2c：文件可读但整表 0 条 → Unavailable + Inactive，冻结。
func TestStatusUnavailableInactive(t *testing.T) {
	r := scanConntrack(strings.NewReader("\n\n   \n"))
	if r.Status != StatusUnavailable {
		t.Fatalf("空表应为 StatusUnavailable，实际 %s", r.Status)
	}
	if !r.Inactive {
		t.Fatal("应标记 Inactive")
	}
	if r.Usable() {
		t.Fatal("内核未跟踪任何连接时不得据此判定在线")
	}
	if !strings.Contains(r.Note(), "未跟踪") {
		t.Fatalf("说明应指出未跟踪，实际 %q", r.Note())
	}
}

// 情况 3：读到一半失败 → Error，冻结。
func TestStatusErrorMidRead(t *testing.T) {
	rd := &failingReader{
		data: []byte("ipv4 2 tcp 6 1 ESTABLISHED src=1.2.3.4 dst=2.3.4.5 sport=1 dport=2 bytes=1\nipv4 2 tcp"),
		err:  errors.New("input/output error"),
	}
	r := scanConntrack(rd)
	if r.Status != StatusError {
		t.Fatalf("读取中断应为 StatusError，实际 %s", r.Status)
	}
	if r.Complete() {
		t.Fatal("读取中断不得视为完整")
	}
	if r.Usable() {
		t.Fatal("读取中断时不得据此判定在线")
	}
	if r.Err == nil {
		t.Fatal("应保留原始错误")
	}
}

// 情况 4：单行损坏 → Partial，冻结（绝不忽略坏行后声称完整）。
func TestStatusPartialOnMalformedLine(t *testing.T) {
	cases := []struct {
		name string
		text string
	}{
		{"字段太少", "ipv4 2 tcp\n"},
		{"tcp 缺状态", "ipv4 2 tcp 6 100 src=1.2.3.4 dst=2.3.4.5 sport=1 dport=2 bytes=1\n"},
		{"sport 非数字", "ipv4 2 tcp 6 100 ESTABLISHED src=1.2.3.4 dst=2.3.4.5 sport=abc dport=2 bytes=1\n"},
		{"dport 非数字", "ipv4 2 tcp 6 100 ESTABLISHED src=1.2.3.4 dst=2.3.4.5 sport=1 dport=xx bytes=1\n"},
		{"bytes 非数字", "ipv4 2 tcp 6 100 ESTABLISHED src=1.2.3.4 dst=2.3.4.5 sport=1 dport=2 bytes=zz\n"},
		{"缺 src", "ipv4 2 tcp 6 100 ESTABLISHED dst=2.3.4.5 sport=1 dport=2 bytes=1\n"},
		{"缺 dport", "ipv4 2 tcp 6 100 ESTABLISHED src=1.2.3.4 dst=2.3.4.5 sport=1 bytes=1\n"},
	}
	for _, c := range cases {
		r := scanConntrack(strings.NewReader(c.text))
		if r.Status != StatusPartial {
			t.Errorf("%s：应为 StatusPartial，实际 %s", c.name, r.Status)
			continue
		}
		if r.Usable() {
			t.Errorf("%s：坏行存在时不得可用", c.name)
		}
		if r.BadLines == 0 {
			t.Errorf("%s：应统计坏行", c.name)
		}
	}
}

// 好行 + 坏行混合：整体仍是 Partial（部分视图不可作为判定依据）。
func TestStatusPartialMixedGoodAndBad(t *testing.T) {
	text := sampleConntrack + "ipv4 2 tcp 6 100 ESTABLISHED src=1.2.3.4 dst=2.3.4.5 sport=1 dport=zz bytes=1\n"
	r := scanConntrack(strings.NewReader(text))
	if r.Status != StatusPartial {
		t.Fatalf("应为 StatusPartial，实际 %s", r.Status)
	}
	if r.Usable() {
		t.Fatal("混合坏行时不得可用")
	}
	// 已解析出的好流仍然带回来（便于诊断），但不得据此释放 slot。
	if len(r.Flows) == 0 {
		t.Fatal("好行应仍被解析出来（供诊断）")
	}
}

// 非 tcp/udp 协议是合法条目，不算坏行。
func TestNonTCPUDPNotBadLine(t *testing.T) {
	text := "ipv4 2 icmp 1 29 type=8 code=0 id=1 src=1.2.3.4 dst=5.6.7.8 packets=1 bytes=84 mark=0 use=1\n" +
		"ipv4 2 sctp 132 100 ESTABLISHED src=1.2.3.4 dst=5.6.7.8 sport=1 dport=2 bytes=1\n"
	r := scanConntrack(strings.NewReader(text))
	if r.Status != StatusOK {
		t.Fatalf("非 tcp/udp 协议不应算坏行，实际 %s（bad=%d）", r.Status, r.BadLines)
	}
	if len(r.Flows) != 0 {
		t.Fatalf("不应保留非 tcp/udp 流，实际 %d", len(r.Flows))
	}
}

// TIME_WAIT 等收尾状态是合法条目，不算坏行，也不保留。
func TestDeadTCPStatesNotBadLine(t *testing.T) {
	text := "ipv4 2 tcp 6 30 TIME_WAIT src=1.2.3.4 dst=5.6.7.8 sport=1 dport=2 bytes=1\n" +
		"ipv4 2 tcp 6 30 CLOSE_WAIT src=1.2.3.4 dst=5.6.7.8 sport=3 dport=4 bytes=1\n"
	r := scanConntrack(strings.NewReader(text))
	if r.Status != StatusOK {
		t.Fatalf("收尾状态不应算坏行，实际 %s（bad=%d）", r.Status, r.BadLines)
	}
	if len(r.Flows) != 0 {
		t.Fatalf("收尾状态不应保留，实际 %d", len(r.Flows))
	}
}

// ---- 解析正确性 ----

func TestParseConntrackKeepsOnlyLiveStates(t *testing.T) {
	r := scanConntrack(strings.NewReader(sampleConntrack))
	if r.Status != StatusOK {
		t.Fatalf("样本应完整解析，实际 %s（bad=%d）", r.Status, r.BadLines)
	}
	if len(r.Flows) != 4 {
		t.Fatalf("应保留 4 条（2 tcp est + 1 syn_sent + 1 udp），实际 %d: %+v", len(r.Flows), r.Flows)
	}
	for _, f := range r.Flows {
		if f.State == "TIME_WAIT" {
			t.Fatal("TIME_WAIT 必须被丢弃")
		}
	}
	var est *Flow
	for i := range r.Flows {
		if r.Flows[i].SrcIP == "203.0.113.5" {
			est = &r.Flows[i]
		}
	}
	if est == nil {
		t.Fatal("未解析出 ESTABLISHED 流")
	}
	// 双向字节求和：1000 + 800
	if est.Bytes != 1800 {
		t.Fatalf("双向字节应为 1800，实际 %d", est.Bytes)
	}
	if est.OrigDstPort != 20000 || est.SrcPort != 54321 {
		t.Fatalf("端口解析错误: %+v", est)
	}
	if est.Proto != "tcp" || est.State != "ESTABLISHED" {
		t.Fatalf("协议/状态解析错误: %+v", est)
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

func TestParseConntrackUDP(t *testing.T) {
	flows := ParseConntrack(sampleConntrack)
	for _, f := range flows {
		if f.Proto == "udp" {
			if f.State != "udp" {
				t.Fatalf("UDP 状态应标为 udp，实际 %q", f.State)
			}
			if f.OrigDstPort != 30000 || f.SrcIP != "203.0.113.8" {
				t.Fatalf("UDP 字段解析错误: %+v", f)
			}
			if f.Bytes != 500 { // 300 + 200
				t.Fatalf("UDP 双向字节应为 500，实际 %d", f.Bytes)
			}
			return
		}
	}
	t.Fatal("未解析出 UDP 流")
}

// 超长行不应导致整体失败（缓冲足够大）。
func TestLongLineHandled(t *testing.T) {
	pad := strings.Repeat(" extra=1", 2000) // ~16KB
	text := "ipv4 2 tcp 6 100 ESTABLISHED src=1.2.3.4 dst=5.6.7.8 sport=1 dport=2 bytes=10" + pad + "\n"
	r := scanConntrack(strings.NewReader(text))
	if r.Status != StatusOK {
		t.Fatalf("长行应正常解析，实际 %s（bad=%d）", r.Status, r.BadLines)
	}
	if len(r.Flows) != 1 {
		t.Fatalf("应解析出 1 条流，实际 %d", len(r.Flows))
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
	var nilIdx Index
	if got := nilIdx.Get("tcp", 20000); got != nil {
		t.Fatal("nil 索引应返回 nil")
	}
}

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

// ---- 辅助 ----

// failingReader 在输出 data 之后返回 err（模拟读到一半失败）。
type failingReader struct {
	data []byte
	err  error
	pos  int
}

func (r *failingReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, r.err
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}

var _ io.Reader = (*failingReader)(nil)

func writeFile(path, content string, mode uint32) error {
	return writeFileImpl(path, content, mode)
}

// ---- benchmark：验证单次扫描的分配与耗时 ----

func genConntrack(n int) string {
	var b strings.Builder
	b.Grow(n * 220)
	for i := 0; i < n; i++ {
		port := 20000 + i%2000
		sport := 30000 + i%20000
		b.WriteString("ipv4     2 tcp      6 431997 ESTABLISHED src=10.")
		b.WriteString(strconv.Itoa(i % 250))
		b.WriteString(".")
		b.WriteString(strconv.Itoa((i / 250) % 250))
		b.WriteString(".1 dst=192.0.2.1 sport=")
		b.WriteString(strconv.Itoa(sport))
		b.WriteString(" dport=")
		b.WriteString(strconv.Itoa(port))
		b.WriteString(" packets=10 bytes=1000 src=192.0.2.1 dst=10.0.0.1 sport=")
		b.WriteString(strconv.Itoa(port))
		b.WriteString(" dport=")
		b.WriteString(strconv.Itoa(sport))
		b.WriteString(" packets=8 bytes=800 [ASSURED] mark=0 zone=0 use=2\n")
	}
	return b.String()
}

func benchParse(b *testing.B, n int) {
	text := genConntrack(n)
	b.SetBytes(int64(len(text)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := scanConntrack(strings.NewReader(text))
		if r.Status != StatusOK {
			b.Fatalf("解析失败: %s (bad=%d)", r.Status, r.BadLines)
		}
		if len(r.Flows) != n {
			b.Fatalf("流数不符：期望 %d 实得 %d", n, len(r.Flows))
		}
	}
}

func BenchmarkParseConntrack1k(b *testing.B)  { benchParse(b, 1000) }
func BenchmarkParseConntrack10k(b *testing.B) { benchParse(b, 10000) }
func BenchmarkParseConntrack50k(b *testing.B) { benchParse(b, 50000) }

// ---- 零值与旧构造方式的 fail-safe ----

// Result 零值必须被判为不可用（绝不能当成「读取成功、没人在线」）。
func TestZeroValueResultIsFailSafe(t *testing.T) {
	var r Result
	if r.Usable() {
		t.Fatal("Result 零值绝不能可用（否则忘记设置状态就会误释放 slot）")
	}
	if r.status() != StatusUnavailable {
		t.Fatalf("零值应推导为 StatusUnavailable，实际 %s", r.status())
	}
	if r.Note() == "" {
		t.Fatal("零值应给出说明")
	}
}

// 旧构造方式（只设 Available/Partial/Err，不设 Status）语义必须与新枚举一致。
func TestLegacyFieldsDeriveStatus(t *testing.T) {
	cases := []struct {
		name string
		res  Result
		want Status
	}{
		{"Available=true", Result{Available: true}, StatusOK},
		{"Available=false", Result{Available: false}, StatusUnavailable},
		{"Inactive", Result{Available: false, Inactive: true}, StatusUnavailable},
		{"Partial", Result{Available: false, Partial: true}, StatusPartial},
		{"Err", Result{Available: false, Err: errors.New("boom")}, StatusError},
		{"Available+Partial", Result{Available: true, Partial: true}, StatusPartial},
	}
	for _, c := range cases {
		if got := c.res.status(); got != c.want {
			t.Errorf("%s：期望 %s，实际 %s", c.name, c.want, got)
		}
		wantUsable := c.want == StatusOK
		if c.res.Usable() != wantUsable {
			t.Errorf("%s：Usable 应为 %v", c.name, wantUsable)
		}
	}
}

// 显式 Status 优先于旧字段（新代码路径）。
func TestExplicitStatusWins(t *testing.T) {
	// 即使 Available=false，显式 StatusOK 也应可用（构造者明确表达了语义）。
	r := Result{Status: StatusOK}
	if !r.Usable() {
		t.Fatal("显式 StatusOK 应可用")
	}
	// 反之显式 StatusPartial 即使 Available=true 也不可用。
	r2 := Result{Status: StatusPartial, Available: true}
	if r2.Usable() {
		t.Fatal("显式 StatusPartial 不得可用")
	}
}
