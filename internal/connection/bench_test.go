package connection

import (
	"os"
	"strconv"
	"strings"
	"testing"
)

// ---- 性能对照：旧实现 vs 新实现 ----
//
// 保留旧实现只为一个目的：给出可复现的 before/after 数字，并防止有人
// 「顺手改回去」时无从判断代价。它不参与生产路径。
//
// 旧实现的问题（每轮 500ms 都要付一次）：
//
//	os.ReadFile          → 整个文件一份 []byte
//	string(b)            → 再一份完整字符串副本
//	strings.Split(text)  → 一个含全部行的 []string（countEntries 用）
//	strings.Split(text)  → 又一个同样大的 []string（ParseConntrack 用）
//	strings.Fields(line) → 每行再一个 []string
//
// 即「两次全文 Split + 两次全文遍历 + 每行一次 Fields」。

// legacyCountEntries 是旧的条目统计（第一次全文 Split）。
func legacyCountEntries(text string) int {
	n := 0
	for _, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) != "" {
			n++
		}
	}
	return n
}

// legacyParseConntrack 是旧的解析实现（第二次全文 Split + 每行 Fields）。
func legacyParseConntrack(text string) []Flow {
	var out []Flow
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		proto := fields[2]
		var state string
		switch proto {
		case "tcp":
			state = fields[5]
			if !keepTCPState(state) {
				continue
			}
		case "udp":
			state = "udp"
		default:
			continue
		}

		var f Flow
		f.Proto = proto
		f.State = state
		var gotSrc, gotSport, gotDport bool
		for _, field := range fields {
			switch {
			case strings.HasPrefix(field, "src=") && !gotSrc:
				f.SrcIP = field[len("src="):]
				gotSrc = true
			case strings.HasPrefix(field, "sport=") && !gotSport:
				f.SrcPort, _ = strconv.Atoi(field[len("sport="):])
				gotSport = true
			case strings.HasPrefix(field, "dport=") && !gotDport:
				f.OrigDstPort, _ = strconv.Atoi(field[len("dport="):])
				gotDport = true
			case strings.HasPrefix(field, "bytes="):
				if v, err := strconv.ParseInt(field[len("bytes="):], 10, 64); err == nil {
					f.Bytes += v
				}
			}
		}
		if f.SrcIP == "" || f.OrigDstPort == 0 {
			continue
		}
		out = append(out, f)
	}
	return out
}

// legacyRead 复刻旧的 ReadConntrack 全流程（含两次遍历）。
func legacyRead(text string) (int, []Flow) {
	entries := legacyCountEntries(text)
	if entries == 0 {
		return 0, nil
	}
	return entries, legacyParseConntrack(text)
}

func benchLegacy(b *testing.B, n int) {
	text := genConntrack(n)
	b.SetBytes(int64(len(text)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		entries, flows := legacyRead(text)
		if entries != n || len(flows) != n {
			b.Fatalf("旧实现结果不符：entries=%d flows=%d", entries, len(flows))
		}
	}
}

func BenchmarkLegacyParseConntrack1k(b *testing.B)  { benchLegacy(b, 1000) }
func BenchmarkLegacyParseConntrack10k(b *testing.B) { benchLegacy(b, 10000) }
func BenchmarkLegacyParseConntrack50k(b *testing.B) { benchLegacy(b, 50000) }

// 新旧实现在正常输入上必须给出相同的流列表（性能改写不改变语义）。
func TestNewParserMatchesLegacyOnValidInput(t *testing.T) {
	for _, n := range []int{1, 7, 100, 1000} {
		text := genConntrack(n)
		want := legacyParseConntrack(text)
		got := ParseConntrack(text)
		if len(want) != len(got) {
			t.Fatalf("n=%d 流数不符：旧 %d 新 %d", n, len(want), len(got))
		}
		for i := range want {
			if want[i] != got[i] {
				t.Fatalf("n=%d 第 %d 条不符：\n旧 %+v\n新 %+v", n, i, want[i], got[i])
			}
		}
	}
	// 混合样本（含 TIME_WAIT / udp / ipv6）同样必须一致。
	want := legacyParseConntrack(sampleConntrack)
	got := ParseConntrack(sampleConntrack)
	if len(want) != len(got) {
		t.Fatalf("样本流数不符：旧 %d 新 %d", len(want), len(got))
	}
	for i := range want {
		if want[i] != got[i] {
			t.Fatalf("样本第 %d 条不符：\n旧 %+v\n新 %+v", i, want[i], got[i])
		}
	}
}

// 真实 /proc/net/nf_conntrack 可读时做一次冒烟（CI runner 上通常不可读，跳过）。
func TestReadRealConntrackIfAvailable(t *testing.T) {
	const p = "/proc/net/nf_conntrack"
	if _, err := os.Stat(p); err != nil {
		t.Skipf("本机无 %s，跳过（这是环境限制，不是实现问题）", p)
	}
	r := ReadConntrack(p)
	switch r.Status {
	case StatusOK:
		t.Logf("真实 conntrack：%d 条目，%d 条相关流", r.Entries, len(r.Flows))
	case StatusUnavailable:
		t.Logf("真实 conntrack 不可用（inactive=%v err=%v）", r.Inactive, r.Err)
	default:
		t.Fatalf("真实 conntrack 解析出现 %s（bad=%d）—— 说明解析器与本机格式不符",
			r.Status, r.BadLines)
	}
}
