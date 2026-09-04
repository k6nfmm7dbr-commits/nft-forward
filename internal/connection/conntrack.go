// Package connection 从 /proc/net/nf_conntrack 观测当前连接。
//
// 在线 IP 必须以真实连接生命周期为依据：
//   - conntrack 可用时，它是 TCP 生命周期的主要事实来源；
//   - SYN_SENT/SYN_RECV = candidate（候选，发起握手未建立）；
//   - ESTABLISHED = active；
//   - FIN/RST/flow 消失后立即从 active 退出（不依赖 /proc 残留）。
//   - 只有 conntrack 不可用/失败时才回退 /proc。
package connection

import (
	"errors"
	"os"
	"strconv"
	"strings"
)

// Flow 是一条 conntrack 流（候选或活跃）。
type Flow struct {
	Proto       string // tcp / udp
	State       string // tcp: ESTABLISHED / SYN_SENT / SYN_RECV；udp: "udp"
	OrigDstPort int    // 原始目标端口（即规则监听端口，conntrack original tuple）
	SrcIP       string // 客户端源 IP
	SrcPort     int    // 客户端源端口
	Bytes       int64  // 双向 bytes 之和（累计）
}

// Result 是 conntrack 读取结果。必须区分四种情况：
//   - Available=true, Flows 可能为空：conntrack 正常，当前确实 0 条相关流；
//   - Available=false, Err==nil, Inactive=false：conntrack 不可用（模块未加载/文件不存在）；
//   - Available=false, Inactive=true：文件可读但整表 0 条 —— 内核没在真正跟踪连接；
//   - Err!=nil：读取失败（不完整），Partial 可能为 true。
type Result struct {
	Flows     []Flow
	Available bool
	Partial   bool
	Err       error

	// Entries 是 conntrack 文件里的总条目数（未经协议/状态过滤）。
	// 用途：区分「conntrack 正常但当前没有相关流」与「conntrack 根本没在跟踪」。
	Entries int

	// Inactive 表示「文件可读但整表 0 条」。出现在没有任何引用 ct 的
	// netfilter 规则的干净机器上：模块已加载、文件存在可读，但内核不建条目。
	// 一台有网络活动的服务器不可能一条 conntrack 都没有（SSH/DNS 自身就会
	// 产生条目），因此「整表为 0」是可靠判据。
	Inactive bool
}

const defaultConntrackPath = "/proc/net/nf_conntrack"

// keepTCPState 报告 TCP 状态是否为「活跃或候选」。
// TIME_WAIT/CLOSE/FIN_WAIT/CLOSE_WAIT/LAST_ACK 等都是已死/收尾状态，丢弃。
func keepTCPState(s string) bool {
	switch s {
	case "ESTABLISHED", "SYN_SENT", "SYN_RECV":
		return true
	}
	return false
}

// ReadConntrack 读取并解析 /proc/net/nf_conntrack。
func ReadConntrack(path string) Result {
	if path == "" {
		path = defaultConntrackPath
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Result{Available: false}
		}
		return Result{Available: false, Partial: true, Err: err}
	}
	text := string(b)
	entries := countEntries(text)
	if entries == 0 {
		// 文件存在可读却一条都没有：内核未真正跟踪连接。作为判活数据源不可用。
		return Result{Available: false, Inactive: true}
	}
	return Result{Flows: ParseConntrack(text), Available: true, Entries: entries}
}

// countEntries 统计 conntrack 文件的非空行数（即总条目数）。
func countEntries(text string) int {
	n := 0
	for _, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) != "" {
			n++
		}
	}
	return n
}

// ParseConntrack 解析 conntrack 文本，保留 tcp(ESTABLISHED/SYN_SENT/SYN_RECV) 与 udp 流。
// 行形如：
//
//	ipv4 2 tcp 6 7199 ESTABLISHED src=1.2.3.4 dst=5.6.7.8 sport=35740 dport=20000
//	    packets=1671 bytes=1906488 src=5.6.7.8 dst=1.2.3.4 sport=20000 dport=35740
//	    packets=1696 bytes=141552 [ASSURED] mark=0 zone=0 use=2
func ParseConntrack(text string) []Flow {
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
