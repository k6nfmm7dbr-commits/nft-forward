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

// Result 是 conntrack 读取结果。必须区分三种情况：
//   - Available=true, Flows 可能为空：conntrack 正常，当前确实 0 条流；
//   - Available=false, Err==nil：conntrack 不可用（模块未加载/文件不存在）；
//   - Err!=nil：读取失败（不完整），Partial 可能为 true。
type Result struct {
	Flows     []Flow
	Available bool
	Partial   bool
	Err       error
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
	return Result{Flows: ParseConntrack(string(b)), Available: true}
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
