// Package connection 从 /proc/net/nf_conntrack 观测当前连接。
//
// 在线 IP 必须以真实连接生命周期为依据：
//   - conntrack 可用时，它是 TCP 生命周期的主要事实来源；
//   - SYN_SENT/SYN_RECV = candidate（候选，发起握手未建立）；
//   - ESTABLISHED = active；
//   - FIN/RST/flow 消失后立即从 active 退出（不依赖 /proc 残留）。
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

// Result 是 conntrack 读取结果。
//
// ★ 语义收口（v0.3.1）：必须严格区分「真的没人在线」与「无法确认是否有人在线」。
// 旧实现只有一个 Available 字段，把两者混在一起，结果「读不到 conntrack」
// 被当成「当前 0 个在线 IP」，进而释放所有 slot、清空 allow set —— 真实用户
// 被踢线。现在用两个独立维度表达：
//
//	Available   conntrack 这个数据源本身是否可用（文件存在、可读、内核在跟踪）；
//	Complete()  本次读取是否完整可信（无 IO 错误、无截断）。
//
// 四种状态与判定：
//
//  1. Available && Complete()          读取成功。Flows 可能为空 —— 这才是
//     「真的没人在线」，允许释放 slot。
//  2. !Available && Err==nil && !Inactive
//     conntrack 不可用（模块未加载/文件不存在）。
//  3. !Available && Inactive           文件可读但整表 0 条：内核没在真正跟踪。
//  4. Err != nil || Partial            读取失败或不完整。
//
// 只有第 1 种允许正常做在线判定；其余全部必须冻结上一轮 slot 状态
// （不新增、不释放、不清空 allow set），但规则结构同步照常执行。
//
// Complete 刻意做成方法而非字段：字段的零值 false 会让「只填 Available:true」
// 的构造意外落进「不完整」分支，方法从 Partial/Err 派生则永远自洽。
type Result struct {
	Flows []Flow

	// Available 表示 conntrack 数据源可用（可以据此做在线判定）。
	Available bool

	// Partial 表示本次读取不完整（IO 错误 / 截断）。
	Partial bool

	// Err 是读取错误（nil 表示无错误）。
	Err error

	// Entries 是 conntrack 文件里的总条目数（未经协议/状态过滤）。
	// 用途：区分「conntrack 正常但当前没有相关流」与「conntrack 根本没在跟踪」。
	Entries int

	// Inactive 表示「文件可读但整表 0 条」。出现在没有任何引用 ct 的
	// netfilter 规则的干净机器上：模块已加载、文件存在可读，但内核不建条目。
	// 一台有网络活动的服务器不可能一条 conntrack 都没有（SSH/DNS 自身就会
	// 产生条目），因此「整表为 0」是可靠判据。
	Inactive bool
}

// Complete 报告本次读取是否完整可信。
func (r Result) Complete() bool { return !r.Partial && r.Err == nil }

// Usable 报告本次结果能否作为「在线 IP 生命周期」的判定依据。
//
// 这是 policy 层唯一应该使用的判据：
//   - true  → 可以正常做准入/释放（Flows 为空即真的没人在线）；
//   - false → 必须冻结上一轮 slot 状态（不新增、不释放、不清空 allow set）。
func (r Result) Usable() bool { return r.Available && r.Complete() }

// Note 返回人类可读的状态说明（供 /api/health 与 selftest 展示）。
// 正常可用时返回空串。
func (r Result) Note() string {
	switch {
	case !r.Complete():
		return "conntrack 读取不完整，已冻结在线 IP 状态（规则同步照常执行）"
	case r.Inactive:
		return "conntrack 已加载但未跟踪任何连接，在线 IP 暂不可用"
	case !r.Available:
		return "conntrack 不可用（模块未加载），在线 IP 与 IP 限制不可用"
	default:
		return ""
	}
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
			// 文件不存在：数据源不可用，但这个结论本身是确定的
			// （Complete()==true，Usable()==false —— 不会被当成「无人在线」）。
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

// FlowKey 是流索引的键：协议 + 原始目标端口。
//
// 这是把 conntrack 扫描从 O(规则数 × flow 数) 降到 O(规则数 + flow 数) 的关键：
// 一条规则只关心「自己协议 + 自己监听端口」的流，用这个键一次建索引即可 O(1) 命中。
type FlowKey struct {
	Proto string // tcp / udp
	Port  int    // 原始目标端口（规则监听端口）
}

// Index 是按 FlowKey 分组的流索引。
type Index map[FlowKey][]Flow

// BuildIndex 一次遍历建立 flow 索引。
//
// 复杂度 O(F)。此后每条规则只需按 (proto, listenPort) 取出属于自己的流，
// 无需重新遍历全部 conntrack。
func BuildIndex(flows []Flow) Index {
	idx := make(Index, len(flows))
	for _, f := range flows {
		k := FlowKey{Proto: f.Proto, Port: f.OrigDstPort}
		idx[k] = append(idx[k], f)
	}
	return idx
}

// Get 返回某协议 + 端口的流（无匹配返回 nil）。
func (i Index) Get(proto string, port int) []Flow {
	if i == nil {
		return nil
	}
	return i[FlowKey{Proto: proto, Port: port}]
}
