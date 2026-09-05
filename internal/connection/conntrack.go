// Package connection 从 /proc/net/nf_conntrack 观测当前连接。
//
// 在线 IP 必须以真实连接生命周期为依据：
//   - conntrack 可用时，它是 TCP 生命周期的主要事实来源；
//   - SYN_SENT/SYN_RECV = candidate（候选，发起握手未建立）；
//   - ESTABLISHED = active；
//   - FIN/RST/flow 消失后立即从 active 退出（不依赖 /proc 残留）。
package connection

import (
	"bufio"
	"errors"
	"io"
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

// Status 是 conntrack 数据源的状态枚举。
//
// ★ 为什么要枚举（v0.3.2 收口）：旧实现把「读到了、确实 0 条连接」与
// 「读不到 / 读了一半 / 有坏行」都塞进 Available=false，于是
// 「无法确认是否有人在线」被当成「确认没人在线」，slot 被误释放、真实用户被踢。
//
// 四种状态语义完全不同，必须显式区分。
type Status int

// conntrack 数据源状态。
//
// ★ 零值必须是「不可用」：Result{} 未初始化时绝不能被判定为「读取成功、
// 没人在线」。因此 StatusUnknown 占据 0，任何忘记设置 Status 的构造都会
// 落进 fail-safe 分支（冻结 slot）而不是误释放。
const (
	// StatusUnknown 是零值：状态未设置，视为不可用（fail-safe）。
	StatusUnknown Status = iota
	// StatusOK 表示成功完整读取并解析。Flows 可能为空 —— 那就是「真的没人在线」。
	StatusOK
	// StatusUnavailable 表示数据源不可用（文件不存在 / 无权限 / 内核未跟踪）。
	StatusUnavailable
	// StatusPartial 表示读到部分数据后中断，或有行解析失败（内容不完整）。
	StatusPartial
	// StatusError 表示读取过程出错。
	StatusError
)

// String 返回状态的可读名。
func (s Status) String() string {
	switch s {
	case StatusOK:
		return "ok"
	case StatusUnavailable:
		return "unavailable"
	case StatusPartial:
		return "partial"
	case StatusError:
		return "error"
	}
	return "unknown"
}

// Result 是 conntrack 读取结果。
//
// 状态矩阵与 slot 行为：
//
//	Status         Available Complete Usable  slot 行为
//	StatusOK       true      true     true    正常准入/释放（Flows 空 = 真没人在线）
//	StatusUnavailable false  true     false   冻结上一轮 slot
//	StatusPartial  false     false    false   冻结上一轮 slot
//	StatusError    false     false    false   冻结上一轮 slot
//
// 只有 Usable()==true 才允许新授 / 释放 slot、重算 allow set。
type Result struct {
	Flows []Flow

	// Status 是数据源状态（唯一权威判据的来源）。
	Status Status

	// Available 表示 conntrack 数据源可用（Status==StatusOK）。
	// 保留该字段是为了让既有调用方与测试语义不变。
	Available bool

	// Partial 表示本次读取不完整（IO 中断 / 有行解析失败）。
	Partial bool

	// Err 是读取错误（nil 表示无错误）。
	Err error

	// Entries 是 conntrack 文件里的总条目数（未经协议/状态过滤）。
	// 用途：区分「conntrack 正常但当前没有相关流」与「conntrack 根本没在跟踪」。
	Entries int

	// BadLines 是解析失败的行数。>0 即视为内容不完整（StatusPartial）：
	// 简单忽略坏行等于用「不完整的连接视图」做在线判定，会误踢用户。
	BadLines int

	// Inactive 表示「文件可读但整表 0 条」。出现在没有任何引用 ct 的
	// netfilter 规则的干净机器上：模块已加载、文件存在可读，但内核不建条目。
	// 一台有网络活动的服务器不可能一条 conntrack 都没有（SSH/DNS 自身就会
	// 产生条目），因此「整表为 0」是可靠判据。
	Inactive bool
}

// Complete 报告本次读取是否完整可信。
func (r Result) Complete() bool {
	return r.status() != StatusPartial && r.status() != StatusError
}

// Usable 报告本次结果能否作为「在线 IP 生命周期」的判定依据。
//
// 这是 policy 层唯一应该使用的判据：
//   - true  → 可以正常做准入/释放（Flows 为空即真的没人在线）；
//   - false → 必须冻结上一轮 slot 状态（不新增、不释放、不清空 allow set）。
func (r Result) Usable() bool { return r.status() == StatusOK }

// status 返回有效状态。
//
// 兼容既有构造方式：不少调用方（含测试）直接写
// Result{Available: true, ...} / Result{Available: false, Partial: true}
// 而不设置 Status。这里按旧字段推导，保证语义一致：
//
//	Partial/Err   → StatusPartial / StatusError
//	Available     → StatusOK
//	Inactive      → StatusUnavailable
//	其余（零值）   → StatusUnavailable（fail-safe，绝不当成「没人在线」）
func (r Result) status() Status {
	if r.Status != StatusUnknown {
		return r.Status
	}
	switch {
	case r.Err != nil:
		return StatusError
	case r.Partial:
		return StatusPartial
	case r.Available:
		return StatusOK
	default:
		return StatusUnavailable
	}
}

// Note 返回人类可读的状态说明（供 /api/health 与 selftest 展示）。
// 正常可用时返回空串。
func (r Result) Note() string {
	switch r.status() {
	case StatusError:
		return "conntrack 读取失败，已冻结在线 IP 状态（规则同步照常执行）"
	case StatusPartial:
		return "conntrack 读取不完整，已冻结在线 IP 状态（规则同步照常执行）"
	case StatusUnavailable:
		if r.Inactive {
			return "conntrack 已加载但未跟踪任何连接，在线 IP 暂不可用"
		}
		return "conntrack 不可用（模块未加载或无权限），在线 IP 与 IP 限制不可用"
	}
	return ""
}

// newResult 按状态构造 Result，保证派生字段自洽。
func newResult(st Status) Result {
	return Result{
		Status:    st,
		Available: st == StatusOK,
		Partial:   st == StatusPartial || st == StatusError,
	}
}

const defaultConntrackPath = "/proc/net/nf_conntrack"

// maxLineBytes 是单行缓冲上限。
//
// conntrack 行通常 < 300 字节；IPv6 + 大量扩展字段的极端行也远小于 64 KiB。
// 设置足够大的缓冲避免 bufio.Scanner 因超长行直接失败（那会被算成 Partial）。
const maxLineBytes = 64 * 1024

// keepTCPState 报告 TCP 状态是否为「活跃或候选」。
// TIME_WAIT/CLOSE/FIN_WAIT/CLOSE_WAIT/LAST_ACK 等都是已死/收尾状态，丢弃。
func keepTCPState(s string) bool {
	switch s {
	case "ESTABLISHED", "SYN_SENT", "SYN_RECV":
		return true
	}
	return false
}

// 协议与状态的常量字符串。
//
// 为什么要 intern：解析器工作在 []byte 上，每次 string(tok) 都是一次堆分配。
// conntrack 的协议名与状态名取值极少且固定，直接返回常量即可把
// 「每条流 3 次分配」降到「每条流 1 次」（只剩必须复制的源 IP）。
const (
	protoTCP = "tcp"
	protoUDP = "udp"
)

// tcpStates 是全部可能出现的 TCP 状态名（含已死状态，用于格式校验）。
var tcpStates = []string{
	"ESTABLISHED", "SYN_SENT", "SYN_RECV",
	"FIN_WAIT", "CLOSE_WAIT", "LAST_ACK", "TIME_WAIT", "CLOSE",
	"SYN_RECV2", "NONE",
}

// internTCPState 把状态 token 映射到常量字符串；未知格式返回 ""。
func internTCPState(tok []byte) string {
	for _, s := range tcpStates {
		if equalStr(tok, s) {
			return s
		}
	}
	return ""
}

// ReadConntrack 读取并解析 conntrack。
//
// ★ 单次流式扫描（v0.3.2）：旧实现是
//
//	os.ReadFile → string(b) → strings.Split（全文切成 []string）
//	→ countEntries 遍历一遍 → ParseConntrack 再 Split 一遍再遍历
//
// 即「两次全文 Split + 两次遍历 + 一份整文件字符串 + 两个大 []string」。
// 500ms 周期下这是持续的 GC 压力。现在改为 bufio.Scanner 单次逐行扫描，
// 同一趟里完成：条目统计、协议/状态过滤、字段解析、坏行计数、完整性判定。
func ReadConntrack(path string) Result {
	if path == "" {
		path = defaultConntrackPath
	}
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// 文件不存在：数据源不可用，但这个结论本身是确定的。
			return newResult(StatusUnavailable)
		}
		// 权限不足等：同样不可用，且带上错误便于诊断。
		res := newResult(StatusUnavailable)
		res.Err = err
		return res
	}
	defer f.Close()
	return scanConntrack(f)
}

// scanConntrack 单次流式解析（导出给测试复用的内部实现）。
func scanConntrack(r io.Reader) Result {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 8*1024), maxLineBytes)

	var (
		flows    []Flow
		entries  int
		badLines int
	)
	for sc.Scan() {
		line := sc.Bytes()
		if len(trimSpaceBytes(line)) == 0 {
			continue
		}
		entries++
		fl, ok, keep := parseLine(line)
		if !ok {
			badLines++
			continue
		}
		if keep {
			flows = append(flows, fl)
		}
	}
	if err := sc.Err(); err != nil {
		// 读到一半失败：内容不完整，必须冻结。
		res := newResult(StatusError)
		res.Err = err
		res.Entries = entries
		res.BadLines = badLines
		res.Flows = flows
		return res
	}
	if entries == 0 {
		// 文件存在可读却一条都没有：内核未真正跟踪连接。作为判活数据源不可用。
		res := newResult(StatusUnavailable)
		res.Inactive = true
		return res
	}
	if badLines > 0 {
		// 有行解析失败 → 连接视图不完整。绝不「忽略坏行后当成完整」。
		res := newResult(StatusPartial)
		res.Entries = entries
		res.BadLines = badLines
		res.Flows = flows
		return res
	}
	res := newResult(StatusOK)
	res.Entries = entries
	res.Flows = flows
	return res
}

// ParseConntrack 解析 conntrack 文本（保留给测试与外部调用）。
//
// 只返回流列表；完整性信息请用 ReadConntrack / scanConntrack。
func ParseConntrack(text string) []Flow {
	return scanConntrack(strings.NewReader(text)).Flows
}

// trimSpaceBytes 去掉首尾空白（避免 string(line) 产生额外分配）。
func trimSpaceBytes(b []byte) []byte {
	start := 0
	for start < len(b) && isSpaceByte(b[start]) {
		start++
	}
	end := len(b)
	for end > start && isSpaceByte(b[end-1]) {
		end--
	}
	return b[start:end]
}

func isSpaceByte(c byte) bool {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\v' || c == '\f'
}

// parseLine 解析一行 conntrack。
//
// 返回值：
//
//	flow  解析出的流（keep==false 时无意义）
//	ok    该行是否是**可识别**的 conntrack 条目（false = 坏行，计入 BadLines）
//	keep  是否需要保留（协议/状态过滤后仍关心）
//
// 行形如（tcp 有状态字段，udp 没有）：
//
//	ipv4 2 tcp 6 7199 ESTABLISHED src=1.2.3.4 dst=5.6.7.8 sport=35740 dport=20000
//	    packets=1671 bytes=1906488 src=5.6.7.8 dst=1.2.3.4 sport=20000 dport=35740
//	    packets=1696 bytes=141552 [ASSURED] mark=0 zone=0 use=2
//	ipv4 2 udp 17 29 src=1.2.3.4 dst=5.6.7.8 sport=40000 dport=30000 …
//
// 因此字段位置不能硬编码「第 6 个之后才是 key=value」——udp 的 src= 就在第 6 个
// （下标 5）。这里改为：含 '=' 的 token 一律按 key=value 解析，
// tcp 的下标 5 且不含 '=' 时才当状态字段。
//
// 判定「坏行」的标准刻意保守：
//   - 字段数不足、协议字段缺失 → 坏行；
//   - tcp 行缺状态字段或状态格式非法 → 坏行；
//   - 关心的协议里缺 src= 或 dport=，或数值字段解析失败 → 坏行；
//   - 非 tcp/udp 协议（icmp 等）→ 正常行但不保留（keep=false）。
func parseLine(line []byte) (Flow, bool, bool) {
	var f Flow

	// 逐字段扫描，不做整行 Split（避免 []string 分配）。
	var (
		fieldIdx  int
		proto     string
		state     string
		gotSrc    bool
		gotSport  bool
		gotDport  bool
		protoSeen bool
	)
	for start := 0; start < len(line); {
		for start < len(line) && isSpaceByte(line[start]) {
			start++
		}
		if start >= len(line) {
			break
		}
		end := start
		for end < len(line) && !isSpaceByte(line[end]) {
			end++
		}
		tok := line[start:end]
		start = end
		idx := fieldIdx
		fieldIdx++

		if idx == 2 {
			switch {
			case equalStr(tok, protoTCP):
				proto = protoTCP
			case equalStr(tok, protoUDP):
				proto = protoUDP
			default:
				// icmp / sctp / dccp 等：合法条目但本程序不关心。
				return f, true, false
			}
			protoSeen = true
			continue
		}
		if idx < 2 {
			continue // family / protonum
		}

		eq := indexByteIn(tok, '=')
		if eq < 0 {
			// 非 key=value：tcp 的状态字段，或 [ASSURED] / 纯数字（timeout 等）。
			if idx == 5 && proto == protoTCP && state == "" {
				// 未知格式返回 ""，随后 validTCPState 会把该行判为坏行。
				state = internTCPState(tok)
				if state == "" {
					return f, false, false
				}
			}
			continue
		}
		key := tok[:eq]
		val := tok[eq+1:]
		switch {
		case !gotSrc && equalStr(key, "src"):
			if len(val) == 0 {
				return f, false, false
			}
			f.SrcIP = string(val)
			gotSrc = true
		case !gotSport && equalStr(key, "sport"):
			n, err := atoiBytes(val)
			if err != nil {
				return f, false, false
			}
			f.SrcPort = n
			gotSport = true
		case !gotDport && equalStr(key, "dport"):
			n, err := atoiBytes(val)
			if err != nil {
				return f, false, false
			}
			f.OrigDstPort = n
			gotDport = true
		case equalStr(key, "bytes"):
			n, err := atoi64Bytes(val)
			if err != nil {
				return f, false, false
			}
			f.Bytes += n
		}
	}

	if !protoSeen || fieldIdx < 6 {
		return f, false, false // 字段太少，无法识别
	}
	f.Proto = proto
	switch proto {
	case protoTCP:
		if !validTCPState(state) {
			return f, false, false // tcp 行必须有格式合法的状态字段
		}
		f.State = state
		if !keepTCPState(state) {
			return f, true, false // TIME_WAIT 等：合法但丢弃
		}
	case protoUDP:
		f.State = protoUDP
	}
	if f.SrcIP == "" || f.OrigDstPort == 0 {
		// 关心的协议缺关键字段 → 视图不完整，算坏行。
		return f, false, false
	}
	return f, true, true
}

// validTCPState 报告 token 是否形如 TCP 状态名（大写字母 + 下划线）。
//
// 为什么要校验格式：若某行缺了状态字段，位置上的 token 会是别的内容
// （例如 `src=1.2.3.4`）。不校验就会把它当成一个「未知但合法」的状态、
// 随后被 keepTCPState 静默丢弃 —— 一条损坏行被当成正常行处理，
// 完整性判定失效。
func validTCPState(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'A' && c <= 'Z') || c == '_' {
			continue
		}
		return false
	}
	return true
}

func indexByteIn(b []byte, c byte) int {
	for i := 0; i < len(b); i++ {
		if b[i] == c {
			return i
		}
	}
	return -1
}

func equalStr(b []byte, s string) bool {
	if len(b) != len(s) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if b[i] != s[i] {
			return false
		}
	}
	return true
}

// atoiBytes 解析非负十进制整数（不分配字符串）。
func atoiBytes(b []byte) (int, error) {
	n, err := atoi64Bytes(b)
	return int(n), err
}

func atoi64Bytes(b []byte) (int64, error) {
	if len(b) == 0 {
		return 0, strconv.ErrSyntax
	}
	var v int64
	for _, c := range b {
		if c < '0' || c > '9' {
			return 0, strconv.ErrSyntax
		}
		v = v*10 + int64(c-'0')
		if v < 0 {
			return 0, strconv.ErrRange
		}
	}
	return v, nil
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
