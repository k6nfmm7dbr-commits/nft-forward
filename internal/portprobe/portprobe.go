// Package portprobe 集中「端口是否可用」的所有探测逻辑。
//
// 为什么单独成包：面板端口（首次安装随机五位数）与转发规则监听端口（留空随机）
// 需要完全相同的判据，两处各写一遍必然漂移。
//
// 探测手段（全部只读，绝不改变系统状态）：
//   - /proc/net/{tcp,tcp6,udp,udp6}：内核视角的真实占用（含 LISTEN 与已绑定
//     的 UDP socket），比 bind 探测更全面 —— bind 到 0.0.0.0 成功并不代表
//     没有别的进程绑在具体地址上；
//   - bind 探测：补足 /proc 不可读（容器/受限环境）时的兜底；
//   - /proc/sys/net/ipv4/ip_local_port_range：内核 ephemeral 区间，
//     自动分配时尽量避开，避免与出站连接的临时端口打架。
package portprobe

import (
	"net"
	"os"
	"strconv"
	"strings"
)

// procPaths 是解析占用状态的 /proc 文件（tcp/tcp6 只取 LISTEN，udp 取全部）。
var procPaths = []struct {
	path       string
	listenOnly bool
}{
	{"/proc/net/tcp", true},
	{"/proc/net/tcp6", true},
	{"/proc/net/udp", false},
	{"/proc/net/udp6", false},
}

// tcpListenState 是 /proc/net/tcp 里 LISTEN 状态的十六进制值。
const tcpListenState = "0A"

// InUse 返回本机当前已被占用的端口集合（TCP LISTEN + 已绑定 UDP）。
//
// /proc 不可读时返回空集合（调用方仍会做 bind 探测），不返回错误 ——
// 端口选择不应该因为 /proc 受限而整体失败。
func InUse() map[int]bool {
	out := map[int]bool{}
	for _, p := range procPaths {
		data, err := os.ReadFile(p.path)
		if err != nil {
			continue
		}
		collectProcPorts(string(data), p.listenOnly, out)
	}
	return out
}

// collectProcPorts 解析 /proc/net/{tcp,udp} 文本，把本地端口填进 out。
//
// 行格式（第一行是表头）：
//
//	sl  local_address rem_address   st tx_queue:rx_queue ...
//	0: 00000000:1F90 00000000:0000 0A ...
func collectProcPorts(text string, listenOnly bool, out map[int]bool) {
	for i, line := range strings.Split(text, "\n") {
		if i == 0 {
			continue // 表头
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		if listenOnly && !strings.EqualFold(fields[3], tcpListenState) {
			continue
		}
		local := fields[1]
		idx := strings.LastIndex(local, ":")
		if idx < 0 || idx+1 >= len(local) {
			continue
		}
		port, err := strconv.ParseInt(local[idx+1:], 16, 32)
		if err != nil || port <= 0 || port > 65535 {
			continue
		}
		out[int(port)] = true
	}
}

// BindBusy 用实际 bind 探测端口占用（TCP 与 UDP 分别探测）。
// 任一协议 bind 失败即视为占用。
func BindBusy(port int, tcp, udp bool) bool {
	addr := ":" + strconv.Itoa(port)
	if tcp {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return true
		}
		_ = ln.Close()
	}
	if udp {
		pc, err := net.ListenPacket("udp", addr)
		if err != nil {
			return true
		}
		_ = pc.Close()
	}
	return false
}

// ephemeralRangePath 是内核 ephemeral 端口区间（变量便于测试覆盖）。
var ephemeralRangePath = "/proc/sys/net/ipv4/ip_local_port_range"

// EphemeralRange 返回内核本地端口区间 [lo, hi]。
// 读取失败或格式异常时 ok=false（调用方据此跳过该项约束，而不是猜一个区间）。
func EphemeralRange() (lo, hi int, ok bool) {
	data, err := os.ReadFile(ephemeralRangePath)
	if err != nil {
		return 0, 0, false
	}
	return parseEphemeralRange(string(data))
}

func parseEphemeralRange(text string) (lo, hi int, ok bool) {
	fields := strings.Fields(text)
	if len(fields) < 2 {
		return 0, 0, false
	}
	a, err1 := strconv.Atoi(fields[0])
	b, err2 := strconv.Atoi(fields[1])
	if err1 != nil || err2 != nil || a < 1 || b > 65535 || a > b {
		return 0, 0, false
	}
	return a, b, true
}

// InEphemeral 报告 port 是否落在内核 ephemeral 区间内。
// 区间不可读时一律返回 false（不因探测失败而排除端口）。
func InEphemeral(port int) bool {
	lo, hi, ok := EphemeralRange()
	if !ok {
		return false
	}
	return port >= lo && port <= hi
}

// SetEphemeralPathForTest 覆盖 ephemeral 区间文件路径，返回恢复函数。
//
// 仅供测试使用：跨包测试（forward 包的分配器）需要控制这个输入，
// 而 Go 的包级私有变量无法跨包赋值。
func SetEphemeralPathForTest(path string) func() {
	old := ephemeralRangePath
	ephemeralRangePath = path
	return func() { ephemeralRangePath = old }
}
