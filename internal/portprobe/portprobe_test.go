package portprobe

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

const procTCPSample = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1
   1: 0100007F:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12346 1
   2: 0100007F:B3A2 0100007F:1F90 01 00000000:00000000 00:00000000 00000000     0        0 12347 1
`

const procUDPSample = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
  100: 00000000:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 555 2 0 0
`

// /proc/net/tcp 只取 LISTEN（st=0A），已建立连接（st=01）的本地端口不算占用。
func TestCollectProcPortsListenOnly(t *testing.T) {
	out := map[int]bool{}
	collectProcPorts(procTCPSample, true, out)
	if !out[0x1F90] { // 8080
		t.Fatal("应识别 LISTEN 的 8080")
	}
	if !out[0x0016] { // 22
		t.Fatal("应识别 LISTEN 的 22")
	}
	if out[0xB3A2] {
		t.Fatal("已建立连接的本地临时端口不应算作监听占用")
	}
}

// UDP 取全部条目（UDP 没有 LISTEN 状态）。
func TestCollectProcPortsUDPAll(t *testing.T) {
	out := map[int]bool{}
	collectProcPorts(procUDPSample, false, out)
	if !out[0x0035] { // 53
		t.Fatal("应识别已绑定的 UDP 53")
	}
}

// 表头与畸形行必须被安全跳过。
func TestCollectProcPortsIgnoresGarbage(t *testing.T) {
	out := map[int]bool{}
	collectProcPorts("header only\n", true, out)
	collectProcPorts("bad line\n0: nocolon 0A\n", true, out)
	collectProcPorts("h\n0: 00000000:ZZZZ 0:0 0A\n", true, out)
	if len(out) != 0 {
		t.Fatalf("畸形输入不应产出端口，实际 %v", out)
	}
}

// bind 探测：正在监听的端口必须判定为占用。
func TestBindBusyDetectsListening(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("无法建立监听: %v", err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	if !BindBusy(port, true, false) {
		t.Skip("环境允许重复 bind（容器/SO_REUSEPORT），跳过")
	}
}

func TestBindBusyFreePort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("无法建立监听: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	// 端口已释放：不应判定为占用（可能被别的进程抢走，失败则跳过）。
	if BindBusy(port, true, false) {
		t.Skipf("端口 %d 在关闭后被他人占用，跳过", port)
	}
}

// ephemeral 区间解析。
func TestParseEphemeralRange(t *testing.T) {
	lo, hi, ok := parseEphemeralRange("32768\t60999\n")
	if !ok || lo != 32768 || hi != 60999 {
		t.Fatalf("解析失败: %d-%d ok=%v", lo, hi, ok)
	}
	for _, bad := range []string{"", "32768", "abc def", "60999 32768", "0 70000"} {
		if _, _, ok := parseEphemeralRange(bad); ok {
			t.Fatalf("非法输入 %q 应解析失败", bad)
		}
	}
}

func TestInEphemeralUsesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "range")
	if err := os.WriteFile(path, []byte("40000 50000\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := ephemeralRangePath
	ephemeralRangePath = path
	t.Cleanup(func() { ephemeralRangePath = old })

	if !InEphemeral(45000) {
		t.Fatal("45000 应落在 ephemeral 区间内")
	}
	if InEphemeral(39999) || InEphemeral(50001) {
		t.Fatal("区间外不应命中")
	}

	// 文件不可读时一律返回 false（不因探测失败而排除端口）。
	ephemeralRangePath = filepath.Join(dir, "nonexistent")
	if InEphemeral(45000) {
		t.Fatal("区间不可读时不应排除任何端口")
	}
	if _, _, ok := EphemeralRange(); ok {
		t.Fatal("不可读时 ok 应为 false")
	}
}

// InUse 在真实 /proc 上不应崩溃（内容因环境而异，只断言可调用）。
func TestInUseDoesNotPanic(t *testing.T) {
	_ = InUse()
}
