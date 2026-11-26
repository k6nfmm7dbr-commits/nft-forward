package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/k6nfmm7dbr-commits/nft-forward/internal/config"
	"github.com/k6nfmm7dbr-commits/nft-forward/internal/connection"
	"github.com/k6nfmm7dbr-commits/nft-forward/internal/database"
	"github.com/k6nfmm7dbr-commits/nft-forward/internal/nft"
	"github.com/k6nfmm7dbr-commits/nft-forward/internal/version"
)

func runCmd(name string, args ...string) {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintln(os.Stderr, name, "执行失败:", err)
	}
}

const installedMenuScript = "/etc/nft-forward/nft-forward.sh"

func runClear() int {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	lock, err := config.Lock(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "清理失败:", err)
		return 1
	}
	defer lock.Close()
	if err := nft.ClearOwned(ctx, nft.ExecRunner{}); err != nil {
		fmt.Println("清理失败:", err)
		return 1
	}
	fmt.Println("已删除自有表 nff_nat4 / nff_nat6 / nff_filter（历史统计数据保留）")
	return 0
}

// panelInfo 打印用户真正需要的两行，不暴露配置等文件的位置。
func panelInfo() int {
	return printPanel(os.Stdout, os.Stderr, publicIP, true)
}

func panelURL() int {
	return printPanel(os.Stdout, os.Stderr, publicIP, false)
}

func printPanel(stdout, stderr io.Writer, discoverIP func() string, withToken bool) int {
	c, err := config.LoadStrict()
	if err != nil {
		fmt.Fprintln(stderr, "读取配置失败:", err)
		return 1
	}
	if c.Port == 0 || c.EntryPath == "" || (withToken && c.Token == "") {
		fmt.Fprintln(stderr, "面板尚未完成初始化，请重新运行安装脚本")
		return 1
	}
	address := buildPanelURL(c.Listen, c.Port, c.EntryRoute(), discoverIP)
	if withToken {
		fmt.Fprintln(stdout, "面板地址:", address)
		fmt.Fprintln(stdout, "访问令牌:", c.Token)
	} else {
		fmt.Fprintln(stdout, address)
	}
	return 0
}

func buildPanelURL(listen string, port int, entryRoute string, discoverIP func() string) string {
	host := listen
	ip, _ := netip.ParseAddr(listen)
	if listen == "" || ip.Unmap().IsUnspecified() {
		// Preserve hostname -I discovery for wildcard binds only; use loopback
		// of the appropriate family if discovery fails.
		host = "127.0.0.1"
		if ip.Unmap().Is6() {
			host = "::1"
		}
		if discovered, err := netip.ParseAddr(discoverIP()); err == nil && !discovered.Unmap().IsUnspecified() {
			host = discovered.String()
		}
	}
	u := url.URL{Scheme: "http", Host: net.JoinHostPort(host, strconv.Itoa(port)), Path: entryRoute + "/"}
	return u.String()
}

// selfTest 输出各子系统状态。
//
// 输出刻意只给「项目 + 状态 + 简短说明」，正常情况下不打印任何文件路径
// （配置 / 数据库 / sysctl）。只有失败时才在说明里带上定位问题必需的技术信息。
func selfTest() int {
	cfg, err := config.LoadStrict()
	if err != nil {
		fmt.Fprintln(os.Stderr, "读取配置失败:", err)
		return 1
	}
	if err := cfg.ValidateServe(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fail := 0
	check := func(name, status, why string) {
		fmt.Printf("%-4s %-16s %s\n", status, name, why)
		if status == "FAIL" {
			fail++
		}
	}

	if err := checkDatabase(cfg.DB); err != nil {
		check("SQLite", "FAIL", "无法打开数据库: "+err.Error())
	} else {
		check("SQLite", "OK", "可读")
	}

	if _, err := exec.LookPath("nft"); err != nil {
		check("nftables", "FAIL", "nft 不在 PATH")
	} else {
		out, err := exec.Command("nft", "--version").Output()
		if err != nil {
			check("nftables", "FAIL", "nft --version 失败: "+err.Error())
		} else {
			check("nftables", "OK", strings.TrimSpace(string(out)))
		}
		if err := exec.Command("nft", "list", "tables").Run(); err != nil {
			check("nft netlink", "FAIL", "nft list tables 失败（权限或内核）")
		} else {
			check("nft netlink", "OK", "可列出表")
		}
	}

	if out, err := exec.Command("nft", "list", "tables").Output(); err == nil {
		has := 0
		for _, t := range []string{nft.TableNAT4, nft.TableNAT6, nft.TableFilter} {
			if strings.Contains(string(out), t) {
				has++
			}
		}
		check("owned tables", "OK", fmt.Sprintf("%d/3", has))
	} else {
		check("owned tables", "WARN", "无法列出表（可能尚未应用规则）")
	}

	if b, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward"); err == nil {
		if strings.TrimSpace(string(b)) == "1" {
			check("ip_forward", "OK", "已启用")
		} else {
			check("ip_forward", "WARN", "未启用（转发将不工作）")
		}
	} else {
		check("ip_forward", "WARN", "无法读取内核转发开关")
	}

	if _, err := os.Stat("/proc/net/nf_conntrack"); err == nil {
		res := connection.ReadConntrack("")
		switch {
		case res.Usable():
			check("conntrack", "OK", fmt.Sprintf("%d 条目可读", res.Entries))
		default:
			// conntrack 不可用只降级 IP 限制，不影响转发数据面。
			check("conntrack", "WARN", res.Note())
		}
	} else {
		check("conntrack", "WARN", "不可用（在线 IP 判活将冻结，转发不受影响）")
	}

	acct := strings.TrimSpace(string(mustRead("/proc/sys/net/netfilter/nf_conntrack_acct")))
	if acct == "1" {
		check("ct_acct", "OK", "已开启字节计费")
	} else if acct != "" {
		check("ct_acct", "WARN", "未开启字节计费（在线 IP 判活将降级）")
	}

	// web server：只探本机回环，不依赖公网可达性。
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(cfg.Port))
	if cfg.Port == 0 {
		check("web server", "FAIL", "面板端口尚未初始化")
	} else if conn, err := net.Dial("tcp", addr); err == nil {
		conn.Close()
		check("web server", "OK", "本机可连接")
	} else {
		check("web server", "WARN", "未监听（服务可能未运行）")
	}

	switch {
	case cfg.Token == "" || cfg.EntryPath == "":
		check("authentication", "FAIL", "访问令牌或入口路径尚未初始化")
	case !localAuthWorks(cfg):
		check("authentication", "WARN", "无法在本机验证登录（服务可能未运行）")
	default:
		check("authentication", "OK", "令牌校验通过")
	}

	// data plane：本机 /healthz 是否 200。
	//
	// 200 严格代表「进程已完成首轮 nft enforcement」；503 表示 HTTP 活着但
	// 数据面未加载 —— 这正是需要 FAIL 的情况（旧版本会把它当成健康）。
	switch dataPlaneState(cfg) {
	case dpReady:
		check("data plane", "OK", "首轮 nft enforcement 已完成")
	case dpNotReady:
		check("data plane", "FAIL", "服务在运行但数据面未就绪（首轮 nft enforcement 失败）")
	default:
		check("data plane", "WARN", "无法确认（服务可能未运行）")
	}

	if fail > 0 {
		fmt.Println("自检存在失败项")
		return 1
	}
	fmt.Println("自检通过")
	return 0
}

func checkDatabase(path string) error {
	db, err := database.OpenReadOnly(path)
	if err != nil {
		return err
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	var n int
	return db.QueryRowContext(ctx, "SELECT count(*) FROM rules").Scan(&n)
}

// 数据面状态。
type dpState int

const (
	dpUnknown dpState = iota
	dpReady
	dpNotReady
)

// dataPlaneState 通过本机 /healthz 判断数据面就绪状态。
func dataPlaneState(cfg *config.Config) dpState {
	if cfg.Port == 0 {
		return dpUnknown
	}
	url := "http://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(cfg.Port)) + "/healthz"
	client := &http.Client{Timeout: 4 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return dpUnknown
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	switch resp.StatusCode {
	case http.StatusOK:
		return dpReady
	case http.StatusServiceUnavailable:
		return dpNotReady
	}
	return dpUnknown
}

// localAuthWorks 用本机回环验证认证链路：
// 无凭据访问入口应返回登录页(200)，带 Bearer 访问 /api/healthz 应 200，
// 错误令牌应 401。三者都符合才算认证工作正常。
func localAuthWorks(cfg *config.Config) bool {
	base := "http://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(cfg.Port)) + cfg.EntryRoute()
	client := &http.Client{
		Timeout:       4 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	get := func(path, token string) int {
		req, err := http.NewRequest(http.MethodGet, base+path, nil)
		if err != nil {
			return 0
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := client.Do(req)
		if err != nil {
			return 0
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}
	if get("/api/healthz", cfg.Token) != http.StatusOK {
		return false
	}
	return get("/api/healthz", "0000000000000000000000000000dead") == http.StatusUnauthorized
}

func mustRead(path string) []byte {
	b, _ := os.ReadFile(path)
	return b
}

func menu() int {
	// The installed script owns the menu (including platform-specific service
	// management). A binary using a custom config should not open the system menu.
	if config.AppDir() == "/etc/nft-forward" && config.ConfPath() == "/etc/nft-forward/panel.json" && os.Getenv("NFF_ROOT") == "" {
		if status, handled := runInstalledMenu(installedMenuScript, os.Stdin, os.Stdout, os.Stderr); handled {
			return status
		}
	}
	standaloneMenu()
	return 0
}

func runInstalledMenu(script string, stdin io.Reader, stdout, stderr io.Writer) (int, bool) {
	if _, err := os.Stat(script); err != nil {
		if os.IsNotExist(err) {
			return 0, false
		}
		fmt.Fprintln(stderr, "无法检查已安装的管理脚本:", err)
		return 1, true
	}
	cmd := exec.Command(script)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, stdout, stderr
	if err := cmd.Run(); err != nil {
		if e, ok := err.(*exec.ExitError); ok && e.ExitCode() >= 0 {
			return e.ExitCode(), true
		}
		fmt.Fprintln(stderr, "无法运行已安装的管理脚本:", err)
		return 1, true
	}
	return 0, true
}

func standaloneMenu() {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Println()
		fmt.Println("━━━━━━━━━━━━━━━━━━━━")
		fmt.Println("  " + version.Name + "  v" + version.Version)
		fmt.Println("━━━━━━━━━━━━━━━━━━━━")
		fmt.Println("  1. 服务状态")
		fmt.Println("  2. 启动服务")
		fmt.Println("  3. 停止服务")
		fmt.Println("  4. 重启服务")
		fmt.Println("  5. 查看日志")
		fmt.Println("  6. 查看面板信息")
		fmt.Println("  7. 检查更新")
		fmt.Println("  8. 自检")
		fmt.Println("  a. 清理自有表")
		fmt.Println("  0. 退出")
		fmt.Println("━━━━━━━━━━━━━━━━━━━━")
		fmt.Print("请选择: ")
		line, err := reader.ReadString('\n')
		if len(line) == 0 && err != nil {
			return
		}
		choice := strings.TrimSpace(line)
		switch choice {
		case "1":
			runCmd("systemctl", "status", "nft-forward", "--no-pager", "-l")
		case "2":
			runCmd("systemctl", "start", "nft-forward")
		case "3":
			runCmd("systemctl", "stop", "nft-forward")
		case "4":
			runCmd("systemctl", "restart", "nft-forward")
		case "5":
			runCmd("journalctl", "-u", "nft-forward", "-n", "50", "--no-pager")
		case "6":
			_ = panelInfo()
		case "7":
			fmt.Println("未使用已安装的管理菜单。请按项目 README 下载并校验发行版安装脚本后再升级。")
		case "8":
			selfTest()
		case "a", "A":
			fmt.Print("确认只删除 nff_* 自有表？(yes/N): ")
			ans, _ := reader.ReadString('\n')
			if strings.TrimSpace(ans) == "yes" {
				_ = runClear()
			} else {
				fmt.Println("已取消")
			}
		case "0":
			return
		default:
			fmt.Println("无效选择")
		}
	}
}

func publicIP() string {
	out, err := exec.Command("hostname", "-I").Output()
	if err != nil {
		return ""
	}
	fields := strings.Fields(string(out))
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}
