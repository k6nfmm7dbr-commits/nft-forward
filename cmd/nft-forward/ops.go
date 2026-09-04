package main

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/k6nfmm7dbr-commits/nft-forward/internal/config"
	"github.com/k6nfmm7dbr-commits/nft-forward/internal/database"
	"github.com/k6nfmm7dbr-commits/nft-forward/internal/nft"
	"github.com/k6nfmm7dbr-commits/nft-forward/internal/version"
)

func runCmd(name string, args ...string) {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	_ = cmd.Run()
}

func resetToken() error {
	tok, err := config.ResetToken()
	if err != nil {
		return err
	}
	fmt.Println("已重置面板令牌（长度", len(tok), "）。请用新令牌登录。")
	return nil
}

// runUpdate 把在线升级交给安装器脚本执行。
//
// 升级逻辑（下载校验、原子替换、失败回滚）全部在 install.sh 里，Go 侧只做
// 转发：正在运行的二进制不能安全地覆盖自己，由外部脚本替换才可靠。
func runUpdate() {
	self := "/etc/nft-forward/nft-forward.sh"
	if _, err := os.Stat(self); err == nil {
		runCmd("bash", self, "--update")
		return
	}
	fmt.Println("未找到安装器脚本，请运行一键安装命令完成升级:")
	fmt.Println("  bash <(curl -fsSL https://raw.githubusercontent.com/k6nfmm7dbr-commits/nft-forward/main/install.sh)")
}

func runClear() int {
	if err := nft.ClearOwned(context.Background(), nft.ExecRunner{}); err != nil {
		fmt.Println("清理失败:", err)
		return 1
	}
	fmt.Println("已删除自有表 nff_nat4 / nff_nat6 / nff_filter（历史统计数据保留）")
	return 0
}

func selfTest() int {
	cfg := config.Load()
	fail := 0
	check := func(name, status, why string) {
		fmt.Printf("%-4s %-16s %s\n", status, name, why)
		if status == "FAIL" {
			fail++
		}
	}

	if _, err := database.Open(cfg.DB); err != nil {
		check("SQLite", "FAIL", "无法打开数据库: "+err.Error())
	} else {
		check("SQLite", "OK", cfg.DB)
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
		check("ip_forward", "WARN", "无法读取 /proc/sys/net/ipv4/ip_forward")
	}

	if _, err := os.Stat("/proc/net/nf_conntrack"); err == nil {
		check("conntrack", "OK", "/proc/net/nf_conntrack 可读")
	} else {
		check("conntrack", "WARN", "不可用（在线 IP 将回退）")
	}

	acct := strings.TrimSpace(string(mustRead("/proc/sys/net/netfilter/nf_conntrack_acct")))
	if acct == "1" {
		check("ct_acct", "OK", "nf_conntrack_acct=1")
	} else if acct != "" {
		check("ct_acct", "WARN", "nf_conntrack_acct="+acct+"（在线 IP 判活将降级）")
	}

	addr := net.JoinHostPort(cfg.Listen, strconv.Itoa(cfg.Port))
	if conn, err := net.Dial("tcp", addr); err == nil {
		conn.Close()
		check("web server", "OK", addr+" 可连接")
	} else {
		check("web server", "WARN", addr+" 未监听（服务可能未运行）")
	}

	if fail > 0 {
		fmt.Println("自检存在失败项")
		return 1
	}
	fmt.Println("自检通过")
	return 0
}

func mustRead(path string) []byte {
	b, _ := os.ReadFile(path)
	return b
}

func menu() {
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
		fmt.Println("  6. 查看面板地址")
		fmt.Println("  7. 重置面板令牌")
		fmt.Println("  8. 检查更新")
		fmt.Println("  9. 自检")
		fmt.Println("  a. 清理自有表")
		fmt.Println("  0. 退出")
		fmt.Println("━━━━━━━━━━━━━━━━━━━━")
		fmt.Print("请选择: ")
		line, _ := reader.ReadString('\n')
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
			c := config.Load()
			host := publicIP()
			if host == "" {
				host = c.Listen
			}
			fmt.Printf("面板地址: http://%s:%d/\n", host, c.Port)
			fmt.Printf("令牌文件: %s\n", config.ConfPath())
		case "7":
			if err := resetToken(); err != nil {
				fmt.Println("重置失败:", err)
			}
		case "8":
			runUpdate()
		case "9":
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
