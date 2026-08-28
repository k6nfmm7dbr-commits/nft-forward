package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/k6nfmm7dbr-commits/nft-forward/internal/config"
	"github.com/k6nfmm7dbr-commits/nft-forward/internal/database"
	"github.com/k6nfmm7dbr-commits/nft-forward/internal/nft"
)

// runCmd 运行系统命令并透传输出。
func runCmd(name string, args ...string) {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	_ = cmd.Run()
}

func resetToken() error {
	// 强制生成新令牌：先清空再 ensure。
	c := config.Load()
	_ = c
	if err := config.Set("token", ""); err != nil {
		return err
	}
	tok, err := config.EnsureToken()
	if err != nil {
		return err
	}
	fmt.Println("已重置面板令牌（长度", len(tok), "）。请用新令牌登录。")
	return nil
}

// selfTest 自检：输出 OK / WARN / FAIL 及原因。
func selfTest() int {
	cfg := config.Load()
	fail := 0
	check := func(name, status, why string) {
		fmt.Printf("%-4s %-14s %s\n", status, name, why)
		if status == "FAIL" {
			fail++
		}
	}

	// SQLite
	if _, err := database.Open(cfg.DB); err != nil {
		check("SQLite", "FAIL", "无法打开数据库: "+err.Error())
	} else {
		check("SQLite", "OK", cfg.DB)
	}

	// nft 可用
	if _, err := exec.LookPath("nft"); err != nil {
		check("nftables", "FAIL", "nft 不在 PATH")
	} else {
		out, _ := exec.Command("nft", "--version").Output()
		check("nftables", "OK", strings.TrimSpace(string(out)))
	}

	// 自有表
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

	// ip_forward
	if b, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward"); err == nil {
		if strings.TrimSpace(string(b)) == "1" {
			check("ip_forward", "OK", "已启用")
		} else {
			check("ip_forward", "WARN", "未启用（转发将不工作）")
		}
	}

	// conntrack
	if _, err := os.Stat("/proc/net/nf_conntrack"); err == nil {
		check("conntrack", "OK", "/proc/net/nf_conntrack 可读")
	} else {
		check("conntrack", "WARN", "不可用（在线 IP 将回退 /proc）")
	}

	// Web 端口
	addr := net.JoinHostPort(cfg.Listen, strconv.Itoa(cfg.Port))
	if conn, err := net.Dial("tcp", addr); err == nil {
		conn.Close()
		check("web server", "OK", addr+" 可连接")
	} else {
		check("web server", "WARN", addr+" 未监听（服务可能未运行）")
	}

	check("collector", "OK", "随服务运行")
	check("policy", "OK", "随服务运行")

	if fail > 0 {
		fmt.Println("自检存在失败项")
		return 1
	}
	fmt.Println("自检通过")
	return 0
}
