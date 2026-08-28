// nft-forward：基于 nftables 的高性能端口转发 + 流量监控面板。
//
// 子命令：
//
//	nft-forward serve              启动面板服务
//	nft-forward selftest           自检（SQLite/nft/ip_forward/conntrack 等）
//	nft-forward config-ensure-token 确保面板令牌存在
//	nft-forward config-get <key>   读取配置
//	nft-forward config-set <k> <v> 写入配置
//	nft-forward（无参数）           运维菜单（不含规则 CRUD，规则统一走 Web 面板）
package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/k6nfmm7dbr-commits/nft-forward/internal/config"
	"github.com/k6nfmm7dbr-commits/nft-forward/internal/service"
	"github.com/k6nfmm7dbr-commits/nft-forward/internal/version"
)

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		menu()
		return
	}
	switch args[0] {
	case "serve":
		os.Exit(service.Serve())
	case "selftest":
		os.Exit(selfTest())
	case "config-ensure-token":
		tok, err := config.EnsureToken()
		if err != nil {
			fmt.Println("生成令牌失败:", err)
			os.Exit(1)
		}
		fmt.Println("面板令牌已就绪（长度", len(tok), "）")
	case "config-get":
		if len(args) < 2 {
			fmt.Println("用法: nft-forward config-get <key>")
			os.Exit(1)
		}
		c := config.Load()
		fmt.Println(c.Str(args[1]))
	case "config-set":
		if len(args) < 3 {
			fmt.Println("用法: nft-forward config-set <key> <value>")
			os.Exit(1)
		}
		if err := config.Set(args[1], strings.Join(args[2:], " ")); err != nil {
			fmt.Println("写入失败:", err)
			os.Exit(1)
		}
		fmt.Println("已写入", args[1])
	case "version", "--version", "-v":
		fmt.Println(version.Name, version.Version)
	case "menu":
		menu()
	default:
		fmt.Println("未知命令:", args[0])
		fmt.Println("可用: serve / selftest / config-ensure-token / config-get / config-set / version")
		os.Exit(1)
	}
}

// menu 是 SSH 运维菜单。规则的新增/修改/删除统一走 Web 面板，不在这里实现。
func menu() {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Println()
		fmt.Println("━━━━━━━━━━━━━━━━━━━━")
		fmt.Println("  " + version.Name + "  " + version.Version)
		fmt.Println("━━━━━━━━━━━━━━━━━━━━")
		fmt.Println("  1. 服务状态")
		fmt.Println("  2. 启动服务")
		fmt.Println("  3. 停止服务")
		fmt.Println("  4. 重启服务")
		fmt.Println("  5. 查看日志")
		fmt.Println("  6. 查看面板地址")
		fmt.Println("  7. 重置面板密码")
		fmt.Println("  8. 更新程序")
		fmt.Println("  9. 自检")
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
			fmt.Printf("面板地址: http://%s:%d\n", c.Listen, c.Port)
		case "7":
			if err := resetToken(); err != nil {
				fmt.Println("重置失败:", err)
			}
		case "8":
			fmt.Println("更新请使用发布脚本（保留数据库/配置）。")
		case "9":
			selfTest()
		case "0":
			return
		default:
			fmt.Println("无效选择")
		}
	}
}
