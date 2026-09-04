// nft-forward：基于 nftables 的高性能端口转发 + 流量监控面板。
//
// 子命令：
//
//	nft-forward serve                启动面板服务
//	nft-forward selftest             自检（SQLite/nft/ip_forward/conntrack 等）
//	nft-forward config-get <key>     读取配置
//	nft-forward config-set <k> <v>   写入配置
//	nft-forward config-migrate       清理废弃配置键
//	nft-forward clear                只删除 nff_* 自有表（不清系统规则）
//	nft-forward（无参数）             运维菜单（不含规则 CRUD，规则统一走 Web 面板）
package main

import (
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
	case "clear", "--clear-firewall":
		os.Exit(runClear())
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
	case "config-migrate":
		dropped, err := config.Migrate()
		if err != nil {
			fmt.Println("迁移失败:", err)
			os.Exit(1)
		}
		if len(dropped) == 0 {
			fmt.Println("无需迁移")
		} else {
			fmt.Println("已删除废弃键:", strings.Join(dropped, ", "))
		}
	case "version", "--version", "-v":
		fmt.Println(version.Name, "v"+version.Version)
	case "menu":
		menu()
	default:
		fmt.Println("未知命令:", args[0])
		fmt.Println("可用: serve / selftest / config-get / config-set / config-migrate / clear / version")
		os.Exit(1)
	}
}
