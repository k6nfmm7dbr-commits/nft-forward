// nft-forward：基于 nftables 的高性能端口转发 + 流量监控面板。
//
// 子命令：
//
//	nft-forward serve                  启动面板服务
//	nft-forward selftest               自检（SQLite/nft/ip_forward/conntrack/认证等）
//	nft-forward config-get <key>       读取配置
//	nft-forward config-set <k> <v>     写入配置
//	nft-forward config-migrate         清理废弃配置键
//	nft-forward config-ensure-token    首次生成 32 位十六进制访问令牌（幂等）
//	nft-forward config-ensure-port     首次生成随机五位数面板端口（幂等）
//	nft-forward config-ensure-entry    首次生成随机面板入口路径（幂等）
//	nft-forward config-ensure-all      一次完成上面三项（安装器用）
//	nft-forward panel-port-check <p>   只校验新面板端口（不写入）
//	nft-forward panel-port-set <p>     校验并写入新面板端口，输出 old_port=<旧端口>
//	nft-forward panel-info             打印面板地址与访问令牌
//	nft-forward clear                  只删除 nff_* 自有表（不清系统规则）
//	nft-forward（无参数）               运维菜单（不含规则 CRUD，规则统一走 Web 面板）
package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/k6nfmm7dbr-commits/nft-forward/internal/config"
	"github.com/k6nfmm7dbr-commits/nft-forward/internal/provision"
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
	case "config-ensure-token":
		// 幂等：已有令牌原样输出，没有则用 crypto/rand 生成 32 位十六进制并写回。
		// panel.json 损坏时 fail-closed（非零退出），安装器必须据此中止。
		tok, err := config.EnsureToken()
		if err != nil {
			fmt.Fprintln(os.Stderr, "生成访问令牌失败:", err)
			os.Exit(1)
		}
		fmt.Println(tok)
	case "config-ensure-entry":
		p, err := config.EnsureEntryPath()
		if err != nil {
			fmt.Fprintln(os.Stderr, "生成面板入口路径失败:", err)
			os.Exit(1)
		}
		fmt.Println(p)
	case "config-ensure-port":
		res, err := provision.EnsurePanelPort()
		if err != nil {
			fmt.Fprintln(os.Stderr, "生成面板端口失败:", err)
			os.Exit(1)
		}
		fmt.Println(res.Port)
	case "config-ensure-all":
		os.Exit(ensureAll())
	case "panel-port-set":
		// 手工修改面板端口：复用与首次安装等价的全部安全检查。
		// 成功时输出 old_port=<旧端口>（供安装器回滚），可能附带 warn=<提示>。
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "用法: nft-forward panel-port-set <端口>")
			os.Exit(1)
		}
		port, perr := strconv.Atoi(strings.TrimSpace(args[1]))
		if perr != nil {
			fmt.Fprintln(os.Stderr, "端口必须是数字:", args[1])
			os.Exit(1)
		}
		oldPort, warn, err := provision.SetPanelPortChecked(port)
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			os.Exit(1)
		}
		fmt.Printf("old_port=%d\n", oldPort)
		if warn != "" {
			fmt.Printf("warn=%s\n", warn)
		}
	case "panel-port-check":
		// 只校验不写入（供脚本预检）。
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "用法: nft-forward panel-port-check <端口>")
			os.Exit(1)
		}
		port, perr := strconv.Atoi(strings.TrimSpace(args[1]))
		if perr != nil {
			fmt.Fprintln(os.Stderr, "端口必须是数字:", args[1])
			os.Exit(1)
		}
		warn, err := provision.ValidatePanelPort(port)
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			os.Exit(1)
		}
		if warn != "" {
			fmt.Printf("warn=%s\n", warn)
		}
		fmt.Println("ok")
	case "panel-info":
		os.Exit(panelInfo())
	case "version", "--version", "-v":
		fmt.Println(version.Name, "v"+version.Version)
	case "menu":
		menu()
	default:
		fmt.Println("未知命令:", args[0])
		fmt.Println("可用: serve / selftest / config-get / config-set / config-migrate / " +
			"config-ensure-token / config-ensure-port / config-ensure-entry / config-ensure-all / " +
			"panel-port-check / panel-port-set / panel-info / clear / version")
		os.Exit(1)
	}
}

// ensureAll 一次完成三项初始化（端口 → 令牌 → 入口路径），任一失败即非零退出。
//
// 顺序无关紧要（三者互不依赖），但都必须成功：安装器据退出码决定是否继续。
func ensureAll() int {
	if _, err := provision.EnsurePanelPort(); err != nil {
		fmt.Fprintln(os.Stderr, "生成面板端口失败:", err)
		return 1
	}
	if _, err := config.EnsureToken(); err != nil {
		fmt.Fprintln(os.Stderr, "生成访问令牌失败:", err)
		return 1
	}
	if _, err := config.EnsureEntryPath(); err != nil {
		fmt.Fprintln(os.Stderr, "生成面板入口路径失败:", err)
		return 1
	}
	c, err := config.LoadStrict()
	if err != nil {
		fmt.Fprintln(os.Stderr, "读取配置失败:", err)
		return 1
	}
	if err := c.ValidateServe(); err != nil {
		fmt.Fprintln(os.Stderr, "初始化未完成:", err)
		return 1
	}
	fmt.Println("ok")
	return 0
}
