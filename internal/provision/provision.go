// Package provision 实现「首次安装期一次性生成、之后永久保持」的初始化步骤：
// 面板随机端口、访问令牌、随机入口路径。
//
// 三者的共同语义：
//   - 已存在即原样返回（服务重启 / 在线升级 / 重复运行安装脚本都不改变）；
//   - 只有用户显式改端口这类操作才会变更；
//   - 生成一律用 crypto/rand（禁止 math/rand、禁止 shell $RANDOM）；
//   - 生成失败就明确失败，绝不 fallback 到固定值。
package provision

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"os"

	"github.com/k6nfmm7dbr-commits/nft-forward/internal/config"
	"github.com/k6nfmm7dbr-commits/nft-forward/internal/database"
	"github.com/k6nfmm7dbr-commits/nft-forward/internal/forward"
	"github.com/k6nfmm7dbr-commits/nft-forward/internal/portprobe"
)

// maxPortTries 是随机面板端口**每个阶段**的尝试次数上限。
//
// 区间有 55536 个候选，正常机器占用不足千个，200 次尝试的失败概率已可忽略；
// 取 512 是为了在极端环境（大量监听端口）下仍有余量。
// 两阶段全部用尽后返回错误 —— 绝不 fallback 到 8090 / 34567 / 任何固定端口。
const maxPortTries = 512

// PortResult 描述一次面板端口确定的结果。
type PortResult struct {
	Port      int
	Generated bool // true = 本次新生成并已持久化；false = 沿用已有配置
}

// EnsurePanelPort 保证 panel.json 里有一个合法面板端口。
//
// 已有端口 → 原样返回（升级 / 重启 / 重复安装都不变）。
// 没有端口 → 在 10000-65535 内用 crypto/rand 选一个未被占用的，持久化后返回。
//
// 冲突判据（任一命中即重新随机）：
//  1. TCP 已监听（/proc/net/tcp[6] LISTEN）
//  2. UDP 已占用（/proc/net/udp[6]）
//  3. bind 探测失败（兜底 /proc 不可读的环境）
//  4. 内核 ephemeral 区间（/proc/sys/net/ipv4/ip_local_port_range）—— **软约束**
//  5. SSH 端口
//  6. guard_ports
//  7. 配置里残留的面板端口
//  8. 已有转发规则的监听端口
//
// ★ 为什么 ephemeral 是软约束（两阶段）：
//
//	不少经过网络调优的机器把 ip_local_port_range 设成 1024/10240 到 65535，
//	几乎覆盖整个候选区间。若把它当硬约束，端口永远分配不出来（真机实测：
//	10240-65535 下 512 次尝试全部失败）。因此先在「避开 ephemeral」模式下尝试，
//	用尽后退化为「不排除 ephemeral，但仍做全部占用与保留检查」——
//	仍然是密码学随机 + 真实占用探测，绝不是固定端口 fallback。
func EnsurePanelPort() (PortResult, error) {
	cfg, err := config.LoadStrict()
	if err != nil {
		return PortResult{}, fmt.Errorf("拒绝生成面板端口: %w", err)
	}
	// v0.3.0 及更早版本的固定默认端口是一个公开指纹：升级时一次性重新随机。
	// 用户自己设的任何其它端口一律不动。
	if cfg.MigratePort() {
		if err := config.ClearPort(); err != nil {
			return PortResult{}, fmt.Errorf("清理遗留默认端口失败: %w", err)
		}
		if cfg, err = config.LoadStrict(); err != nil {
			return PortResult{}, err
		}
	}
	if cfg.Port >= 1 && cfg.Port <= 65535 {
		return PortResult{Port: cfg.Port}, nil
	}
	taken := reservedPorts(cfg)
	inUse := portprobe.InUse()

	// 阶段 1：避开 ephemeral；阶段 2：放宽该项（其余检查不变）。
	for _, avoidEphemeral := range []bool{true, false} {
		port, perr := pickPort(taken, inUse, avoidEphemeral)
		if perr != nil {
			return PortResult{}, perr
		}
		if port == 0 {
			continue // 本阶段用尽尝试次数，进入下一阶段
		}
		if err := config.SetPort(port); err != nil {
			return PortResult{}, fmt.Errorf("写入面板端口失败: %w", err)
		}
		return PortResult{Port: port, Generated: true}, nil
	}
	return PortResult{}, fmt.Errorf(
		"无法为面板分配随机端口：两阶段各 %d 次尝试均冲突。请检查本机端口占用后重试，"+
			"或手工执行 nft-forward config-set port <端口>", maxPortTries)
}

// pickPort 在区间内随机挑一个可用端口。
// 返回 0 表示本阶段尝试次数用尽（不是错误）；error 只在随机源失效时返回。
func pickPort(taken, inUse map[int]bool, avoidEphemeral bool) (int, error) {
	span := config.PanelPortMax - config.PanelPortMin + 1
	for i := 0; i < maxPortTries; i++ {
		p, err := randInt(span)
		if err != nil {
			return 0, err
		}
		port := config.PanelPortMin + p
		if taken[port] || inUse[port] {
			continue
		}
		if avoidEphemeral && portprobe.InEphemeral(port) {
			continue
		}
		if portprobe.BindBusy(port, true, true) {
			continue
		}
		return port, nil
	}
	return 0, nil
}

// reservedPorts 汇总「绝不能作为面板端口」的集合。
func reservedPorts(cfg *config.Config) map[int]bool {
	out := map[int]bool{}
	for p := range cfg.GuardPorts() { // 含面板当前端口 + SSH + 用户 guard_ports
		out[p] = true
	}
	if cfg.Port > 0 {
		out[cfg.Port] = true
	}
	for _, p := range ruleListenPorts(cfg.DB) {
		out[p] = true
	}
	return out
}

// ruleListenPorts 读取已有转发规则的监听端口。
//
// 只读且容错：数据库不存在（全新安装）或打不开时返回空 —— 此时本就没有规则。
func ruleListenPorts(dbPath string) []int {
	if dbPath == "" {
		return nil
	}
	if _, err := os.Stat(dbPath); err != nil {
		return nil
	}
	db, err := database.Open(dbPath)
	if err != nil {
		return nil
	}
	defer db.Close()
	rules, err := forward.NewStore(db.DB).ListActive(context.Background())
	if err != nil {
		return nil
	}
	out := make([]int, 0, len(rules))
	for _, r := range rules {
		if r != nil && r.ListenPort > 0 {
			out = append(out, r.ListenPort)
		}
	}
	return out
}

// randInt 返回 [0, n) 内的密码学安全随机整数（拒绝取模偏置）。
func randInt(n int) (int, error) {
	if n <= 0 {
		return 0, fmt.Errorf("随机区间非法: %d", n)
	}
	limit := ^uint64(0) - (^uint64(0) % uint64(n)) // 最大可用无偏上界
	var b [8]byte
	for i := 0; i < 64; i++ {
		if _, err := rand.Read(b[:]); err != nil {
			return 0, fmt.Errorf("crypto/rand 不可用: %w", err)
		}
		v := binary.BigEndian.Uint64(b[:])
		if v >= limit {
			continue // 落在会造成偏置的尾部区间，重抽
		}
		return int(v % uint64(n)), nil
	}
	return 0, fmt.Errorf("crypto/rand 连续 64 次未取到无偏样本")
}
