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
func EnsurePanelPort() (PortResult, error) { return ensure(false) }

// EnsureAll initializes the panel in a single committed config write.
func EnsureAll() error { _, err := ensure(true); return err }

func ensure(all bool) (PortResult, error) {
	var generated bool
	p, _, _, err := config.Ensure(func(cfg *config.Config) (int, error) {
		if cfg.Port != 0 && !cfg.MigratePort() {
			return cfg.Port, nil
		}
		p, err := choosePort(cfg)
		generated = err == nil
		return p, err
	}, all, all)
	if err != nil {
		return PortResult{}, fmt.Errorf("拒绝初始化面板: %w", err)
	}
	return PortResult{Port: p, Generated: generated}, nil
}

func choosePort(cfg *config.Config) (int, error) {
	taken, err := reservedPorts(cfg)
	if err != nil {
		return 0, err
	}
	inUse := portprobe.InUse()
	for _, avoidEphemeral := range []bool{true, false} {
		port, err := pickPort(taken, inUse, avoidEphemeral)
		if err != nil || port != 0 {
			return port, err
		}
	}
	return 0, fmt.Errorf("无法为面板分配随机端口：两阶段各 %d 次尝试均冲突", maxPortTries)
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
//
// 读取已有转发端口失败时返回 error（fail-closed）：调用方必须中止端口生成/修改，
// 绝不能在「不知道哪些端口正被转发占用」的情况下随机一个新端口。
func reservedPorts(cfg *config.Config) (map[int]bool, error) {
	out := map[int]bool{}
	for p := range cfg.GuardPorts() { // 含面板当前端口 + SSH + 用户 guard_ports
		out[p] = true
	}
	if cfg.Port > 0 {
		out[cfg.Port] = true
	}
	ports, err := configuredRulePorts(cfg)
	if err != nil {
		return nil, err
	}
	for _, p := range ports {
		out[p] = true
	}
	return out, nil
}

// ReservedPorts 是 reservedPorts 的导出版本（供手工改端口的校验复用）。
func ReservedPorts(cfg *config.Config) (map[int]bool, error) { return reservedPorts(cfg) }

// ruleListenPorts 读取已有转发规则的监听端口。
//
// ★ fail-closed 语义（v0.3.2）：
//
//	dbPath 为空 / 文件不存在  → (nil, nil)：真正的首次安装，本就没有规则。
//	文件存在但打不开、schema 异常、查询失败、权限不足 → (nil, error)。
//
// 旧实现对后者也返回空列表，等于「读不到就假装没有规则」，新面板端口可能撞上
// 正在使用的转发端口，用户的转发会被面板抢走。那是 fail-open，必须拒绝。
func configuredRulePorts(cfg *config.Config) ([]int, error) {
	expected, err := config.DatabaseExpected(cfg)
	if err != nil {
		return nil, err
	}
	return readRulePorts(cfg.DB, expected)
}

func ruleListenPorts(path string) ([]int, error) { return readRulePorts(path, false) }

func readRulePorts(path string, expected bool) ([]int, error) {
	if path == "" && !expected {
		return nil, nil
	}
	exists, err := database.Exists(path)
	if err != nil {
		return nil, err
	}
	if !exists {
		if expected {
			return nil, fmt.Errorf("已初始化的规则数据库缺失: %s", path)
		}
		return nil, nil
	}
	db, err := database.OpenReadOnly(path)
	if err != nil {
		return nil, fmt.Errorf("无法打开规则数据库 %s: %w", path, err)
	}
	defer db.Close()
	rows, err := db.QueryContext(context.Background(), `SELECT listen_port FROM rules WHERE deleted=0`)
	if err != nil {
		return nil, fmt.Errorf("无法读取已有转发端口: %w", err)
	}
	defer rows.Close()
	var out []int
	for rows.Next() {
		var port int
		if err := rows.Scan(&port); err != nil {
			return nil, err
		}
		if !forward.ValidPort(port) {
			return nil, fmt.Errorf("数据库中的转发端口非法: %d", port)
		}
		out = append(out, port)
	}
	return out, rows.Err()
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

// ---- 手工修改面板端口（v0.3.2）----
//
// 旧行为：nff 菜单只校验 1 <= port <= 65535，然后写配置 + restart。
// 于是可以把面板端口改成 SSH 端口、已被监听的端口、或某条转发规则的监听端口 ——
// 结果是服务起不来（或抢掉用户的转发），而配置已经被改坏。
//
// 现在改端口必须复用与首次安装等价的全部安全检查，且失败不写配置。

// PortRejection 描述一次端口校验失败的原因。
type PortRejection struct {
	Port   int
	Reason string
}

func (e *PortRejection) Error() string {
	return fmt.Sprintf("端口 %d 不可用：%s", e.Port, e.Reason)
}

// ValidatePanelPort 校验用户手工指定的面板端口。
//
// 检查项（与首次安装的自动选择等价，除 ephemeral 一项）：
//  1. 1-65535
//  2. 不等于当前面板端口（无变化则无需重启）
//  3. TCP 未被监听
//  4. UDP 未被占用
//  5. 不与 SSH 端口冲突
//  6. 不与 guard_ports 冲突
//  7. 不与已有转发规则的监听端口冲突（读不到规则则 fail-closed 拒绝）
//  8. bind 探测可用
//
// ephemeral 区间：手工指定**不强制拒绝**（用户可能确有需要），
// 但返回 warn 文本供调用方提示。自动选择仍会尽量避开。
func ValidatePanelPort(port int) (warn string, err error) {
	cfg, err := config.LoadStrict()
	if err != nil {
		return "", fmt.Errorf("拒绝修改面板端口: %w", err)
	}
	return validatePanelPort(cfg, port)
}

func validatePanelPort(cfg *config.Config, port int) (warn string, err error) {
	if !forward.ValidPort(port) {
		return "", &PortRejection{Port: port, Reason: "必须在 1-65535 之间"}
	}
	if port == cfg.Port {
		return "", &PortRejection{Port: port, Reason: "与当前面板端口相同"}
	}

	// SSH / guard_ports / 已有转发端口（含 fail-closed）。
	if port == cfg.SSHGuard {
		return "", &PortRejection{Port: port, Reason: "与 SSH 端口冲突"}
	}
	for p, label := range cfg.ExtraGuards {
		if p == port {
			return "", &PortRejection{Port: port, Reason: "与保留端口冲突（" + label + "）"}
		}
	}
	rulePorts, err := configuredRulePorts(cfg)
	if err != nil {
		return "", fmt.Errorf("拒绝修改面板端口: %w", err)
	}
	for _, p := range rulePorts {
		if p == port {
			return "", &PortRejection{Port: port, Reason: "已被转发规则用作监听端口"}
		}
	}

	// 系统占用：/proc 监听表 + 实际 bind。
	if portprobe.InUse()[port] {
		return "", &PortRejection{Port: port, Reason: "已被本机进程监听/占用"}
	}
	if portprobe.BindBusy(port, true, true) {
		return "", &PortRejection{Port: port, Reason: "bind 探测失败（端口已被占用）"}
	}

	if portprobe.InEphemeral(port) {
		lo, hi, _ := portprobe.EphemeralRange()
		warn = fmt.Sprintf("端口 %d 落在内核临时端口区间 %d-%d，可能与出站连接偶发冲突",
			port, lo, hi)
	}
	return warn, nil
}

// SetPanelPortChecked 校验并写入新面板端口。返回旧端口（供调用方回滚）。
//
// 只负责「校验 + 写配置」；重启、健康确认与回滚由安装器脚本完成
// （它才有 systemd 与 curl）。
func SetPanelPortChecked(port int) (oldPort int, warn string, err error) {
	_, _, _, err = config.Ensure(func(cfg *config.Config) (int, error) {
		oldPort = cfg.Port
		var err error
		warn, err = validatePanelPort(cfg, port)
		return port, err
	}, false, false)
	return oldPort, warn, err
}
