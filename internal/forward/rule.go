// Package forward 定义转发规则模型、校验与冲突检查。
//
// 数据模型要求稳定且不复用的 ID，软删除（deleted 标记），历史流量不因删除丢失。
//
// 监听语义（v0.2 起）：规则**没有监听地址**概念。用户只配置监听端口，
// 规则自动作用于「目的地址属于本机」的数据包（nft 侧用 fib daddr type local
// 限定），因此不会误劫持仅路由经过本机的 transit 流量。
//
// 冲突判定：协议集合相交 + 相同监听端口 即冲突（DNAT 只按端口匹配）。
package forward

import (
	"fmt"
	"strings"
	"time"
)

// 协议常量。
const (
	ProtoTCP    = "tcp"
	ProtoUDP    = "udp"
	ProtoTCPUDP = "tcp+udp"
)

// 解析状态常量（域名规则运行时状态）。
const (
	// ResolveNA 表示无需解析（目标是 IP 字面量）。
	ResolveNA = ""
	// ResolveOK 表示最近一次解析成功。
	ResolveOK = "ok"
	// ResolveStale 表示最近一次解析失败，正在沿用上次有效地址。
	ResolveStale = "stale"
	// ResolveFailed 表示解析失败且没有可用的历史地址。
	ResolveFailed = "failed"
)

// maxNameLen 是规则名称长度上限（字符数，按 rune 计）。
const maxNameLen = 64

// Rule 是一条转发规则。
//
// 用户配置字段：Name / Enabled / Protocol / ListenPort / TargetAddress /
// TargetPort，以及 Quota、IPLimit 策略字段。
//
// 运行时解析结果（Resolved*）由后台 DNS reconcile 维护，用户不直接配置，
// API 只读暴露。它与用户配置严格分离：TargetAddress 永远保存用户填写的原始
// 值（域名保持域名，绝不被解析结果覆盖）。
type Rule struct {
	ID            int64  `json:"id"`
	Name          string `json:"name"`
	Enabled       bool   `json:"enabled"`
	Protocol      string `json:"protocol"` // tcp / udp / tcp+udp
	ListenPort    int    `json:"listen_port"`
	TargetAddress string `json:"target_address"`
	TargetPort    int    `json:"target_port"`
	CreatedAt     int64  `json:"created_at"`
	UpdatedAt     int64  `json:"updated_at"`
	Deleted       bool   `json:"deleted"`
	DeletedAt     int64  `json:"deleted_at,omitempty"`

	// 策略
	QuotaEnabled       bool  `json:"quota_enabled"`
	QuotaLimitBytes    int64 `json:"quota_limit_bytes"`
	QuotaResetBaseline int64 `json:"quota_reset_baseline,omitempty"`
	IPLimitEnabled     bool  `json:"ip_limit_enabled"`
	IPLimitMax         int   `json:"ip_limit_max"`

	// 运行时 DNS 解析结果（只读；IP 目标时为空）。
	ResolvedV4    string `json:"resolved_ipv4,omitempty"`
	ResolvedV6    string `json:"resolved_ipv6,omitempty"`
	ResolvedAt    int64  `json:"resolved_at,omitempty"`
	ResolveStatus string `json:"resolve_status,omitempty"`
	ResolveError  string `json:"resolve_error,omitempty"`
}

// TargetKind 返回目标地址形态。
func (r *Rule) TargetKind() TargetKind { return KindOf(r.TargetAddress) }

// IsDomainTarget 报告目标是否为域名。
func (r *Rule) IsDomainTarget() bool { return r.TargetKind() == TargetDomain }

// HasTCP 报告规则是否承载 TCP。
func (r *Rule) HasTCP() bool {
	return r.Protocol == ProtoTCP || r.Protocol == ProtoTCPUDP
}

// HasUDP 报告规则是否承载 UDP。
func (r *Rule) HasUDP() bool {
	return r.Protocol == ProtoUDP || r.Protocol == ProtoTCPUDP
}

// DialV4 返回本规则当前应写入 IPv4 数据面的目标地址（无则空串）。
//
// IP 目标：字面量本身决定数据面；域名目标：使用最近一次有效解析结果。
// 绝不做 NAT64/NAT46 —— IPv4 数据面只会指向 IPv4 目标。
func (r *Rule) DialV4() string {
	switch r.TargetKind() {
	case TargetIPv4:
		return strings.TrimSpace(r.TargetAddress)
	case TargetDomain:
		return strings.TrimSpace(r.ResolvedV4)
	default:
		return ""
	}
}

// DialV6 返回本规则当前应写入 IPv6 数据面的目标地址（无则空串）。
func (r *Rule) DialV6() string {
	switch r.TargetKind() {
	case TargetIPv6:
		return strings.TrimSpace(r.TargetAddress)
	case TargetDomain:
		return strings.TrimSpace(r.ResolvedV6)
	default:
		return ""
	}
}

// Resolvable 报告规则当前是否有可用的数据面目标。
// 域名解析全部失败（且无历史地址）时为 false —— 此时不生成任何 DNAT 规则，
// 但规则本身与其 counter / 配额 / IP 限制状态一律保留。
func (r *Rule) Resolvable() bool { return r.DialV4() != "" || r.DialV6() != "" }

// ValidProtocol 报告协议串是否合法。
func ValidProtocol(p string) bool {
	switch p {
	case ProtoTCP, ProtoUDP, ProtoTCPUDP:
		return true
	}
	return false
}

// NormalizeName 去除首尾空白并校验名称长度。
func NormalizeName(raw string) (string, error) {
	n := strings.TrimSpace(raw)
	if n == "" {
		return "", fmt.Errorf("规则名称不能为空")
	}
	if len([]rune(n)) > maxNameLen {
		return "", fmt.Errorf("规则名称过长（最多 %d 个字符）", maxNameLen)
	}
	if strings.ContainsAny(n, "\r\n\t") {
		return "", fmt.Errorf("规则名称不能包含换行或制表符")
	}
	return n, nil
}

// ValidPort 报告端口是否在合法区间。
func ValidPort(p int) bool { return p >= 1 && p <= 65535 }

// Normalize 就地规范化用户可配置字段，供 Validate 之前调用。
//
// 注意：不处理 ListenPort==0（自动分配）——那是 PortAllocator 的职责，
// 必须在 Validate 之前完成分配。
func Normalize(r *Rule) error {
	name, err := NormalizeName(r.Name)
	if err != nil {
		return err
	}
	r.Name = name
	r.Protocol = strings.ToLower(strings.TrimSpace(r.Protocol))
	if !ValidProtocol(r.Protocol) {
		return fmt.Errorf("协议非法: %q（应为 tcp/udp/tcp+udp）", r.Protocol)
	}
	target, _, err := NormalizeTarget(r.TargetAddress)
	if err != nil {
		return err
	}
	r.TargetAddress = target
	return nil
}

// Validate 校验规则自身字段合法性（不含冲突检查、不含 DNS 解析）。
func Validate(r *Rule) error {
	if err := Normalize(r); err != nil {
		return err
	}
	if !ValidPort(r.ListenPort) {
		return fmt.Errorf("监听端口必须在 1-65535: %d", r.ListenPort)
	}
	if !ValidPort(r.TargetPort) {
		return fmt.Errorf("目标端口必须在 1-65535: %d", r.TargetPort)
	}
	if r.QuotaEnabled && r.QuotaLimitBytes <= 0 {
		return fmt.Errorf("流量额度必须 > 0")
	}
	if r.IPLimitEnabled && r.IPLimitMax < 1 {
		return fmt.Errorf("最大同时在线数必须 >= 1")
	}
	return nil
}

// ConflictsWith 报告本规则是否与另一条规则在「协议+监听端口」上冲突。
func (r *Rule) ConflictsWith(other *Rule) bool {
	if r.ListenPort != other.ListenPort {
		return false
	}
	if r.HasTCP() && other.HasTCP() {
		return true
	}
	if r.HasUDP() && other.HasUDP() {
		return true
	}
	return false
}

// GuardPorts 是转发规则不允许占用的保留端口（面板、SSH 等）。
type GuardPorts map[int]string

// CheckPort 只做端口层面的检查（保留端口 + 与既有规则冲突），不校验其它字段。
// existing 只应包含未删除的规则；同 ID 视为自身并跳过。
func CheckPort(r *Rule, existing []*Rule, guard GuardPorts) error {
	if label, ok := guard[r.ListenPort]; ok {
		return fmt.Errorf("监听端口 %d 已被%s占用，请改用其它端口", r.ListenPort, label)
	}
	for _, o := range existing {
		if o == nil || o.Deleted || o.ID == r.ID {
			continue
		}
		if r.ConflictsWith(o) {
			return fmt.Errorf("与规则「%s」使用了相同的 %s 监听端口 %d",
				o.Name, protoLabel(r, o), r.ListenPort)
		}
	}
	return nil
}

// protoLabel 给出两条规则重叠的协议文案（用于友好错误提示）。
func protoLabel(a, b *Rule) string {
	tcp := a.HasTCP() && b.HasTCP()
	udp := a.HasUDP() && b.HasUDP()
	switch {
	case tcp && udp:
		return "TCP/UDP"
	case udp:
		return "UDP"
	default:
		return "TCP"
	}
}

// CheckConflicts 校验新规则字段合法且不与已有规则冲突、不占用保留端口。
func CheckConflicts(r *Rule, existing []*Rule, guard GuardPorts) error {
	if err := Validate(r); err != nil {
		return err
	}
	return CheckPort(r, existing, guard)
}

// Now 返回当前 Unix 秒。
func Now() int64 { return time.Now().Unix() }
