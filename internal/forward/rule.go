// Package forward 定义转发规则模型、校验与冲突检查。
//
// 数据模型要求稳定且不复用的 ID，软删除（deleted 标记），历史流量不因删除丢失。
// 冲突检查：两条规则协议集合相交 + 相同监听端口 即冲突（DNAT 按端口匹配，
// 与监听地址无关；0.0.0.0:X 会覆盖任何具体地址的 :X）。
package forward

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// 协议常量。
const (
	ProtoTCP    = "tcp"
	ProtoUDP    = "udp"
	ProtoTCPUDP = "tcp+udp"
)

// Rule 是一条转发规则。
type Rule struct {
	ID            int64  `json:"id"`
	Name          string `json:"name"`
	Enabled       bool   `json:"enabled"`
	Protocol      string `json:"protocol"` // tcp / udp / tcp+udp
	ListenAddress string `json:"listen_address"`
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
}

// HasTCP 报告规则是否承载 TCP。
func (r *Rule) HasTCP() bool {
	return r.Protocol == ProtoTCP || r.Protocol == ProtoTCPUDP
}

// HasUDP 报告规则是否承载 UDP。
func (r *Rule) HasUDP() bool {
	return r.Protocol == ProtoUDP || r.Protocol == ProtoTCPUDP
}

// ValidProtocol 报告协议串是否合法。
func ValidProtocol(p string) bool {
	switch p {
	case ProtoTCP, ProtoUDP, ProtoTCPUDP:
		return true
	}
	return false
}

// isAny 报告监听地址是否为「任意地址」（空串、0.0.0.0、::）。
func isAny(addr string) bool {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return true
	}
	ip := net.ParseIP(addr)
	return ip != nil && ip.IsUnspecified()
}

// isIPv4 报告地址是否为 IPv4。
func isIPv4(addr string) bool {
	addr = strings.TrimSpace(addr)
	if addr == "" || addr == "0.0.0.0" {
		return true // 默认按 IPv4 任意地址
	}
	ip := net.ParseIP(addr)
	return ip != nil && ip.To4() != nil
}

// Validate 校验规则自身字段合法性（不含冲突检查）。
func Validate(r *Rule) error {
	if strings.TrimSpace(r.Name) == "" {
		return fmt.Errorf("规则名称不能为空")
	}
	if !ValidProtocol(r.Protocol) {
		return fmt.Errorf("协议非法: %q（应为 tcp/udp/tcp+udp）", r.Protocol)
	}
	if r.ListenPort < 1 || r.ListenPort > 65535 {
		return fmt.Errorf("监听端口必须在 1-65535: %d", r.ListenPort)
	}
	if r.TargetPort < 1 || r.TargetPort > 65535 {
		return fmt.Errorf("目标端口必须在 1-65535: %d", r.TargetPort)
	}
	// 地址合法性。
	la := strings.TrimSpace(r.ListenAddress)
	if la == "" {
		la = "0.0.0.0" // 默认任意地址
	}
	if !isAny(la) && net.ParseIP(la) == nil {
		return fmt.Errorf("监听地址非法: %q", r.ListenAddress)
	}
	ta := strings.TrimSpace(r.TargetAddress)
	if ta == "" {
		return fmt.Errorf("目标地址不能为空")
	}
	if ip := net.ParseIP(ta); ip == nil || ip.IsUnspecified() {
		return fmt.Errorf("目标地址非法: %q", r.TargetAddress)
	}
	// 地址族必须一致（IPv4→IPv4 / IPv6→IPv6），禁止 NAT64/46。
	if isIPv4(la) != isIPv4(ta) {
		return fmt.Errorf("监听地址与目标地址的地址族必须一致（IPv4→IPv4 / IPv6→IPv6）")
	}
	// 策略数值。
	if r.QuotaEnabled && r.QuotaLimitBytes <= 0 {
		return fmt.Errorf("流量额度必须 > 0")
	}
	if r.IPLimitEnabled && r.IPLimitMax < 1 {
		return fmt.Errorf("最大同时在线数必须 >= 1")
	}
	return nil
}

// ConflictsWith 报告本规则是否与另一条规则在「协议+监听端口」上冲突。
// DNAT 按端口匹配，地址不影响冲突判定。
func (r *Rule) ConflictsWith(other *Rule) bool {
	if r.ListenPort != other.ListenPort {
		return false
	}
	// 协议集合相交才冲突。
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

// CheckConflicts 校验新规则不与已有规则冲突，且不占用保留端口。
// existing 只应包含未删除的规则。selfID 用于编辑时排除自身。
func CheckConflicts(r *Rule, existing []*Rule, guard GuardPorts) error {
	if err := Validate(r); err != nil {
		return err
	}
	if label, ok := guard[r.ListenPort]; ok {
		return fmt.Errorf("监听端口 %d 已被 %s 占用，不能用作转发", r.ListenPort, label)
	}
	for _, o := range existing {
		if o.Deleted {
			continue
		}
		if o.ID == r.ID {
			continue // 编辑自身，跳过
		}
		if r.ConflictsWith(o) {
			return fmt.Errorf("与规则「%s」(#%d %s :%d) 冲突：相同协议不能使用相同监听端口",
				o.Name, o.ID, o.Protocol, o.ListenPort)
		}
	}
	return nil
}

// Now 返回当前 Unix 秒。
func Now() int64 { return time.Now().Unix() }
