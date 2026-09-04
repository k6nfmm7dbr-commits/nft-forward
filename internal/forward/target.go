// Package forward 定义转发规则模型、目标地址校验、端口分配与冲突检查。
package forward

import (
	"fmt"
	"net/netip"
	"strings"
)

// TargetKind 是目标地址的形态。
type TargetKind string

// 目标地址形态常量。
const (
	// TargetIPv4 是字面量 IPv4 地址。
	TargetIPv4 TargetKind = "ipv4"
	// TargetIPv6 是字面量 IPv6 地址。
	TargetIPv6 TargetKind = "ipv6"
	// TargetDomain 是域名（运行时由 DNS 解析出实际地址）。
	TargetDomain TargetKind = "domain"
)

// maxHostnameLen 是域名总长上限（RFC 1035 的 255 减去长度字节与根点）。
const maxHostnameLen = 253

// ErrTargetHasScheme 等错误文案在 API 与 UI 之间共享，保持措辞一致。
const (
	msgTargetEmpty  = "目标地址不能为空"
	msgTargetSchema = "目标地址只填写 IP 或域名，不要包含 http://、https://、端口或路径"
	msgTargetBad    = "请输入有效的 IPv4、IPv6 或域名"
)

// NormalizeTarget 规范化并判定目标地址形态。
//
// 允许：IPv4 字面量、IPv6 字面量（裸写，不带方括号）、域名。
// 拒绝：URL（含 scheme / 路径）、内嵌端口、方括号包裹的 IPv6、空白、
// 通配地址（0.0.0.0 / ::）、组播、带 zone 的链路本地地址。
//
// 目标端口永远是独立字段 TargetPort，绝不从地址里解析。
func NormalizeTarget(raw string) (string, TargetKind, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", "", fmt.Errorf("%s", msgTargetEmpty)
	}
	// 明显是 URL / 带路径 / 带方括号 / 含空白的输入，给出针对性提示。
	lower := strings.ToLower(s)
	if strings.Contains(lower, "://") || strings.HasPrefix(lower, "http:") ||
		strings.HasPrefix(lower, "https:") || strings.Contains(s, "/") ||
		strings.Contains(s, "[") || strings.Contains(s, "]") ||
		strings.Contains(s, "?") || strings.Contains(s, "@") {
		return "", "", fmt.Errorf("%s", msgTargetSchema)
	}
	if strings.ContainsAny(s, " \t\r\n") {
		return "", "", fmt.Errorf("%s", msgTargetBad)
	}

	// 先按 IP 解析。net/netip 是权威判定，不自己写正则。
	if addr, err := netip.ParseAddr(s); err == nil {
		return normalizeIP(addr)
	}

	// 形如 host:port / 1.2.3.4:443 的输入：冒号在这里只能是 IPv6 的一部分，
	// 而上一步已确认它不是合法 IPv6，因此一律按「不要带端口」提示。
	if strings.Contains(s, ":") {
		return "", "", fmt.Errorf("%s", msgTargetSchema)
	}

	host, err := normalizeHostname(s)
	if err != nil {
		return "", "", err
	}
	return host, TargetDomain, nil
}

// normalizeIP 校验并规范化 IP 字面量。
func normalizeIP(addr netip.Addr) (string, TargetKind, error) {
	// ::ffff:1.2.3.4 归一到 IPv4：数据面只有 v4/v6 两条路径，
	// 保留 mapped 形态会让「族判定」与 nft 语法出现歧义。
	addr = addr.Unmap()
	if addr.Zone() != "" {
		// fe80::1%eth0 这类带 zone 的地址无法直接写进 nft dnat 目标。
		return "", "", fmt.Errorf("目标地址不支持带网卡区域（zone）的地址: %s", addr.String())
	}
	if !addr.IsValid() {
		return "", "", fmt.Errorf("%s", msgTargetBad)
	}
	if addr.IsUnspecified() {
		return "", "", fmt.Errorf("目标地址不能是通配地址（0.0.0.0 / ::）")
	}
	if addr.IsMulticast() || addr.IsInterfaceLocalMulticast() {
		return "", "", fmt.Errorf("目标地址不能是组播地址: %s", addr.String())
	}
	if addr.Is4() {
		return addr.String(), TargetIPv4, nil
	}
	return addr.String(), TargetIPv6, nil
}

// normalizeHostname 严格校验 hostname / FQDN，返回小写形式（去掉末尾根点）。
//
// 规则：总长 ≤ 253；至少两个 label；每个 label 1-63 字符、只含 [a-z0-9-]、
// 不以 - 开头或结尾；末尾 label（TLD）至少 2 个字符且全为字母。
func normalizeHostname(s string) (string, error) {
	h := strings.ToLower(strings.TrimSuffix(s, "."))
	if h == "" || len(h) > maxHostnameLen {
		return "", fmt.Errorf("%s", msgTargetBad)
	}
	labels := strings.Split(h, ".")
	if len(labels) < 2 {
		// 单 label（如 "localhost"、"example"）不接受：转发目标需要可解析的
		// 完整域名，单 label 更常见于输入错误。
		return "", fmt.Errorf("%s", msgTargetBad)
	}
	for _, l := range labels {
		if len(l) == 0 || len(l) > 63 {
			return "", fmt.Errorf("%s", msgTargetBad)
		}
		if l[0] == '-' || l[len(l)-1] == '-' {
			return "", fmt.Errorf("%s", msgTargetBad)
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'
			if !ok {
				return "", fmt.Errorf("%s", msgTargetBad)
			}
		}
	}
	tld := labels[len(labels)-1]
	if len(tld) < 2 {
		return "", fmt.Errorf("%s", msgTargetBad)
	}
	for i := 0; i < len(tld); i++ {
		if c := tld[i]; c < 'a' || c > 'z' {
			return "", fmt.Errorf("%s", msgTargetBad)
		}
	}
	return h, nil
}

// KindOf 返回已规范化目标地址的形态（不再做完整校验，供内部快速判定）。
func KindOf(target string) TargetKind {
	if addr, err := netip.ParseAddr(strings.TrimSpace(target)); err == nil {
		if addr.Unmap().Is4() {
			return TargetIPv4
		}
		return TargetIPv6
	}
	return TargetDomain
}

// IsDomain 报告目标地址是否为域名。
func IsDomain(target string) bool { return KindOf(target) == TargetDomain }

// FormatHostPort 按显示约定拼接「地址:端口」：IPv6 加方括号，其余直接拼。
func FormatHostPort(addr string, port int) string {
	if KindOf(addr) == TargetIPv6 {
		return fmt.Sprintf("[%s]:%d", addr, port)
	}
	return fmt.Sprintf("%s:%d", addr, port)
}
