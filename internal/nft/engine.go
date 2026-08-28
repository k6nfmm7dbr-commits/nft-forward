// Package nft 生成并应用 nftables 转发规则。
//
// 安全约束（不可妥协）：
//   - 绝不执行 `nft flush ruleset`；
//   - 只 create/delete 本程序拥有的固定前缀表（nff_*）；
//   - 任何应用都先 `nft -c -f` 语法检查，通过后才 `nft -f` 应用（事务化）。
//
// 表结构：
//   - table ip   nff_nat4    IPv4 NAT（PREROUTING DNAT + POSTROUTING masquerade）
//   - table ip6  nff_nat6    IPv6 NAT
//   - table inet nff_filter  FORWARD 计数 + 配额阻断 + IP allow set
//
// 为什么计数放在 FORWARD 而不是 NAT 链：
//   NAT 链（PREROUTING/POSTROUTING）主要负责连接 NAT 决策，不能依赖其 counter
//   统计完整持续数据流；完整的上传/下载字节必须在 FORWARD（filter）路径、
//   用 conntrack 归属到规则后统计。
//
// 为什么用 `ct original proto-dst <listen_port>` 归属规则：
//   多条规则可以指向同一个目标地址:端口（如 20000→X:8844、30000→X:8844）。
//   若用「目标地址+端口」匹配会把两条规则的流量混在一起。必须用连接进入时的
//   原始目标端口（监听端口，即 conntrack original tuple 的 proto-dst）来稳定归属。
//   冲突校验保证「协议+监听端口」唯一，因此该组合无歧义。
//
// 方向定义（与 SBX 习惯一致）：
//   - upload / rx  = ct direction original（客户端 → 转发服务器 → 目标）
//   - download / tx = ct direction reply（目标 → 转发服务器 → 客户端）
package nft

import (
	"fmt"
	"sort"
	"strings"

	"github.com/k6nfmm7dbr-commits/nft-forward/internal/forward"
)

// 表名（固定前缀 nff_，只能管理这些表）。
const (
	TableNAT4   = "nff_nat4"
	TableNAT6   = "nff_nat6"
	TableFilter = "nff_filter"
)

// RuleState 是单条规则的运行时强制状态（由 policy 层提供）。
type RuleState struct {
	QuotaExceeded  bool
	IPLimitEnabled bool
	AllowV4        []string
	AllowV6        []string
}

// GenInput 是生成脚本的输入。
type GenInput struct {
	Rules  []*forward.Rule
	States map[int64]*RuleState // rule id -> 状态；可为 nil（默认全部不限）
}

func (g *GenInput) stateOf(id int64) *RuleState {
	if g.States == nil {
		return nil
	}
	return g.States[id]
}

func isV4(addr string) bool {
	addr = strings.TrimSpace(addr)
	if addr == "" || addr == "0.0.0.0" {
		return true
	}
	return strings.Count(addr, ":") == 0
}

// GenScript 生成完整的自有表脚本（事务化应用）。
func GenScript(g *GenInput) string {
	var v4Rules, v6Rules []*forward.Rule
	for _, r := range g.Rules {
		if r.Deleted || !r.Enabled {
			continue
		}
		if isV4(r.TargetAddress) {
			v4Rules = append(v4Rules, r)
		} else {
			v6Rules = append(v6Rules, r)
		}
	}
	sort.Slice(v4Rules, func(i, j int) bool { return v4Rules[i].ID < v4Rules[j].ID })
	sort.Slice(v6Rules, func(i, j int) bool { return v6Rules[i].ID < v6Rules[j].ID })

	var b strings.Builder
	b.WriteString("#!/usr/sbin/nft -f\n")
	b.WriteString("# 由 nft-forward 自动生成，仅管理 nff_* 表，绝不整体清空系统规则集。\n\n")

	b.WriteString(genNATTable("ip", TableNAT4, v4Rules))
	b.WriteString(genNATTable("ip6", TableNAT6, v6Rules))
	b.WriteString(genFilterTable(g, v4Rules, v6Rules))
	return b.String()
}

// genNATTable 生成一个族的 NAT 表（PREROUTING DNAT + POSTROUTING masquerade）。
func genNATTable(family, table string, rules []*forward.Rule) string {
	var b strings.Builder
	// create-then-delete-then-create：保证无论表是否存在都能原子重建。
	fmt.Fprintf(&b, "table %s %s\n", family, table)
	fmt.Fprintf(&b, "delete table %s %s\n", family, table)
	fmt.Fprintf(&b, "table %s %s {\n", family, table)

	if len(rules) > 0 {
		// 供 POSTROUTING masquerade 识别本程序 DNAT 过的连接。
		marks := make([]string, 0, len(rules))
		for _, r := range rules {
			marks = append(marks, fmt.Sprintf("%d", r.ID))
		}
		fmt.Fprintf(&b, "    set %s_marks {\n        type mark\n        elements = { %s }\n    }\n",
			table, strings.Join(marks, ", "))

		// PREROUTING：设置 ct mark 并 DNAT。ct mark 随连接持久化，
		// FORWARD 链据此把流量归属回规则（解决多规则同目标的歧义）。
		fmt.Fprintf(&b, "    chain %s_prerouting {\n", table)
		fmt.Fprintf(&b, "        type nat hook prerouting priority dstnat; policy accept;\n")
		for _, r := range rules {
			proto := ruleProtos(r)
			// IPv6 目标必须用方括号包裹（nftables dnat 语法）。
			var dnatTarget string
			if strings.Contains(r.TargetAddress, ":") {
				dnatTarget = fmt.Sprintf("[%s]:%d", r.TargetAddress, r.TargetPort)
			} else {
				dnatTarget = fmt.Sprintf("%s:%d", r.TargetAddress, r.TargetPort)
			}
			addrMatch := listenAddrMatch(family, r.ListenAddress)
			for _, p := range proto {
				fmt.Fprintf(&b, "        %s dport %d%s ct mark set %d dnat to %s\n",
					p, r.ListenPort, addrMatch, r.ID, dnatTarget)
			}
		}
		b.WriteString("    }\n")

		// POSTROUTING masquerade：只对本程序 DNAT 过的连接（带 mark）做 SNAT。
		fmt.Fprintf(&b, "    chain %s_postrouting {\n", table)
		fmt.Fprintf(&b, "        type nat hook postrouting priority srcnat; policy accept;\n")
		fmt.Fprintf(&b, "        ct mark @%s_marks masquerade\n", table)
		b.WriteString("    }\n")
	}

	b.WriteString("}\n\n")
	return b.String()
}

// ruleProtos 返回规则承载的协议列表。
func ruleProtos(r *forward.Rule) []string {
	var out []string
	if r.HasTCP() {
		out = append(out, "tcp")
	}
	if r.HasUDP() {
		out = append(out, "udp")
	}
	return out
}

// listenAddrMatch 若监听地址是具体地址（非通配），生成目的地址匹配以限制 DNAT 范围。
func listenAddrMatch(family, listenAddr string) string {
	la := strings.TrimSpace(listenAddr)
	if la == "" || la == "0.0.0.0" || la == "::" {
		return ""
	}
	if family == "ip" {
		return " ip daddr " + la
	}
	return " ip6 daddr " + la
}

// genFilterTable 生成 FORWARD 计数 + 配额阻断 + IP allow set 表。
func genFilterTable(g *GenInput, v4Rules, v6Rules []*forward.Rule) string {
	var b strings.Builder
	fmt.Fprintf(&b, "table inet %s\n", TableFilter)
	fmt.Fprintf(&b, "delete table inet %s\n", TableFilter)
	fmt.Fprintf(&b, "table inet %s {\n", TableFilter)

	all := append(append([]*forward.Rule{}, v4Rules...), v6Rules...)

	// 先声明所有需要的 set 与 counter。配额达限的规则只阻断，不生成计数。
	for _, r := range all {
		st := g.stateOf(r.ID)
		// IP allow set：仅当该规则启用 IP 限制时。
		if st != nil && st.IPLimitEnabled {
			writeSet(&b, fmt.Sprintf("%s_allow_%d_v4", TableFilter, r.ID), "ipv4_addr", st.AllowV4)
			writeSet(&b, fmt.Sprintf("%s_allow_%d_v6", TableFilter, r.ID), "ipv6_addr", st.AllowV6)
		}
		// 命名 counter（上传/下载）；达限规则不计数。
		if st == nil || !st.QuotaExceeded {
			fmt.Fprintf(&b, "    counter %s_up_%d {\n    }\n", TableFilter, r.ID)
			fmt.Fprintf(&b, "    counter %s_down_%d {\n    }\n", TableFilter, r.ID)
		}
	}

	// FORWARD 链：按 ct mark 归属规则，统计上传/下载、执行配额阻断与 IP 限制。
	// 完整上传/下载字节必须在 FORWARD（filter）路径计数，而非 NAT 链。
	fmt.Fprintf(&b, "    chain %s_forward {\n", TableFilter)
	fmt.Fprintf(&b, "        type filter hook forward priority filter; policy accept;\n")
	for _, r := range all {
		st := g.stateOf(r.ID)
		mid := r.ID
		// 1) 配额阻断：达限则丢弃该规则的全部转发流量（放在计数前，被阻流量不计入用量）。
		if st != nil && st.QuotaExceeded {
			fmt.Fprintf(&b, "        ct mark %d drop\n", mid)
			continue // 已阻断，无需计数/allow
		}
		// 2) 上传/下载计数（ct direction original = 客户端→目标，reply = 目标→客户端）。
		fmt.Fprintf(&b, "        ct mark %d ct direction original counter name \"%s_up_%d\"\n",
			mid, TableFilter, mid)
		fmt.Fprintf(&b, "        ct mark %d ct direction reply counter name \"%s_down_%d\"\n",
			mid, TableFilter, mid)
		// 3) IP 限制：只丢弃「已建立」且不在 allow set 的源，放行 SYN（候选可见）。
		if st != nil && st.IPLimitEnabled {
			fmt.Fprintf(&b, "        ct mark %d ct state established ip saddr != @%s_allow_%d_v4 drop\n",
				mid, TableFilter, mid)
			fmt.Fprintf(&b, "        ct mark %d ct state established ip6 saddr != @%s_allow_%d_v6 drop\n",
				mid, TableFilter, mid)
		}
	}
	b.WriteString("    }\n")
	b.WriteString("}\n")
	return b.String()
}

func writeSet(b *strings.Builder, name, typ string, elements []string) {
	sorted := append([]string{}, elements...)
	sort.Strings(sorted)
	fmt.Fprintf(b, "    set %s {\n        type %s\n", name, typ)
	if len(sorted) > 0 {
		fmt.Fprintf(b, "        elements = { %s }\n", strings.Join(sorted, ", "))
	}
	b.WriteString("    }\n")
}
