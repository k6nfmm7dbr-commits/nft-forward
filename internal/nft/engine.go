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
// ★ 为什么绝不能用 `delete table` 重建（本项目最重要的一条）：
//
//	named counter 是表级对象，`delete table` 会把它连同累计字节一起销毁。
//	策略 reconcile 是周期性的（秒级甚至亚秒级），如果每轮都重建表，counter
//	会被反复清零，采集器读到的永远是残片 —— 流量统计几乎全部丢失。
//	因此本包采用：
//	  1) `table ... { counter/set 声明 }` 幂等 add（已存在则保留原值）；
//	  2) `flush chain` 只清空链内规则（表级 counter / set 不受影响）；
//	  3) flush + add rules 放在同一个 `nft -f` 脚本里 —— nft 单脚本是原子
//	     事务，因此不存在「规则短暂缺失」的丢包窗口。
//
//	域名规则的 DNS 目标变化走的也是这条路径：只重写链规则，counter 不动。
//
// ★ 为什么结构与元素分离：
//
//	allow set 的元素（在线 IP）变化频繁，若为此重建链规则，会周期性出现
//	空 allow set 窗口，把已授权 IP 的 established 流量误 drop。
//	因此元素变化只走 `nft add/delete element`，绝不触碰链。
//
// ★ 为什么每条 DNAT 规则都带 `fib daddr type local`：
//
//	规则不再有「监听地址」——用户只配监听端口。若直接写
//	`tcp dport 5000 dnat to ...`，那么当这台服务器同时承担路由/网关职责时，
//	**仅仅经过**本机（目的地址是别人）的同端口流量也会被 DNAT 劫持。
//	`fib daddr type local` 让规则只匹配「目的地址属于本机」的包，
//	等价于「监听本机所有本地地址」，同时不误伤 transit 流量。
//
// 为什么计数放在 FORWARD 而不是 NAT 链：
//
//	NAT 链（PREROUTING/POSTROUTING）只在连接首包做 NAT 决策，其 counter
//	无法统计完整数据流；完整上传/下载字节必须在 FORWARD（filter）路径统计。
//
// 为什么用 `ct mark` 归属规则：
//
//	多条规则可指向同一目标地址:端口（如 20000→X:80、30000→X:80）。
//	用「目标地址+端口」匹配会把两条规则的流量混在一起。PREROUTING 时按
//	监听端口打上 ct mark（随连接持久化），FORWARD 据此稳定归属。
//	（nft 1.0.6 不支持 `ct original proto-dst`，故采用 ct mark 方案。）
//
// 方向定义（与 SBX 习惯一致）：
//   - upload / rx  = ct direction original（客户端 → 转发服务器 → 目标）
//   - download / tx = ct direction reply（目标 → 转发服务器 → 客户端）
package nft

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/k6nfmm7dbr-commits/nft-forward/internal/forward"
)

// 表名与 set 名（固定前缀 nff_，只能管理这些对象）。
const (
	TableNAT4   = "nff_nat4"
	TableNAT6   = "nff_nat6"
	TableFilter = "nff_filter"

	// SetQuotaBlock 存放「配额已超限」的规则 ID（mark）。
	// 配额状态变化只增删该 set 的元素，无需重建链。
	SetQuotaBlock = TableFilter + "_qblock"
)

// CounterUp 返回某规则上传方向的 named counter 名。
func CounterUp(id int64) string { return TableFilter + "_up_" + strconv.FormatInt(id, 10) }

// CounterDown 返回某规则下载方向的 named counter 名。
func CounterDown(id int64) string { return TableFilter + "_down_" + strconv.FormatInt(id, 10) }

// AllowSetV4 返回某规则的 IPv4 allow set 名。
func AllowSetV4(id int64) string {
	return TableFilter + "_allow_" + strconv.FormatInt(id, 10) + "_v4"
}

// AllowSetV6 返回某规则的 IPv6 allow set 名。
func AllowSetV6(id int64) string {
	return TableFilter + "_allow_" + strconv.FormatInt(id, 10) + "_v6"
}

// MarksSet 返回某 NAT 表的 mark set 名（POSTROUTING masquerade 用）。
func MarksSet(table string) string { return table + "_marks" }

// ChainPrerouting / ChainPostrouting / ChainForward 返回链名。
func ChainPrerouting(table string) string  { return table + "_prerouting" }
func ChainPostrouting(table string) string { return table + "_postrouting" }
func ChainForward() string                 { return TableFilter + "_forward" }

// RuleState 是单条规则的运行时强制状态（由 policy 层提供）。
type RuleState struct {
	QuotaExceeded  bool
	IPLimitEnabled bool
	AllowV4        []string
	AllowV6        []string
}

// GenInput 是生成脚本的输入。Rules 应只含未删除的规则。
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

// dnatTarget 是一条要写入某地址族数据面的 DNAT 意图。
type dnatTarget struct {
	rule *forward.Rule
	addr string // 目标地址（IPv4 或 IPv6 字面量，已由上层解析/校验）
}

// families 返回按地址族分组的 DNAT 意图（已按规则 ID 排序，脚本稳定可比较）。
//
// 关键语义：
//   - IPv4 目标（字面量或域名的 A 记录）→ 只进 nff_nat4；
//   - IPv6 目标（字面量或域名的 AAAA 记录）→ 只进 nff_nat6；
//   - 域名同时有 A + AAAA → 同一规则同时出现在两张表（同监听端口，各自族内闭环）；
//   - 绝不交叉（不做 NAT64 / NAT46）；
//   - 域名解析尚无任何有效地址 → 该规则本轮不产生 DNAT 规则，
//     但它的 counter / allow set / 配额状态一律保留。
func (g *GenInput) families() (v4, v6 []dnatTarget) {
	for _, r := range g.Rules {
		if r == nil || r.Deleted || !r.Enabled {
			continue
		}
		if a := r.DialV4(); a != "" {
			v4 = append(v4, dnatTarget{rule: r, addr: a})
		}
		if a := r.DialV6(); a != "" {
			v6 = append(v6, dnatTarget{rule: r, addr: a})
		}
	}
	sort.Slice(v4, func(i, j int) bool { return v4[i].rule.ID < v4[j].rule.ID })
	sort.Slice(v6, func(i, j int) bool { return v6[i].rule.ID < v6[j].rule.ID })
	return v4, v6
}

// enabledRules 返回所有启用且未删除的规则（filter 表的 counter/链以此为准）。
//
// 注意：即使域名当前解析失败（无 DialV4/DialV6），规则依然在此列表里 ——
// counter 必须继续存在，否则「DNS 故障」会连带清掉流量统计。
func (g *GenInput) enabledRules() []*forward.Rule {
	var out []*forward.Rule
	for _, r := range g.Rules {
		if r == nil || r.Deleted || !r.Enabled {
			continue
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// ---- 结构签名 ----

// StructSig 返回「结构」的稳定签名。只有它变化时才需要重写链规则。
//
// 包含：规则 ID / 协议 / 监听端口 / 当前数据面目标地址（含 DNS 解析结果）/
// 目标端口 / 是否启用 IP 限制。
//
// 故意 **不含** allow set 元素与配额超限状态：
//   - allow set 元素走增量 element 操作；
//   - 配额超限走 qblock set 元素。
//
// 这样在稳定运行期（仅在线 IP 增减、配额用量变化）完全不会触碰链和 counter。
// DNS 解析结果变化会改变签名 → 触发链重写（counter 保留）。
func StructSig(g *GenInput) string {
	var b strings.Builder
	for _, r := range g.enabledRules() {
		st := g.stateOf(r.ID)
		ipLimit := st != nil && st.IPLimitEnabled
		fmt.Fprintf(&b, "%d|%s|%d|%s|%s|%d|%t;",
			r.ID, r.Protocol, r.ListenPort, r.DialV4(), r.DialV6(), r.TargetPort, ipLimit)
	}
	return b.String()
}

// ---- 结构脚本 ----

// Existing 描述 nft 中已存在的自有对象（用于清理遗留 counter/set）。
type Existing struct {
	FilterTableExists bool
	NAT4TableExists   bool
	NAT6TableExists   bool
	Counters          []string // nff_filter 表内已存在的 named counter
	Sets              []string // nff_filter 表内已存在的 set
}

// GenStructScript 生成结构脚本：幂等声明表/链/counter/set，flush 链后重建规则。
//
// 关键：**不使用 `delete table`**。counter 与 set 作为表级对象被保留，
// 只有链内规则被 flush 重建；整个脚本是单个 nft 原子事务，无中间态。
func GenStructScript(g *GenInput, ex *Existing) string {
	v4, v6 := g.families()

	var b strings.Builder
	b.WriteString("#!/usr/sbin/nft -f\n")
	b.WriteString("# 由 nft-forward 自动生成。只管理 nff_* 前缀的自有表，从不清空系统规则集。\n")
	b.WriteString("# 表从不整体销毁重建：counter 是表级对象，这里只清空链再重建链内规则，\n")
	b.WriteString("# 因此流量累计字节得以保留（域名 DNS 目标变化走的也是这条路径）。\n")
	b.WriteString("# 每条 DNAT 都带 fib daddr type local：只匹配目的地址属于本机的包，\n")
	b.WriteString("# 绝不劫持仅路由经过本机的 transit 流量。\n\n")

	b.WriteString(genNATStruct("ip", TableNAT4, v4))
	b.WriteString(genNATStruct("ip6", TableNAT6, v6))
	b.WriteString(genFilterStruct(g, ex))
	return b.String()
}

// genNATStruct 生成一个族的 NAT 表结构（幂等 add + flush chain + 规则）。
//
// 链内规则一律由 natIntents 渲染 —— 与自愈内容校验用的期望签名同源，
// 避免「脚本改了、期望没改」造成的无限重建或永久漏检。
func genNATStruct(family, table string, targets []dnatTarget) string {
	var b strings.Builder
	marks := MarksSet(table)
	pre := ChainPrerouting(table)
	post := ChainPostrouting(table)

	// 1) 幂等声明（表已存在则不动其内容）。
	fmt.Fprintf(&b, "table %s %s {\n", family, table)
	fmt.Fprintf(&b, "    set %s {\n        type mark\n    }\n", marks)
	fmt.Fprintf(&b, "    chain %s {\n        type nat hook prerouting priority dstnat; policy accept;\n    }\n", pre)
	fmt.Fprintf(&b, "    chain %s {\n        type nat hook postrouting priority srcnat; policy accept;\n    }\n", post)
	b.WriteString("}\n")

	// 2) 清空链与 marks set（同一事务内，无窗口）。
	fmt.Fprintf(&b, "flush chain %s %s %s\n", family, table, pre)
	fmt.Fprintf(&b, "flush chain %s %s %s\n", family, table, post)
	fmt.Fprintf(&b, "flush set %s %s %s\n", family, table, marks)

	// 3) 重建内容。
	if len(targets) > 0 {
		ids := make([]string, 0, len(targets))
		seen := map[int64]bool{}
		for _, t := range targets {
			if seen[t.rule.ID] {
				continue
			}
			seen[t.rule.ID] = true
			ids = append(ids, strconv.FormatInt(t.rule.ID, 10))
		}
		fmt.Fprintf(&b, "add element %s %s %s { %s }\n", family, table, marks, strings.Join(ids, ", "))

		preIntents, postIntents := natIntents(family, table, targets)
		for _, in := range preIntents {
			b.WriteString(in.render())
			b.WriteByte('\n')
		}
		// 只对本程序 DNAT 过的连接做 masquerade。
		for _, in := range postIntents {
			b.WriteString(in.render())
			b.WriteByte('\n')
		}
	}
	b.WriteString("\n")
	return b.String()
}

// genFilterStruct 生成 filter 表结构：counter/set 幂等声明 + flush chain + 规则。
func genFilterStruct(g *GenInput, ex *Existing) string {
	var b strings.Builder
	fwd := ChainForward()
	all := g.enabledRules()

	// 1) 幂等声明。counter 已存在时保留累计值，这是流量不丢的关键。
	fmt.Fprintf(&b, "table inet %s {\n", TableFilter)
	fmt.Fprintf(&b, "    set %s {\n        type mark\n    }\n", SetQuotaBlock)
	for _, r := range all {
		fmt.Fprintf(&b, "    counter %s {\n    }\n", CounterUp(r.ID))
		fmt.Fprintf(&b, "    counter %s {\n    }\n", CounterDown(r.ID))
		st := g.stateOf(r.ID)
		if st != nil && st.IPLimitEnabled {
			fmt.Fprintf(&b, "    set %s {\n        type ipv4_addr\n    }\n", AllowSetV4(r.ID))
			fmt.Fprintf(&b, "    set %s {\n        type ipv6_addr\n    }\n", AllowSetV6(r.ID))
		}
	}
	fmt.Fprintf(&b, "    chain %s {\n        type filter hook forward priority filter; policy accept;\n    }\n", fwd)
	b.WriteString("}\n")

	// 2) 清空链（counter / set 不受影响）。
	fmt.Fprintf(&b, "flush chain inet %s %s\n", TableFilter, fwd)

	// 3) 重建规则。
	//
	//    顺序由 filterIntents 决定：配额阻断在最前（被阻断的流量不计入用量，
	//    否则用量会继续虚增），随后每条规则的 up/down counter，
	//    最后是启用 IP 限制的规则的 v4/v6 drop。
	//
	//    渲染与自愈期望签名同源（见 internal/nft/intent.go）。
	for _, in := range filterIntents(g) {
		b.WriteString(in.render())
		b.WriteByte('\n')
	}

	// 4) 清理遗留对象（规则被删除/关闭 IP 限制后残留的 counter 与 set）。
	if ex != nil && ex.FilterTableExists {
		want := map[string]bool{}
		for _, r := range all {
			want[CounterUp(r.ID)] = true
			want[CounterDown(r.ID)] = true
			if st := g.stateOf(r.ID); st != nil && st.IPLimitEnabled {
				want[AllowSetV4(r.ID)] = true
				want[AllowSetV6(r.ID)] = true
			}
		}
		stale := append([]string{}, staleNames(ex.Counters, want)...)
		sort.Strings(stale)
		for _, name := range stale {
			fmt.Fprintf(&b, "delete counter inet %s %s\n", TableFilter, name)
		}
		want[SetQuotaBlock] = true // qblock 永久保留
		staleSets := append([]string{}, staleNames(ex.Sets, want)...)
		sort.Strings(staleSets)
		for _, name := range staleSets {
			fmt.Fprintf(&b, "delete set inet %s %s\n", TableFilter, name)
		}
	}
	return b.String()
}

// staleNames 返回 existing 中不在 want 里、且属于本程序前缀的名字。
func staleNames(existing []string, want map[string]bool) []string {
	var out []string
	for _, name := range existing {
		if want[name] {
			continue
		}
		if !strings.HasPrefix(name, TableFilter+"_") {
			continue // 非本程序对象，绝不删
		}
		out = append(out, name)
	}
	return out
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
