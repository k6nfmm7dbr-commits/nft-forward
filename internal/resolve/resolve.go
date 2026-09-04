// Package resolve 负责域名目标的 DNS 解析与「稳定地址选择」。
//
// 设计要点（全部为强制行为，有对应回归测试）：
//
//   - 解析器抽象成 Resolver 接口，测试用 fake，绝不依赖公网 DNS；
//   - IPv4 走 A、IPv6 走 AAAA，各自独立跟踪；不做 NAT64/NAT46；
//   - 多 A / 多 AAAA 时**保持当前地址**：只要当前使用的地址仍在本次结果集合中
//     就继续用它，避免 DNS 轮转顺序变化导致 nft 目标反复抖动；
//   - 当前地址从结果集合消失时，按字典序选取确定性的新地址（可测试）；
//   - DNS 临时失败（timeout / SERVFAIL / 网络错误）时保留 last-known-good，
//     状态标记为 stale，绝不删除规则、绝不写入 0.0.0.0 之类假地址；
//   - 只有「从未成功解析过」才是 failed。
package resolve

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"
)

// Resolver 抽象 DNS 查询。签名与 *net.Resolver.LookupNetIP 一致，
// 因此生产实现可直接用 net.Resolver。
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// SystemResolver 是基于 net.Resolver 的生产实现。
type SystemResolver struct {
	r       *net.Resolver
	Timeout time.Duration
}

// NewSystemResolver 构造系统解析器。timeout <= 0 时用 5s。
func NewSystemResolver(timeout time.Duration) *SystemResolver {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &SystemResolver{r: &net.Resolver{}, Timeout: timeout}
}

// LookupNetIP 实现 Resolver。
func (s *SystemResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	cctx, cancel := context.WithTimeout(ctx, s.Timeout)
	defer cancel()
	return s.r.LookupNetIP(cctx, network, host)
}

// State 是某个域名目标的解析状态（last-known-good + 最近一次结果）。
type State struct {
	// V4 / V6 是当前用于数据面的地址（last-known-good）。
	V4 string
	V6 string
	// At 是最近一次**成功**解析的 Unix 秒。
	At int64
	// Status 取值见 forward.Resolve*：ok / stale / failed。
	Status string
	// Err 是最近一次失败原因（成功时为空）。
	Err string
}

// Changed 报告两个状态的数据面地址是否不同（只比较 V4/V6）。
func (s State) Changed(other State) bool { return s.V4 != other.V4 || s.V6 != other.V6 }

// Empty 报告当前没有任何可用地址。
func (s State) Empty() bool { return s.V4 == "" && s.V6 == "" }

// 解析状态常量（与 forward 包的取值保持一致，避免包循环）。
const (
	StatusOK     = "ok"
	StatusStale  = "stale"
	StatusFailed = "failed"
)

// Resolve 对 host 做一次 A + AAAA 查询，并结合 prev 计算新的稳定状态。
//
// 语义矩阵：
//
//	两族都失败 + prev 有地址   → 保留 prev 地址，Status=stale（记录错误）
//	两族都失败 + prev 无地址   → Status=failed，地址为空
//	某族成功、另一族无记录     → 该族更新，另一族置空（域名确实没有该族记录）
//	某族查询出错、另一族成功   → 出错族保留 prev 地址（避免抖动），Status=stale
func Resolve(ctx context.Context, r Resolver, host string, prev State, now time.Time) State {
	host = strings.TrimSpace(host)
	out := State{At: prev.At}

	v4s, err4 := lookup(ctx, r, "ip4", host)
	v6s, err6 := lookup(ctx, r, "ip6", host)

	// 两族都出错：完整保留上次有效地址。
	if err4 != nil && err6 != nil {
		out.V4, out.V6 = prev.V4, prev.V6
		out.Err = joinErr(err4, err6)
		if out.Empty() {
			out.Status = StatusFailed
		} else {
			out.Status = StatusStale
		}
		return out
	}

	// 逐族处理：查询成功则采用稳定选择结果（可能为空 = 该族无记录）；
	// 查询失败则沿用上次地址，避免单族抖动影响已工作的数据面。
	var stale bool
	if err4 != nil {
		out.V4 = prev.V4
		stale = true
	} else {
		out.V4 = pickStable(prev.V4, v4s)
	}
	if err6 != nil {
		out.V6 = prev.V6
		stale = true
	} else {
		out.V6 = pickStable(prev.V6, v6s)
	}

	if out.Empty() {
		// 两族查询都「成功」但没有任何 A/AAAA 记录：等价于无法解析。
		// 有历史地址时按 stale 处理（保留旧地址继续转发）。
		out.V4, out.V6 = prev.V4, prev.V6
		out.Err = fmt.Sprintf("域名 %s 没有 A/AAAA 记录", host)
		if out.Empty() {
			out.Status = StatusFailed
		} else {
			out.Status = StatusStale
		}
		return out
	}

	if stale {
		out.Status = StatusStale
		out.Err = joinErr(err4, err6)
		// 仍有可用地址：At 只在完全成功时刷新，便于 UI 显示「上次成功时间」。
		return out
	}
	out.Status = StatusOK
	out.At = now.Unix()
	out.Err = ""
	return out
}

// lookup 查询单一地址族并归一化为字符串集合。
//
// 「无记录」不是错误：返回空切片 + nil。只有真正的查询故障
// （timeout / SERVFAIL / 网络不可达）才返回 error —— 这是保留
// last-known-good 与「域名确实没有该族记录」的分界线。
func lookup(ctx context.Context, r Resolver, network, host string) ([]string, error) {
	addrs, err := r.LookupNetIP(ctx, network, host)
	if err != nil {
		if isNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	want4 := network == "ip4"
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		a = a.Unmap()
		if a.Zone() != "" || !a.IsValid() || a.IsUnspecified() || a.IsMulticast() {
			continue
		}
		if a.Is4() != want4 {
			continue
		}
		out = append(out, a.String())
	}
	return out, nil
}

// isNotFound 判断错误是否为「没有该类型记录 / 域名不存在但无记录」。
//
// NXDOMAIN 与 NODATA 在 Go 里都表现为 *net.DNSError{IsNotFound:true}。
// 二者都归为「无记录」：调用方看到两族都空即判定无法解析，
// 语义与「查询故障」区分开。
func isNotFound(err error) bool {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return dnsErr.IsNotFound
	}
	return false
}

// pickStable 从候选集合中挑选地址，优先保持 current 不变。
//
//   - 候选为空 → 返回空串（该族无记录）；
//   - current 仍在候选集合 → 继续用 current（DNS 顺序变化不影响数据面）；
//   - 否则 → 取字典序最小者（确定性、可测试；本轮不做负载均衡）。
func pickStable(current string, candidates []string) string {
	if len(candidates) == 0 {
		return ""
	}
	for _, c := range candidates {
		if c == current && current != "" {
			return current
		}
	}
	sorted := append([]string{}, candidates...)
	sort.Strings(sorted)
	return sorted[0]
}

func joinErr(a, b error) string {
	switch {
	case a != nil && b != nil:
		if a.Error() == b.Error() {
			return a.Error()
		}
		return a.Error() + "; " + b.Error()
	case a != nil:
		return a.Error()
	case b != nil:
		return b.Error()
	default:
		return ""
	}
}
