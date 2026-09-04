package policy

import (
	"sort"
	"time"
)

// IPActivity 是单轮采集得到的某个客户端 IP 的活动摘要（TCP/UDP 合并）。
type IPActivity struct {
	IP          string
	TCPSessions int
	UDPSessions int
	Traffic     bool // 本轮判定有流量（conntrack 字节有增量）
}

// IPSlot 已获得使用资格（granted）的 IP。
type IPSlot struct {
	IP          string
	GrantedAt   time.Time
	LastSeen    time.Time
	LastTraffic time.Time
	TCP         bool
	UDP         bool
	// Provisional 表示该 slot 是「候选→临时授予」，握手尚未完成；
	// 超过 provisionalTTL 仍未建立则释放（防端口扫描占满名额）。
	Provisional bool
	CandidateAt time.Time
}

// ObservedIP 采集层观察到的 IP。
type ObservedIP struct {
	IP          string
	FirstSeen   time.Time
	LastSeen    time.Time
	LastTraffic time.Time
	TCPSessions int
	UDPSessions int
}

// NodeIPState 单条规则的 IP 状态。
//
//	Slots    = Granted（合法使用资格，nft allow set 的权威来源）
//	Observed = 发现过（含候选/扫描）
//	Rejected = 因超出上限被拒绝
type NodeIPState struct {
	Slots    map[string]*IPSlot
	Observed map[string]*ObservedIP
	Rejected map[string]time.Time
	MaxIPs   int
}

func newIPState() *NodeIPState {
	return &NodeIPState{
		Slots:    map[string]*IPSlot{},
		Observed: map[string]*ObservedIP{},
		Rejected: map[string]time.Time{},
	}
}

func lastActive(lastSeen, lastTraffic time.Time) time.Time {
	if lastTraffic.After(lastSeen) {
		return lastTraffic
	}
	return lastSeen
}

// Reconcile 执行一轮严格原子 admission。
//
// active 是「已建立并判活在线」的 IP；candidates 是「发起握手但尚未建立」的 IP。
// maxIPs<=0 表示不限制。idle/udpIdle 分别是 TCP/UDP 的 Observed GC 窗口。
//
//   - 已持有 slot 优先保留；
//   - active 优先于 candidate；
//   - 候选在有名额时 provisional 授予（进 allow set 让握手完成）；
//   - 候选超过 provisionalTTL 仍未建立 → 释放；
//   - 超出上限 → Rejected，绝不进 allow set。
//
// 返回 allowSet（所有 slot，含 provisional）与是否有新拒绝。
func (st *NodeIPState) Reconcile(active, candidates map[string]IPActivity, maxIPs int, now time.Time, idle, udpIdle, rejectedTTL, provisionalTTL time.Duration) (allowSet map[string]bool, hasRejected bool) {
	st.MaxIPs = maxIPs

	type want struct {
		ip     string
		active bool
	}
	seen := map[string]bool{}
	all := make([]want, 0, len(active)+len(candidates))

	// 1) 更新 Observed（active 与 candidate 都算「见过」）。
	for ip, a := range active {
		st.touchObserved(ip, a, now)
		seen[ip] = true
		all = append(all, want{ip, true})
	}
	for ip, a := range candidates {
		if seen[ip] {
			continue
		}
		st.touchObserved(ip, a, now)
		seen[ip] = true
		all = append(all, want{ip, false})
	}

	// 2) Rejected TTL 清理。
	for ip, t := range st.Rejected {
		if now.Sub(t) > rejectedTTL {
			delete(st.Rejected, ip)
		}
	}

	// 3) 释放 slot：本轮不在 active（conntrack 已无 ESTABLISHED = 确认关闭）立即释放；
	// candidate 超时未建立也释放。
	// released 记录本轮刚释放的 IP，admission 不得在同一轮立刻 re-grant（否则 TTL 形同虚设）。
	released := map[string]bool{}
	for ip, slot := range st.Slots {
		if !seen[ip] {
			delete(st.Slots, ip)
			released[ip] = true
			continue
		}
		if slot.Provisional && now.Sub(slot.CandidateAt) > provisionalTTL {
			delete(st.Slots, ip)
			released[ip] = true
		}
	}

	// 4) 排序（优先级从高到低）：
	//      ① 已建立且已持有正式 slot —— 在用的真实客户端，绝不能被挤掉
	//      ② 已建立（active）—— 完成过握手，比只发 SYN 的可信
	//      ③ 已持有 provisional slot 的候选
	//      ④ 其余候选
	//    再按 FirstSeen、IP 兜底保证确定性。
	//
	// 为什么 active 必须排在「持有 provisional slot 的候选」之前：
	// 只发 SYN 的陌生 IP 会先拿到 provisional slot，若「持有 slot」优先级最高，
	// 它就能在名额满时把真正 ESTABLISHED 的客户端推进 Rejected；每
	// provisionalTTL 内重发一次 SYN 即可持续拒服。max_ips=1 时最明显。
	rank := func(w want) int {
		slot, has := st.Slots[w.ip]
		switch {
		case has && !slot.Provisional && w.active:
			return 0
		case w.active:
			return 1
		case has && slot.Provisional:
			return 2
		default:
			return 3
		}
	}
	sort.Slice(all, func(i, j int) bool {
		a, b := all[i], all[j]
		ra, rb := rank(a), rank(b)
		if ra != rb {
			return ra < rb
		}
		fa, fb := st.Observed[a.ip].FirstSeen, st.Observed[b.ip].FirstSeen
		if !fa.Equal(fb) {
			return fa.Before(fb)
		}
		return a.ip < b.ip
	})

	// 5) Admission。
	for _, w := range all {
		if released[w.ip] {
			continue // 本轮刚释放，不 re-grant
		}
		a := active[w.ip]
		if !w.active {
			a = candidates[w.ip]
		}
		if slot, ok := st.Slots[w.ip]; ok {
			slot.LastSeen = now
			if a.TCPSessions > 0 {
				slot.TCP = true
			}
			if a.UDPSessions > 0 {
				slot.UDP = true
			}
			if a.Traffic {
				slot.LastTraffic = now
			}
			if w.active {
				slot.Provisional = false
				slot.CandidateAt = time.Time{}
			}
			continue
		}
		hasRoom := maxIPs <= 0 || len(st.Slots) < maxIPs
		// 名额已满但本 IP 已完成握手 → 抢占一个 provisional slot。
		// provisional 只是「让 SYN 能过 nft」的临时预留，不代表在用连接；
		// 真实客户端的优先级必须高于它，否则只发 SYN 的陌生 IP 能占死名额
		// （纯 SYN 扫描长期占用正式名额，真实客户端永远连不上）。
		// 被抢占者进 Rejected（其 SYN 本轮起被拦，下轮可重新竞争）。
		if !hasRoom && w.active {
			if victim := oldestProvisional(st); victim != "" {
				delete(st.Slots, victim)
				st.Rejected[victim] = now
				hasRejected = true
				hasRoom = true
			}
		}
		if hasRoom {
			slot := &IPSlot{IP: w.ip, GrantedAt: now, LastSeen: now, TCP: a.TCPSessions > 0, UDP: a.UDPSessions > 0}
			if w.active {
				if a.Traffic {
					slot.LastTraffic = now
				}
			} else {
				slot.Provisional = true
				slot.CandidateAt = now
			}
			st.Slots[w.ip] = slot
		} else {
			st.Rejected[w.ip] = now
			hasRejected = true
		}
	}

	// 6) allow set = 所有 slot（含 provisional）。
	allowSet = make(map[string]bool, len(st.Slots))
	for ip := range st.Slots {
		allowSet[ip] = true
	}

	// 7) Observed GC：无 slot、无拒绝、久未活跃的观察项清理。
	//    UDP 会话用较长的 udpIdle 窗口（UDP 无连接状态，收敛更慢）。
	for ip, o := range st.Observed {
		if _, ok := st.Slots[ip]; ok {
			continue
		}
		if _, ok := st.Rejected[ip]; ok {
			continue
		}
		window := idle
		if o.UDPSessions > 0 && udpIdle > window {
			window = udpIdle
		}
		if now.Sub(lastActive(o.LastSeen, o.LastTraffic)) > window {
			delete(st.Observed, ip)
		}
	}

	return allowSet, hasRejected
}

// oldestProvisional 返回最早授予的 provisional slot 的 IP（无则空串）。
// 用于「真实客户端抢占仅 SYN 候选占用的名额」，按 CandidateAt 最早、
// 同刻按 IP 升序，保证确定性。
func oldestProvisional(st *NodeIPState) string {
	best := ""
	var bestAt time.Time
	for ip, slot := range st.Slots {
		if !slot.Provisional {
			continue
		}
		if best == "" || slot.CandidateAt.Before(bestAt) ||
			(slot.CandidateAt.Equal(bestAt) && ip < best) {
			best, bestAt = ip, slot.CandidateAt
		}
	}
	return best
}

func (st *NodeIPState) touchObserved(ip string, a IPActivity, now time.Time) {
	o, ok := st.Observed[ip]
	if !ok {
		o = &ObservedIP{IP: ip, FirstSeen: now}
		st.Observed[ip] = o
	}
	o.LastSeen = now
	o.TCPSessions = a.TCPSessions
	o.UDPSessions = a.UDPSessions
	if a.Traffic {
		o.LastTraffic = now
	}
}

// grantedCount 返回持有 slot 的 IP 数（含 provisional）。
func (st *NodeIPState) grantedCount() int { return len(st.Slots) }

// activeGrantedCount 返回已建立（非 provisional）的 granted IP 数，即「在线」。
func (st *NodeIPState) activeGrantedCount() int {
	n := 0
	for _, s := range st.Slots {
		if !s.Provisional {
			n++
		}
	}
	return n
}
