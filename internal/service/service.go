// Package service 编排 nft-forward 的运行：配置、DB、采集、策略、DNS、API。
package service

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/k6nfmm7dbr-commits/nft-forward/internal/api"
	"github.com/k6nfmm7dbr-commits/nft-forward/internal/config"
	"github.com/k6nfmm7dbr-commits/nft-forward/internal/database"
	"github.com/k6nfmm7dbr-commits/nft-forward/internal/forward"
	"github.com/k6nfmm7dbr-commits/nft-forward/internal/nft"
	"github.com/k6nfmm7dbr-commits/nft-forward/internal/policy"
	"github.com/k6nfmm7dbr-commits/nft-forward/internal/resolve"
	"github.com/k6nfmm7dbr-commits/nft-forward/internal/rulesvc"
	"github.com/k6nfmm7dbr-commits/nft-forward/internal/traffic"
)

// Serve 启动服务，阻塞直至 SIGINT/SIGTERM。
func Serve() int {
	cfg, err := config.LoadStrict()
	if err != nil {
		slog.Error(err.Error())
		return 1
	}
	// fail-closed：令牌 / 端口 / 入口路径三项缺一不可。
	// 宁可不启动，也不能带着「无认证 / 固定端口 / 固定入口」的状态对外监听。
	if err := cfg.ValidateServe(); err != nil {
		slog.Error("配置未完成初始化，拒绝启动", "err", err)
		return 1
	}

	db, err := database.Open(cfg.DB)
	if err != nil {
		slog.Error("数据库打开失败", "err", err)
		return 1
	}
	defer db.Close()

	store := forward.NewStore(db.DB)
	runner := nft.ExecRunner{}

	pol := policy.New(db.DB, store, runner, cfg.NftConf, "")
	collect := traffic.NewCollector(db, runner, cfg.TZ)
	// 配额实时判定：policy 用 collector 的「已落库累计 + counter 基线」快照，
	// 配合自己那轮 nft 读数算出未落库增量，无需额外系统调用。
	pol.SetQuotaSource(collect.LiveSnapshot)

	// 统一规则变更服务：Web API 与后台 DNS worker 共用它，
	// 因此不存在「两套 nft 修改逻辑」。
	resolver := resolve.NewSystemResolver(5 * time.Second)
	rules := rulesvc.New(store, pol, resolver,
		func() forward.GuardPorts { return forward.GuardPorts(cfg.GuardPorts()) })

	srv, hs := api.New(cfg, db, store, pol, rules, collect)
	// SSE 广播依赖 srv，构造后回填。
	rules.SetNotifier(func() { srv.PublishSnapshotNow() })

	addr := net.JoinHostPort(cfg.Listen, fmt.Sprint(cfg.Port))
	ln, lerr := net.Listen("tcp", addr)
	if lerr != nil {
		slog.Error("无法监听 "+addr, "err", lerr)
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// ---- HTTP 先起来，但此刻数据面尚未就绪 ----
	//
	// 顺序刻意是「先 Serve，再做首轮 reconcile」：
	//   · 先 Serve → /healthz 能立刻应答，安装器/systemd 不会因连不上而误判；
	//   · 但在首轮 reconcile 成功之前 /healthz 返回 503（见 api.Server.Ready），
	//     因此「HTTP 活着但转发数据面没加载」不会被当成健康。
	serveErr := make(chan error, 1)
	go func() { serveErr <- hs.Serve(ln) }()
	slog.Info("HTTP 已监听（数据面就绪前 /healthz 返回 503）", "listen", addr)

	// ---- 首轮数据面 enforcement：成功才算 ready ----
	//
	// 带重试：nftables 在开机早期可能短暂不可用（模块尚未加载完），
	// 一次失败就判死会让安装/升级无谓失败。重试仍失败则保持未就绪
	// （healthz 503），由周期 reconcile 继续尝试自愈。
	//
	// conntrack 不可用**不影响**这里：结构 enforcement（DNAT/counter/quota）
	// 不依赖 conntrack，只有 IP slot 会进入冻结状态。
	if reconcileWithRetry(ctx, pol) {
		slog.Info("数据面就绪（首轮 nft enforcement 成功）", "entry", cfg.EntryRoute()+"/")
	} else {
		slog.Error("首轮 nft enforcement 失败：数据面未就绪，/healthz 将返回 503；" +
			"周期 reconcile 会继续尝试恢复")
	}

	// 首轮采集立即执行一次：让 collector 的 LiveDelta 尽快就绪，
	// 否则最初几百毫秒内配额判定只能退回纯 SQLite 口径。
	if err := collect.Tick(ctx); err != nil {
		slog.Debug("首次采集失败", "err", err)
	}

	// 采集循环。
	collectCtx, collectCancel := context.WithCancel(ctx)
	defer collectCancel()
	go runCollector(collectCtx, collect, time.Duration(cfg.Interval)*time.Second)

	// 策略周期 reconcile（一致性自愈 + 配额事件兜底 + IP 准入）。
	// 500ms 是为了缩短「连接已建立但 slot 未授予」的竞态窗口。
	// reconcile 只在结构/内容漂移时重写 nft 链，稳定期只做元素增量，
	// 因此高频运行不会清零流量 counter。
	polCtx, polCancel := context.WithCancel(ctx)
	defer polCancel()
	go runPolicy(polCtx, pol, 500*time.Millisecond)

	// 域名目标 DNS reconcile。
	dnsCtx, dnsCancel := context.WithCancel(ctx)
	defer dnsCancel()
	go runDNS(dnsCtx, rules, srv, time.Duration(cfg.DNSRefresh)*time.Second)

	// SSE 快照推送由变更服务在状态变化时主动 Publish；这里定期兜底广播。
	snapCtx, snapCancel := context.WithCancel(ctx)
	defer snapCancel()
	go runSnapshotPublisher(snapCtx, srv, 2*time.Second)

	select {
	case <-ctx.Done():
	case err := <-serveErr:
		if err != nil && err != http.ErrServerClosed {
			slog.Error("HTTP 服务异常退出", "err", err)
			return 1
		}
	}

	// 关闭顺序：先停所有后台 worker（DNS / policy / collector / SSE 广播），
	// 再优雅关闭 HTTP。全部 goroutine 都绑定在可取消的 ctx 上，
	// 因此进程退出前不会留下悬挂 goroutine。
	dnsCancel()
	polCancel()
	collectCancel()
	snapCancel()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := hs.Shutdown(shutdownCtx); err != nil {
		slog.Warn("HTTP 关闭超时", "err", err)
	}
	return 0
}

// initialReconcileAttempts 是首轮数据面 enforcement 的尝试次数。
//
// 开机早期 nftables 内核模块可能尚未完全就绪（systemd 的 After= 只保证
// 网络目标，不保证 nf_tables 已加载）。一次失败就判死会让安装/升级无谓失败，
// 因此重试若干次；仍失败则保持未就绪状态（healthz 503），交给周期 reconcile。
const initialReconcileAttempts = 5

// reconcileWithRetry 反复尝试首轮 reconcile，成功返回 true。
func reconcileWithRetry(ctx context.Context, pol *policy.Service) bool {
	for i := 0; i < initialReconcileAttempts; i++ {
		if err := pol.Reconcile(ctx); err == nil {
			return true
		} else if i == initialReconcileAttempts-1 {
			slog.Error("首轮 nft enforcement 失败", "attempts", initialReconcileAttempts, "err", err)
		} else {
			slog.Warn("首轮 nft enforcement 失败，稍后重试", "attempt", i+1, "err", err)
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(time.Duration(i+1) * time.Second):
		}
	}
	return false
}

func runCollector(ctx context.Context, c *traffic.Collector, interval time.Duration) {
	if interval < time.Second {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := c.Tick(ctx); err != nil {
				slog.Debug("采集失败", "err", err)
			}
		}
	}
}

// runPolicy 周期 reconcile。interval 允许亚秒（IP 准入需要尽快授予 slot，
// 否则新 IP 的连接会在 allow set 更新前被 drop）。
func runPolicy(ctx context.Context, p *policy.Service, interval time.Duration) {
	if interval < 100*time.Millisecond {
		interval = 100 * time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := p.Reconcile(ctx); err != nil {
				slog.Debug("策略 reconcile 失败", "err", err)
			}
		}
	}
}

// runDNS 周期刷新域名目标。
//
// 首轮立即执行一次（服务重启后尽快恢复/校正解析结果），之后按配置周期运行。
// 单轮失败只记录，不影响已生效的转发（last-known-good 由 resolve 层保证）。
func runDNS(ctx context.Context, rules *rulesvc.Service, srv *api.Server, interval time.Duration) {
	if interval < 10*time.Second {
		interval = 10 * time.Second
	}
	run := func() {
		changed, err := rules.RefreshDNS(ctx)
		if err != nil {
			slog.Warn("DNS 刷新失败", "err", err)
			srv.SetDNSHealth(api.DNSHealth{Err: err.Error()})
			return
		}
		if changed > 0 {
			slog.Info("域名目标已更新", "rules", changed)
		}
		srv.SetDNSHealth(api.DNSHealth{LastOK: time.Now().Unix()})
	}
	run()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			run()
		}
	}
}

// runSnapshotPublisher 周期性向 SSE 订阅者广播快照（兜底，变化推送由变更服务触发）。
func runSnapshotPublisher(ctx context.Context, srv *api.Server, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			srv.PublishSnapshotTick()
		}
	}
}
