// Package service 编排 nft-forward 的运行：配置、DB、采集、策略、API。
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
	"github.com/k6nfmm7dbr-commits/nft-forward/internal/traffic"
)

// Serve 启动服务，阻塞直至 SIGINT/SIGTERM。
func Serve() int {
	cfg, err := config.LoadStrict()
	if err != nil {
		slog.Error(err.Error())
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

	srv, hs := api.New(cfg, db, store, pol, collect)

	addr := net.JoinHostPort(cfg.Listen, fmt.Sprint(cfg.Port))
	ln, lerr := net.Listen("tcp", addr)
	if lerr != nil {
		slog.Error("无法监听 "+addr, "err", lerr)
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// 启动立即 reconcile 一次（恢复 nft 期望状态）。
	if err := pol.Reconcile(ctx); err != nil {
		slog.Warn("首次 reconcile 失败", "err", err)
	} else {
		slog.Info("策略系统就绪")
	}

	// 采集循环。
	collectCtx, collectCancel := context.WithCancel(ctx)
	defer collectCancel()
	go runCollector(collectCtx, collect, time.Duration(cfg.Interval)*time.Second)

	// 策略周期 reconcile（一致性自愈 + 配额事件兜底 + IP 准入）。
	// 500ms 是为了缩短「连接已建立但 slot 未授予」的竞态窗口。
	// 注意：reconcile 现在只在结构变化时重写 nft 链，稳定期只做元素增量，
	// 因此高频运行不会清零流量 counter。
	polCtx, polCancel := context.WithCancel(ctx)
	defer polCancel()
	go runPolicy(polCtx, pol, 500*time.Millisecond)

	// SSE 快照推送由 API 在状态变化时主动 Publish；这里定期兜底广播。
	go runSnapshotPublisher(ctx, srv, 2*time.Second)

	slog.Info("面板已启动 http://" + addr)

	serveErr := make(chan error, 1)
	go func() { serveErr <- hs.Serve(ln) }()

	select {
	case <-ctx.Done():
	case err := <-serveErr:
		if err != nil && err != http.ErrServerClosed {
			slog.Error("HTTP 服务异常退出", "err", err)
			return 1
		}
	}

	polCancel()
	collectCancel()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := hs.Shutdown(shutdownCtx); err != nil {
		slog.Warn("HTTP 关闭超时", "err", err)
	}
	return 0
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

// runSnapshotPublisher 周期性向 SSE 订阅者广播快照（兜底，变化推送由 API 主动触发）。
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
