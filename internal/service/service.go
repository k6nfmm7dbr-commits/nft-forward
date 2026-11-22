// Package service 编排 nft-forward 的运行：配置、DB、采集、策略、DNS、API。
package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/k6nfmm7dbr-commits/nft-forward/internal/api"
	"github.com/k6nfmm7dbr-commits/nft-forward/internal/config"
	"github.com/k6nfmm7dbr-commits/nft-forward/internal/database"
	"github.com/k6nfmm7dbr-commits/nft-forward/internal/forward"
	"github.com/k6nfmm7dbr-commits/nft-forward/internal/fsx"
	"github.com/k6nfmm7dbr-commits/nft-forward/internal/nft"
	"github.com/k6nfmm7dbr-commits/nft-forward/internal/policy"
	"github.com/k6nfmm7dbr-commits/nft-forward/internal/resolve"
	"github.com/k6nfmm7dbr-commits/nft-forward/internal/rulesvc"
	"github.com/k6nfmm7dbr-commits/nft-forward/internal/traffic"
)

// Serve runs until SIGINT/SIGTERM or a fatal startup/server failure.
func Serve() int {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := serve(ctx, nft.ExecRunner{}); err != nil {
		slog.Error("服务失败", "err", err)
		return 1
	}
	return 0
}

func serve(parent context.Context, runner nft.Runner) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	startup, done := context.WithTimeout(ctx, 18*time.Second)
	defer done()
	daemonCtx, stopWaiting := context.WithTimeout(startup, 500*time.Millisecond)
	daemonLock, err := fsx.Lock(daemonCtx, config.ConfPath()+".serve.lock")
	stopWaiting()
	if err != nil {
		return fmt.Errorf("无法取得服务实例锁: %w", err)
	}
	defer daemonLock.Close()
	cfgLock, err := config.Lock(startup)
	if err != nil {
		return err
	}
	defer cfgLock.Close()
	cfg, err := config.LoadStrict()
	if err != nil {
		return err
	}
	if err := cfg.ValidateServe(); err != nil {
		return err
	}
	expected, err := config.DatabaseExpected(cfg)
	if err != nil {
		return err
	}
	db, err := database.OpenConfigured(startup, cfg.DB, expected)
	if err != nil {
		return fmt.Errorf("数据库打开失败: %w", err)
	}
	defer db.Close()

	store := forward.NewStore(db.DB)
	current, err := store.ListActive(startup)
	if err != nil {
		return fmt.Errorf("读取保存的规则失败: %w", err)
	}
	if err := validateSavedRules(current, cfg.Port); err != nil {
		return err
	}
	addr := net.JoinHostPort(cfg.Listen, fmt.Sprint(cfg.Port))
	ln, err := (&net.ListenConfig{}).Listen(startup, "tcp", addr)
	if err != nil {
		return fmt.Errorf("无法监听 %s: %w", addr, err)
	}
	defer ln.Close()

	pol := policy.New(db.DB, store, runner, cfg.NftConf, "")
	collect := traffic.NewCollector(db, runner, cfg.TZ)
	pol.SetQuotaSource(collect.LiveSnapshot)
	// Capture pre-existing counters before reconciling so startup quota does
	// not rely solely on previously persisted bytes after an interruption.
	if err := collect.Tick(startup); err != nil {
		slog.Warn("首次采集失败", "err", err)
	}
	if err := reconcileWithRetry(startup, pol.Reconcile); err != nil {
		if parent.Err() != nil {
			return nil
		}
		return fmt.Errorf("首轮 nft enforcement 失败: %w", err)
	}
	if err := config.Checkpoint(cfg); err != nil {
		return fmt.Errorf("无法记录健康配置: %w", err)
	}
	_ = cfgLock.Close()
	done()

	rules := rulesvc.New(store, pol, resolve.NewSystemResolver(5*time.Second), nil)
	rules.SetMutationLock(func(ctx context.Context) (forward.GuardPorts, func(), error) {
		lock, err := config.Lock(ctx)
		if err != nil {
			return nil, nil, err
		}
		current, err := config.LoadStrict()
		if err != nil {
			lock.Close()
			return nil, nil, err
		}
		// Reserve both the live and the staged panel ports through restart.
		// If the database was changed, restart before accepting edits to it.
		if current.DB != cfg.DB {
			lock.Close()
			return nil, nil, fmt.Errorf("数据库路径已变更，请重启服务")
		}
		guards := current.GuardPorts()
		guards[cfg.Port] = "面板"
		return guards, func() { _ = lock.Close() }, nil
	})
	srv, hs := api.New(cfg, db, store, pol, rules, collect)
	hs.BaseContext = func(net.Listener) context.Context { return ctx }
	rules.SetNotifier(srv.PublishSnapshotNow)
	serveErr := make(chan error, 1)
	go func() { serveErr <- hs.Serve(ln) }()
	slog.Info("HTTP 与数据面已就绪", "listen", addr)

	var wg sync.WaitGroup
	worker := func(run func()) { wg.Add(1); go func() { defer wg.Done(); run() }() }
	worker(func() { runCollector(ctx, collect, time.Duration(cfg.Interval)*time.Second) })
	worker(func() { runPolicy(ctx, pol, 500*time.Millisecond) })
	worker(func() { runDNS(ctx, rules, srv, time.Duration(cfg.DNSRefresh)*time.Second) })
	worker(func() { runSnapshotPublisher(ctx, srv, 2*time.Second) })

	var exitErr error
	select {
	case <-ctx.Done():
	case err := <-serveErr:
		if !errors.Is(err, http.ErrServerClosed) {
			exitErr = fmt.Errorf("HTTP 异常退出: %w", err)
		}
	}
	cancel()
	shutdown, stop := context.WithTimeout(context.Background(), 10*time.Second)
	defer stop()
	if err := hs.Shutdown(shutdown); err != nil {
		_ = hs.Close()
		slog.Warn("HTTP 关闭超时", "err", err)
	}
	wg.Wait()
	return exitErr
}

func validateSavedRules(rules []*forward.Rule, panelPort int) error {
	type listen struct {
		port int
		tcp  bool
	}
	used := map[listen]int64{}
	for _, r := range rules {
		if r.ListenPort == panelPort {
			return fmt.Errorf("面板端口 %d 与规则 %d 冲突", panelPort, r.ID)
		}
		if !r.Enabled {
			continue
		}
		cp := *r
		if r.ID <= 0 || r.ID > 4294967295 {
			return fmt.Errorf("规则 ID 超出 nft mark 范围: %d", r.ID)
		}
		if err := forward.Validate(&cp); err != nil {
			return fmt.Errorf("已保存规则 %d 无效: %w", r.ID, err)
		}
		for _, tcp := range []bool{true, false} {
			if (tcp && !r.HasTCP()) || (!tcp && !r.HasUDP()) {
				continue
			}
			k := listen{r.ListenPort, tcp}
			if id := used[k]; id != 0 {
				return fmt.Errorf("规则 %d 与 %d 监听端口冲突", id, r.ID)
			}
			used[k] = r.ID
		}
	}
	return nil
}

func reconcileWithRetry(ctx context.Context, reconcile func(context.Context) error) error {
	const attempts = 5
	var last error
	for i := 0; i < attempts; i++ {
		if err := ctx.Err(); err != nil {
			return errors.Join(last, err)
		}
		if last = reconcile(ctx); last == nil {
			return nil
		}
		if i == attempts-1 {
			break
		}
		slog.Warn("首轮 nft enforcement 失败，稍后重试", "attempt", i+1, "err", last)
		timer := time.NewTimer(time.Duration(i+1) * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return errors.Join(last, ctx.Err())
		case <-timer.C:
		}
	}
	return last
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
			lock, err := config.Lock(ctx)
			if err == nil {
				err = c.Tick(ctx)
				_ = lock.Close()
			}
			if err != nil && ctx.Err() == nil {
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
			lock, err := config.Lock(ctx)
			if err == nil {
				err = p.Reconcile(ctx)
				_ = lock.Close()
			} else {
				p.MarkUnready(err)
			}
			if err != nil && ctx.Err() == nil {
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
