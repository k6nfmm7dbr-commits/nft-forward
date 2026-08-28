// Package traffic 负责流量采集：读取 nft named counter、单调差分、
// reset/epoch 检测、写入 SQLite（totals / daily / samples）。
//
// 方向定义（与 SBX 习惯一致）：
//   - upload / rx  = 客户端 → 转发服务器 → 目标（ct direction original）
//   - download / tx = 目标 → 转发服务器 → 客户端（ct direction reply）
//
// counter reset 处理（关键，禁止制造假流量）：
//   - counter 是单调递增的；当 current < previous 时，说明 counter 被重置
//     （nft 表重建 / 服务重启 / 规则重新生成），此时 delta = current（新值即
//     重置后的增量），并把 baseline 重置为 current；
//   - 绝不允许出现 unsigned 溢出，也绝不把旧累计再加一次。
package traffic

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/k6nfmm7dbr-commits/nft-forward/internal/database"
	"github.com/k6nfmm7dbr-commits/nft-forward/internal/nft"
)

// Rate 是单条规则的实时速率（字节/秒）。
type Rate struct {
	Upload   float64 `json:"rx"` // 上传（客户端→目标）
	Download float64 `json:"tx"` // 下载（目标→客户端）
}

// Status 是采集器快照。
type Status struct {
	Error   string
	LastOK  int64
	Rates   map[int64]Rate
	ConnTCP map[int64]int
	ConnUDP map[int64]int
}

// Collector 采集 nft named counter 并写库。
type Collector struct {
	db     *database.DB
	runner nft.Runner
	tz     string
	now    func() time.Time

	mu        sync.RWMutex
	lastError string
	lastOK    int64
	rates     map[int64]Rate
	lastTick  map[int64]time.Time // 上一次有效采样的时间（算速率用）
}

// NewCollector 构造采集器。
func NewCollector(db *database.DB, runner nft.Runner, tz string) *Collector {
	if runner == nil {
		runner = nft.ExecRunner{}
	}
	return &Collector{
		db:       db,
		runner:   runner,
		tz:       tz,
		now:      time.Now,
		rates:    map[int64]Rate{},
		lastTick: map[int64]time.Time{},
	}
}

// SetClock 注入时钟（测试用）。
func (c *Collector) SetClock(fn func() time.Time) { c.now = fn }

// Location 返回时区。
func (c *Collector) Location() *time.Location { return Location(c.tz) }

// Location 解析时区，缺省 UTC+8（与 SBX 一致）。
func Location(tz string) *time.Location {
	if strings.TrimSpace(tz) == "" {
		return time.FixedZone("UTC+8", 8*3600)
	}
	if loc, err := time.LoadLocation(tz); err == nil {
		return loc
	}
	return time.FixedZone("UTC+8", 8*3600)
}

// Snapshot 返回采集器快照。
func (c *Collector) Snapshot() Status {
	c.mu.RLock()
	defer c.mu.RUnlock()
	rates := make(map[int64]Rate, len(c.rates))
	for k, v := range c.rates {
		rates[k] = v
	}
	return Status{
		Error:  c.lastError,
		LastOK: c.lastOK,
		Rates:  rates,
	}
}

// nftCountersDoc 是 `nft -j list counters table inet nff_filter` 的 JSON 结构。
type nftCountersDoc struct {
	Nftables []struct {
		Counter *struct {
			Name    string `json:"name"`
			Bytes   int64  `json:"bytes"`
			Packets int64  `json:"packets"`
		} `json:"counter"`
	} `json:"nftables"`
}

// readCounters 读取本项目 filter 表的所有 named counter。
func (c *Collector) readCounters(ctx context.Context) (map[string]int64, error) {
	rc, out, stderr, err := c.runner.Run(ctx, "nft", "-j", "list", "counters", "table", "inet", nft.TableFilter)
	if err != nil || rc != 0 {
		return nil, fmt.Errorf("读取 counter 失败: %s", strings.TrimSpace(stderr))
	}
	var doc nftCountersDoc
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		return nil, fmt.Errorf("counter JSON 解析失败: %w", err)
	}
	out_ := map[string]int64{}
	for _, item := range doc.Nftables {
		if item.Counter == nil {
			continue
		}
		out_[item.Counter.Name] = item.Counter.Bytes
	}
	return out_, nil
}

// parseCounterName 把 "nff_filter_up_<id>" / "nff_filter_down_<id>" 解析为 (ruleID, dir)。
// dir: 1=upload(rx)，2=download(tx)。
func parseCounterName(name string) (ruleID int64, dir int, ok bool) {
	upPrefix := nft.TableFilter + "_up_"
	downPrefix := nft.TableFilter + "_down_"
	switch {
	case strings.HasPrefix(name, upPrefix):
		id, err := parseInt64(name[len(upPrefix):])
		if err != nil {
			return 0, 0, false
		}
		return id, 1, true
	case strings.HasPrefix(name, downPrefix):
		id, err := parseInt64(name[len(downPrefix):])
		if err != nil {
			return 0, 0, false
		}
		return id, 2, true
	}
	return 0, 0, false
}

func parseInt64(s string) (int64, error) {
	var v int64
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return 0, fmt.Errorf("bad int %q", s)
		}
		v = v*10 + int64(ch-'0')
	}
	return v, nil
}

// Tick 执行一轮采集。
func (c *Collector) Tick(ctx context.Context) error {
	counters, err := c.readCounters(ctx)
	if err != nil {
		c.mu.Lock()
		c.lastError = err.Error()
		c.mu.Unlock()
		return err
	}

	now := c.now()
	nowSec := now.Unix()
	day := now.In(c.Location()).Format("2006-01-02")

	// 读取 counter_state 基线。
	baselines, err := c.loadBaselines(ctx)
	if err != nil {
		c.mu.Lock()
		c.lastError = err.Error()
		c.mu.Unlock()
		return err
	}

	// 计算每条规则的上传/下载增量（含 reset 检测）。
	deltas := map[int64]*deltaAgg{}

	for name, cur := range counters {
		ruleID, dir, ok := parseCounterName(name)
		if !ok {
			continue
		}
		prev := baselines[name]
		var d int64
		if cur >= prev {
			d = cur - prev // 正常单调递增
		} else {
			// counter 被重置（表重建/重启）：新值即重置后增量，绝不产生负/溢出
			d = cur
			slog.Info("counter 重置, 基线已衔接", "counter", name, "cur", cur)
		}
		baselines[name] = cur

		dl := deltas[ruleID]
		if dl == nil {
			dl = &deltaAgg{}
			deltas[ruleID] = dl
		}
		if dir == 1 {
			dl.up += d
		} else {
			dl.down += d
		}
	}

	// 写库：totals / daily / samples（一个事务）。
	if err := c.commit(ctx, day, nowSec, deltas, baselines); err != nil {
		c.mu.Lock()
		c.lastError = err.Error()
		c.mu.Unlock()
		return err
	}

	// 更新内存速率。
	c.mu.Lock()
	for id, dl := range deltas {
		last, hasLast := c.lastTick[id]
		if hasLast {
			dt := now.Sub(last).Seconds()
			if dt > 0 {
				c.rates[id] = Rate{Upload: float64(dl.up) / dt, Download: float64(dl.down) / dt}
			}
		}
		c.lastTick[id] = now
	}
	// 清理本轮未出现（规则被删）的速率。
	for id := range c.rates {
		if _, ok := deltas[id]; !ok {
			delete(c.rates, id)
			delete(c.lastTick, id)
		}
	}
	c.lastError = ""
	c.lastOK = nowSec
	c.mu.Unlock()

	return nil
}

func (c *Collector) loadBaselines(ctx context.Context) (map[string]int64, error) {
	rows, err := c.db.QueryContext(ctx, "SELECT name,last_bytes FROM counter_state")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var name string
		var b int64
		if err := rows.Scan(&name, &b); err != nil {
			return nil, err
		}
		out[name] = b
	}
	return out, rows.Err()
}

type deltaAgg struct{ up, down int64 }

func (c *Collector) commit(ctx context.Context, day string, nowSec int64, deltas map[int64]*deltaAgg, baselines map[string]int64) error {
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	// counter_state 全量重写。
	if _, err := tx.ExecContext(ctx, "DELETE FROM counter_state"); err != nil {
		return err
	}
	for name, b := range baselines {
		if _, err := tx.ExecContext(ctx,
			"INSERT INTO counter_state(name,last_bytes,last_pkts,updated_at) VALUES(?,?,0,?)",
			name, b, nowSec); err != nil {
			return err
		}
	}

	for id, d := range deltas {
		if d.up == 0 && d.down == 0 {
			continue
		}
		// totals 累加。
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO traffic_totals(rule_id,upload_bytes,download_bytes) VALUES(?,?,?)
			 ON CONFLICT(rule_id) DO UPDATE SET upload_bytes=upload_bytes+excluded.upload_bytes,
			 download_bytes=download_bytes+excluded.download_bytes`,
			id, d.up, d.down); err != nil {
			return err
		}
		// daily 累加。
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO traffic_daily(day,rule_id,upload_bytes,download_bytes) VALUES(?,?,?,?)
			 ON CONFLICT(day,rule_id) DO UPDATE SET upload_bytes=upload_bytes+excluded.upload_bytes,
			 download_bytes=download_bytes+excluded.download_bytes`,
			day, id, d.up, d.down); err != nil {
			return err
		}
	}
	return tx.Commit()
}

var _ = sql.ErrNoRows
