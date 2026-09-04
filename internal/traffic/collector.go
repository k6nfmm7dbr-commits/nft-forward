// Package traffic 负责流量采集：读取 nft named counter、单调差分、
// reset 检测、写入 SQLite（totals / daily）。
//
// 方向定义（与 SBX 习惯一致）：
//   - upload / rx  = 客户端 → 转发服务器 → 目标（ct direction original）
//   - download / tx = 目标 → 转发服务器 → 客户端（ct direction reply）
//
// 正确性要求（每条都有回归测试）：
//
//   - **单调差分**：counter 单调递增，delta = cur - prev；
//   - **reset 检测**：cur < prev 说明 counter 被重置（表被外部删除/重建），
//     此时 delta = cur（新值即重置后的增量），绝不产生负数或把旧累计重复计入；
//   - **不制造假峰值**：counter 重置或首次见到某 counter 时，字节照常计入累计，
//     但**不写速率**（重置发生的时刻未知，除以采样间隔会得到虚高速率）；
//   - **真实 elapsed**：速率用「本次采样时刻 - 该 counter 上次采样时刻」计算，
//     不假设固定周期（进程卡顿、系统挂起都会让实际间隔偏离配置值）；
//   - **部分读取保护**：上一轮存在的 counter 若本轮消失且表仍存在，说明读取
//     不完整，本轮整体放弃提交 —— 否则 counter_state 的全量重写会丢掉基线，
//     恢复后这些 counter 会被当成新的从 0 全量重复入账；
//   - **跨天**：按配置时区计算 day，跨天自然写入新的一行，不需要特殊处理；
//   - **重启恢复**：基线持久化在 counter_state 表，进程重启后继续差分。
package traffic

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
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
	Error  string
	LastOK int64
	Rates  map[int64]Rate
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
}

// NewCollector 构造采集器。
func NewCollector(db *database.DB, runner nft.Runner, tz string) *Collector {
	if runner == nil {
		runner = nft.ExecRunner{}
	}
	return &Collector{
		db:     db,
		runner: runner,
		tz:     tz,
		now:    time.Now,
		rates:  map[int64]Rate{},
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
	return Status{Error: c.lastError, LastOK: c.lastOK, Rates: rates}
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

// counterVal 是单个 counter 的读数。
type counterVal struct {
	bytes int64
	pkts  int64
}

// readCounters 读取本项目 filter 表的所有 named counter。
//
// 表不存在（首次启动、规则被清空）不是错误：返回空集合 + tableMissing=true，
// 调用方据此跳过「部分读取」保护（表整体消失时基线消失是合法的）。
func (c *Collector) readCounters(ctx context.Context) (map[string]counterVal, bool, error) {
	rc, out, stderr, err := c.runner.Run(ctx, "nft", "-j", "list", "counters", "table", "inet", nft.TableFilter)
	if err != nil {
		return nil, false, fmt.Errorf("读取 counter 失败: %w", err)
	}
	if rc != 0 {
		msg := strings.TrimSpace(stderr)
		if strings.Contains(msg, "No such file or directory") || strings.Contains(msg, "does not exist") {
			return map[string]counterVal{}, true, nil
		}
		return nil, false, fmt.Errorf("读取 counter 失败: %s", msg)
	}
	var doc nftCountersDoc
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		return nil, false, fmt.Errorf("counter JSON 解析失败: %w", err)
	}
	res := map[string]counterVal{}
	for _, item := range doc.Nftables {
		if item.Counter == nil {
			continue
		}
		res[item.Counter.Name] = counterVal{bytes: item.Counter.Bytes, pkts: item.Counter.Packets}
	}
	return res, false, nil
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
	if s == "" {
		return 0, fmt.Errorf("empty int")
	}
	var v int64
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return 0, fmt.Errorf("bad int %q", s)
		}
		v = v*10 + int64(ch-'0')
	}
	return v, nil
}

// baseline 是 counter_state 里的一行：字节、包、上次采样毫秒时间戳。
type baseline struct {
	bytes int64
	pkts  int64
	atMS  int64
}

// deltaAgg 聚合单条规则本轮的增量与速率有效性。
type deltaAgg struct {
	up, down       int64
	upPkts         int64
	downPkts       int64
	elapsedMS      int64
	valid          bool // 速率是否可信（两方向都有可信基线且间隔合理）
	seenUp, seenDn bool
}

// Tick 执行一轮采集。
func (c *Collector) Tick(ctx context.Context) error {
	counters, tableMissing, err := c.readCounters(ctx)
	if err != nil {
		c.setErr(err.Error())
		return err
	}

	now := c.now()
	nowSec := now.Unix()
	nowMS := now.UnixMilli()
	day := now.In(c.Location()).Format("2006-01-02")

	baselines, err := c.loadBaselines(ctx)
	if err != nil {
		c.setErr(err.Error())
		return err
	}

	// 部分读取保护：表仍存在时，上一轮的 counter 不应凭空消失。
	// 合法消失只有两种情况：表整体不存在（tableMissing），或规则被删除
	// —— 后者会由 nft 侧 delete counter 完成，同一轮里其它 counter 仍在，
	// 因此这里只在「本轮一条都没读到但基线非空」时判定不完整。
	if !tableMissing && len(baselines) > 0 && len(counters) == 0 {
		msg := "counter 快照为空但基线非空（疑似部分读取），本轮放弃提交"
		c.setErr(msg)
		return fmt.Errorf("%s", msg)
	}

	deltas := map[int64]*deltaAgg{}
	newBaselines := make(map[string]baseline, len(counters))
	resetHits := 0

	names := make([]string, 0, len(counters))
	for name := range counters {
		names = append(names, name)
	}
	sort.Strings(names) // 稳定顺序，便于测试与日志

	for _, name := range names {
		cur := counters[name]
		ruleID, dir, ok := parseCounterName(name)
		if !ok {
			continue
		}
		prev, had := baselines[name]

		var dBytes, dPkts int64
		elapsed := int64(0)
		valid := false
		switch {
		case !had:
			// 第一次看到这个 counter：字节可累计，但起点时刻未知，不算速率。
			dBytes, dPkts = cur.bytes, cur.pkts
		case cur.bytes < prev.bytes:
			// counter 被重置（表被外部删除重建）：新值即重置后的增量。
			// 重置时刻未知，不写速率，避免假峰值。
			dBytes, dPkts = cur.bytes, cur.pkts
			resetHits++
		default:
			dBytes = cur.bytes - prev.bytes
			dPkts = cur.pkts - prev.pkts
			if dPkts < 0 {
				dPkts = 0
			}
			elapsed = nowMS - prev.atMS
			// 真实 elapsed 必须落在合理区间：太小说明时钟回拨/重复采样，
			// 太大说明进程曾挂起（此时字节仍计入累计，只是不算速率）。
			valid = elapsed >= 200 && elapsed <= 10*60*1000
		}
		newBaselines[name] = baseline{bytes: cur.bytes, pkts: cur.pkts, atMS: nowMS}

		agg := deltas[ruleID]
		if agg == nil {
			agg = &deltaAgg{valid: true}
			deltas[ruleID] = agg
		}
		if dir == 1 {
			agg.up += dBytes
			agg.upPkts += dPkts
			agg.seenUp = true
		} else {
			agg.down += dBytes
			agg.downPkts += dPkts
			agg.seenDn = true
		}
		if elapsed > agg.elapsedMS {
			agg.elapsedMS = elapsed
		}
		agg.valid = agg.valid && valid
	}

	// 一条规则必须同时拿到上/下两个方向的可信基线，才写速率。
	for _, agg := range deltas {
		agg.valid = agg.valid && agg.seenUp && agg.seenDn && agg.elapsedMS > 0
	}

	if err := c.commit(ctx, day, nowSec, deltas, newBaselines); err != nil {
		c.setErr(err.Error())
		return err
	}

	// 更新内存速率。
	c.mu.Lock()
	for id, agg := range deltas {
		if !agg.valid {
			continue // 保留上一次速率，不写入不可信值
		}
		dt := float64(agg.elapsedMS) / 1000
		c.rates[id] = Rate{Upload: float64(agg.up) / dt, Download: float64(agg.down) / dt}
	}
	// 清理本轮未出现（规则被删）的速率。
	for id := range c.rates {
		if _, ok := deltas[id]; !ok {
			delete(c.rates, id)
		}
	}
	c.lastError = ""
	c.lastOK = nowSec
	c.mu.Unlock()

	if resetHits > 0 {
		slog.Warn("检测到 counter 归零，已补入累计；为避免假峰值本轮不写速率", "count", resetHits)
	}
	return nil
}

func (c *Collector) setErr(msg string) {
	c.mu.Lock()
	c.lastError = msg
	c.mu.Unlock()
}

func (c *Collector) loadBaselines(ctx context.Context) (map[string]baseline, error) {
	rows, err := c.db.QueryContext(ctx, "SELECT name,last_bytes,last_pkts,updated_at FROM counter_state")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]baseline{}
	for rows.Next() {
		var name string
		var b, p, upd int64
		if err := rows.Scan(&name, &b, &p, &upd); err != nil {
			return nil, err
		}
		// 兼容早期版本以秒存储 updated_at 的库。
		if upd > 0 && upd < 1_000_000_000_000 {
			upd *= 1000
		}
		out[name] = baseline{bytes: b, pkts: p, atMS: upd}
	}
	return out, rows.Err()
}

// commit 把一轮差分结果原子入账：totals / daily / counter_state 同事务。
func (c *Collector) commit(ctx context.Context, day string, nowSec int64,
	deltas map[int64]*deltaAgg, baselines map[string]baseline) error {
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	// counter_state 全量重写（事务内一致）。
	if _, err := tx.ExecContext(ctx, "DELETE FROM counter_state"); err != nil {
		return err
	}
	names := make([]string, 0, len(baselines))
	for name := range baselines {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		b := baselines[name]
		if _, err := tx.ExecContext(ctx,
			"INSERT INTO counter_state(name,last_bytes,last_pkts,updated_at) VALUES(?,?,?,?)",
			name, b.bytes, b.pkts, b.atMS); err != nil {
			return err
		}
	}

	ids := make([]int64, 0, len(deltas))
	for id := range deltas {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, id := range ids {
		d := deltas[id]
		if d.up == 0 && d.down == 0 {
			continue
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO traffic_totals(rule_id,upload_bytes,download_bytes) VALUES(?,?,?)
			 ON CONFLICT(rule_id) DO UPDATE SET upload_bytes=upload_bytes+excluded.upload_bytes,
			 download_bytes=download_bytes+excluded.download_bytes`,
			id, d.up, d.down); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO traffic_daily(day,rule_id,upload_bytes,download_bytes) VALUES(?,?,?,?)
			 ON CONFLICT(day,rule_id) DO UPDATE SET upload_bytes=upload_bytes+excluded.upload_bytes,
			 download_bytes=download_bytes+excluded.download_bytes`,
			day, id, d.up, d.down); err != nil {
			return err
		}
	}
	_ = nowSec
	return tx.Commit()
}
