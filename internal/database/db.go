// Package database 封装 SQLite 访问：单连接 + WAL + 建表/迁移。
package database

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"modernc.org/sqlite"
)

// Schema 是建表脚本（全新库）。
//
// 方向定义（与 SBX 习惯一致）：
//   - upload / rx  = 客户端 → 转发服务器 → 目标
//   - download / tx = 目标 → 转发服务器 → 客户端
//
// rules.deleted 是软删除标记：删除转发规则时不物理删除，保留历史流量可审计。
//
// 关于 listen_address：v0.2 起转发规则**没有监听地址**概念（用户只配监听端口，
// nft 侧用 fib daddr type local 匹配本机地址）。老库里可能存在该列，
// 迁移策略是「保留列、不再读写」——见 migrate()。全新库不再创建该列。
const Schema = `
CREATE TABLE IF NOT EXISTS meta (
    k TEXT PRIMARY KEY,
    v TEXT
);
CREATE TABLE IF NOT EXISTS rules (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    name                 TEXT    NOT NULL,
    enabled              INTEGER NOT NULL DEFAULT 1,
    protocol             TEXT    NOT NULL,
    listen_port          INTEGER NOT NULL,
    target_address       TEXT    NOT NULL,
    target_port          INTEGER NOT NULL,
    created_at           INTEGER NOT NULL DEFAULT 0,
    updated_at           INTEGER NOT NULL DEFAULT 0,
    deleted              INTEGER NOT NULL DEFAULT 0,
    deleted_at           INTEGER NOT NULL DEFAULT 0,
    quota_enabled        INTEGER NOT NULL DEFAULT 0,
    quota_limit_bytes    INTEGER NOT NULL DEFAULT 0,
    quota_reset_baseline INTEGER NOT NULL DEFAULT 0,
    ip_limit_enabled     INTEGER NOT NULL DEFAULT 0,
    ip_limit_max         INTEGER NOT NULL DEFAULT 0,
    resolved_ipv4        TEXT    NOT NULL DEFAULT '',
    resolved_ipv6        TEXT    NOT NULL DEFAULT '',
    resolved_at          INTEGER NOT NULL DEFAULT 0,
    resolve_status       TEXT    NOT NULL DEFAULT '',
    resolve_error        TEXT    NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS counter_state (
    name       TEXT PRIMARY KEY,
    last_bytes INTEGER NOT NULL DEFAULT 0,
    last_pkts  INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS traffic_daily (
    day            TEXT    NOT NULL,
    rule_id        INTEGER NOT NULL,
    upload_bytes   INTEGER NOT NULL DEFAULT 0,
    download_bytes INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (day, rule_id)
);
CREATE INDEX IF NOT EXISTS idx_daily_day ON traffic_daily(day);
-- 单规则趋势查询（WHERE rule_id=? ORDER BY day DESC LIMIT ?）无法用主键 (day, rule_id)
-- 的前缀，没有这条索引就只能全表扫描；规则详情页与 60s 轮询都会走它。
-- 覆盖索引：查询只取 day/upload/download，索引本身即可满足，不回表。
CREATE INDEX IF NOT EXISTS idx_daily_rule
    ON traffic_daily(rule_id, day, upload_bytes, download_bytes);
CREATE TABLE IF NOT EXISTS traffic_totals (
    rule_id        INTEGER PRIMARY KEY,
    upload_bytes   INTEGER NOT NULL DEFAULT 0,
    download_bytes INTEGER NOT NULL DEFAULT 0
);
`

// addColumns 是升级老库时需要补齐的列（幂等：已存在则跳过）。
//
// 只做 ADD COLUMN，绝不 DROP / 重建表：SQLite 的 DROP COLUMN 需要重写整表，
// 一旦中途失败可能丢数据。历史 listen_address 列因此被原样保留（新代码不读写它），
// 规则 ID、流量统计、配额、IP 限制、每日历史全部不受影响。
var addColumns = []struct{ col, ddl string }{
	{"resolved_ipv4", "ALTER TABLE rules ADD COLUMN resolved_ipv4 TEXT NOT NULL DEFAULT ''"},
	{"resolved_ipv6", "ALTER TABLE rules ADD COLUMN resolved_ipv6 TEXT NOT NULL DEFAULT ''"},
	{"resolved_at", "ALTER TABLE rules ADD COLUMN resolved_at INTEGER NOT NULL DEFAULT 0"},
	{"resolve_status", "ALTER TABLE rules ADD COLUMN resolve_status TEXT NOT NULL DEFAULT ''"},
	{"resolve_error", "ALTER TABLE rules ADD COLUMN resolve_error TEXT NOT NULL DEFAULT ''"},
}

// DB 包装 *sql.DB。单写者，连接数限制为 1 以规避 SQLITE_BUSY。
type DB struct {
	*sql.DB
	path string
}

// Exists checks whether the configured SQLite file is present without
// mistaking dangling links, empty files, or orphaned journals for first use.
func Exists(path string) (bool, error) {
	st, err := os.Stat(path)
	if err == nil {
		if !st.Mode().IsRegular() || st.Size() == 0 {
			return false, fmt.Errorf("规则数据库不是非空普通文件: %s", path)
		}
		return true, nil
	}
	if !os.IsNotExist(err) {
		return false, err
	}
	for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
		if _, err := os.Lstat(path + suffix); !os.IsNotExist(err) {
			if err != nil {
				return false, err
			}
			return false, fmt.Errorf("主数据库缺失但发现数据库路径或日志: %s", path+suffix)
		}
	}
	return false, nil
}

func connect(path, mode string) (*DB, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	uri := url.URL{Scheme: "file", Path: abs, RawQuery: "mode=" + mode}
	db := sql.OpenDB(&pragmaConnector{dsn: uri.String()})
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	return &DB{DB: db, path: path}, nil
}

// OpenReadOnly never creates a database, changes its schema, or changes its
// journal mode. SQLite still reads the WAL (unlike immutable mode).
func OpenReadOnly(path string) (*DB, error) { return connect(path, "ro") }

func Open(path string) (*DB, error) { return OpenConfigured(context.Background(), path, false) }

// OpenConfigured refuses to initialize a missing database when this path
// was previously known to contain service state.
func OpenConfigured(ctx context.Context, path string, requireExisting bool) (*DB, error) {
	if path == "" {
		return nil, fmt.Errorf("数据库路径不能为空")
	}
	exists, err := Exists(path)
	if err != nil {
		return nil, err
	}
	mode := "rw"
	if !exists {
		if requireExisting {
			return nil, fmt.Errorf("已初始化的数据库缺失: %s", path)
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return nil, err
		}
		mode = "rwc"
	}
	d, err := connect(path, mode)
	if err != nil {
		return nil, err
	}
	if err := d.migrate(ctx, exists); err != nil {
		d.Close()
		return nil, err
	}
	var journal string
	if err := d.QueryRowContext(ctx, "PRAGMA journal_mode=WAL").Scan(&journal); err != nil || journal != "wal" {
		slog.Warn("WAL 不可用, 使用现有日志模式", "mode", journal, "err", err)
	}
	return d, nil
}

// Path 返回数据库文件路径。
func (d *DB) Path() string { return d.path }

// Run schema creation and all additive migrations in one SQLite transaction.
func (d *DB) migrate(ctx context.Context, existing bool) error {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("开启迁移事务失败: %w", err)
	}
	defer tx.Rollback()
	if existing {
		var found int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE type='table' AND name='rules'`).Scan(&found); err != nil {
			return err
		}
		if found != 1 {
			return fmt.Errorf("现有数据库缺少 rules 表，拒绝初始化: %s", d.path)
		}
	}
	for _, stmt := range splitStatements(Schema) {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("建表失败: %w", err)
		}
	}
	have, err := ruleColumns(ctx, tx)
	if err != nil {
		return err
	}
	for _, c := range addColumns {
		if !have[c.col] {
			if _, err := tx.ExecContext(ctx, c.ddl); err != nil {
				return fmt.Errorf("升级 rules 表失败(%s): %w", c.col, err)
			}
		}
	}
	// Verify fields used by the backend before committing any migration.
	const probe = `SELECT id,name,enabled,protocol,listen_port,target_address,target_port,created_at,updated_at,
        deleted,deleted_at,quota_enabled,quota_limit_bytes,quota_reset_baseline,ip_limit_enabled,ip_limit_max,
        resolved_ipv4,resolved_ipv6,resolved_at,resolve_status,resolve_error FROM rules LIMIT 0`
	rows, err := tx.QueryContext(ctx, probe)
	if err != nil {
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	return tx.Commit()
}

func ruleColumns(ctx context.Context, tx *sql.Tx) (map[string]bool, error) {
	rows, err := tx.QueryContext(ctx, "PRAGMA table_info(rules)")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull int
		var dflt sql.NullString
		var pk int
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return nil, err
		}
		out[name] = true
	}
	return out, rows.Err()
}

type pragmaConnector struct{ dsn string }

func (c *pragmaConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := (&sqlite.Driver{}).Open(c.dsn)
	if err != nil {
		return nil, err
	}
	if ec, ok := conn.(driver.ExecerContext); ok {
		if _, err := ec.ExecContext(ctx, "PRAGMA busy_timeout=30000", nil); err != nil {
			slog.Debug("busy_timeout 设置失败", "err", err)
		}
	}
	return conn, nil
}

func (c *pragmaConnector) Driver() driver.Driver { return &sqlite.Driver{} }

func splitStatements(script string) []string {
	var out []string
	for _, part := range strings.Split(script, ";") {
		stmt := strings.TrimSpace(part)
		if stmt == "" || isCommentOnly(stmt) {
			continue
		}
		out = append(out, stmt)
	}
	return out
}

func isCommentOnly(stmt string) bool {
	for _, line := range strings.Split(stmt, "\n") {
		t := strings.TrimSpace(line)
		if t != "" && !strings.HasPrefix(t, "--") {
			return false
		}
	}
	return true
}
