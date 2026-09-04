// Package database 封装 SQLite 访问：单连接 + WAL + 建表/迁移。
package database

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"log/slog"
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

// Open 打开（必要时创建）数据库并执行迁移。
func Open(path string) (*DB, error) {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("创建数据目录失败: %w", err)
		}
	}
	db := sql.OpenDB(&pragmaConnector{dsn: "file:" + path})
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)
	db.SetConnMaxIdleTime(0)

	d := &DB{DB: db, path: path}
	if _, err := d.Exec("PRAGMA journal_mode=WAL"); err != nil {
		slog.Debug("WAL 不可用, 使用默认日志模式", "err", err)
	}
	if err := d.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return d, nil
}

// Path 返回数据库文件路径。
func (d *DB) Path() string { return d.path }

func (d *DB) migrate() error {
	tx, err := d.Begin()
	if err != nil {
		return fmt.Errorf("开启迁移事务失败: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	for _, stmt := range splitStatements(Schema) {
		if _, err := tx.Exec(stmt); err != nil {
			return fmt.Errorf("建表失败: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return d.migrateRuleColumns()
}

// migrateRuleColumns 为老库补齐 rules 表新增列。
//
// 老库特征：存在 listen_address（NOT NULL，无默认值时插入会失败）。
// 处理方式见 legacyListenAddrDefault：给它补一个默认值语义，
// 由 forward.Store 的 INSERT 显式写入 ” 占位，从此不再参与任何业务判断。
func (d *DB) migrateRuleColumns() error {
	have, err := d.ruleColumns()
	if err != nil {
		return err
	}
	for _, c := range addColumns {
		if have[c.col] {
			continue
		}
		if _, err := d.Exec(c.ddl); err != nil {
			return fmt.Errorf("升级 rules 表失败(%s): %w", c.col, err)
		}
		slog.Info("数据库已升级", "column", c.col)
	}
	return nil
}

// ruleColumns 返回 rules 表现有列集合。
func (d *DB) ruleColumns() (map[string]bool, error) {
	rows, err := d.Query("PRAGMA table_info(rules)")
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

// HasLegacyListenAddress 报告本库是否仍带历史 listen_address 列。
// 供 forward.Store 决定 INSERT 是否需要为其写入占位值，以及 selftest 展示。
func (d *DB) HasLegacyListenAddress() bool {
	cols, err := d.ruleColumns()
	if err != nil {
		return false
	}
	return cols["listen_address"]
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
