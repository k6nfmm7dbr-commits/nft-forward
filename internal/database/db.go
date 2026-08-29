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

// Schema 是建表脚本。
// 方向定义（与 SBX 习惯一致）：
//   - upload / rx  = 客户端 → 转发服务器 → 目标
//   - download / tx = 目标 → 转发服务器 → 客户端
//
// rules.deleted 是软删除标记：删除转发规则时不物理删除，保留历史流量可审计。
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
    listen_address       TEXT    NOT NULL DEFAULT '0.0.0.0',
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
    ip_limit_max         INTEGER NOT NULL DEFAULT 0
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
	return tx.Commit()
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
