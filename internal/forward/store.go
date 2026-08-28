package forward

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// Store 是规则在 SQLite 上的持久层。
type Store struct{ db *sql.DB }

// NewStore 构造规则存储。
func NewStore(db *sql.DB) *Store { return &Store{db: db} }

const ruleCols = `id,name,enabled,protocol,listen_address,listen_port,
	target_address,target_port,created_at,updated_at,deleted,deleted_at,
	quota_enabled,quota_limit_bytes,quota_reset_baseline,ip_limit_enabled,ip_limit_max`

func scanRule(s interface{ Scan(...any) error }, r *Rule) error {
	var enabled, deleted int
	var quotaEnabled, ipLimitEnabled int
	err := s.Scan(&r.ID, &r.Name, &enabled, &r.Protocol, &r.ListenAddress, &r.ListenPort,
		&r.TargetAddress, &r.TargetPort, &r.CreatedAt, &r.UpdatedAt, &deleted, &r.DeletedAt,
		&quotaEnabled, &r.QuotaLimitBytes, &r.QuotaResetBaseline, &ipLimitEnabled, &r.IPLimitMax)
	if err != nil {
		return err
	}
	r.Enabled = enabled != 0
	r.Deleted = deleted != 0
	r.QuotaEnabled = quotaEnabled != 0
	r.IPLimitEnabled = ipLimitEnabled != 0
	return nil
}

// Create 插入新规则，返回生成的稳定自增 ID（AUTOINCREMENT 不复用）。
func (st *Store) Create(ctx context.Context, r *Rule) (int64, error) {
	now := time.Now().Unix()
	r.CreatedAt = now
	r.UpdatedAt = now
	res, err := st.db.ExecContext(ctx,
		`INSERT INTO rules(name,enabled,protocol,listen_address,listen_port,
			target_address,target_port,created_at,updated_at,deleted,deleted_at,
			quota_enabled,quota_limit_bytes,quota_reset_baseline,ip_limit_enabled,ip_limit_max)
			VALUES(?,?,?,?,?,?,?,?,?,0,0,?,?,?,?,?)`,
		r.Name, b2i(r.Enabled), r.Protocol, r.ListenAddress, r.ListenPort,
		r.TargetAddress, r.TargetPort, r.CreatedAt, r.UpdatedAt,
		b2i(r.QuotaEnabled), r.QuotaLimitBytes, r.QuotaResetBaseline,
		b2i(r.IPLimitEnabled), r.IPLimitMax)
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	r.ID = id
	return id, nil
}

// Update 更新规则字段（不含软删除）。
func (st *Store) Update(ctx context.Context, r *Rule) error {
	r.UpdatedAt = time.Now().Unix()
	res, err := st.db.ExecContext(ctx,
		`UPDATE rules SET name=?,enabled=?,protocol=?,listen_address=?,listen_port=?,
			target_address=?,target_port=?,updated_at=?,
			quota_enabled=?,quota_limit_bytes=?,quota_reset_baseline=?,
			ip_limit_enabled=?,ip_limit_max=? WHERE id=? AND deleted=0`,
		r.Name, b2i(r.Enabled), r.Protocol, r.ListenAddress, r.ListenPort,
		r.TargetAddress, r.TargetPort, r.UpdatedAt,
		b2i(r.QuotaEnabled), r.QuotaLimitBytes, r.QuotaResetBaseline,
		b2i(r.IPLimitEnabled), r.IPLimitMax, r.ID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("规则 %d 不存在或已删除", r.ID)
	}
	return nil
}

// SoftDelete 软删除：标记 deleted，保留历史。
func (st *Store) SoftDelete(ctx context.Context, id int64) error {
	now := time.Now().Unix()
	res, err := st.db.ExecContext(ctx,
		`UPDATE rules SET deleted=1,deleted_at=? WHERE id=? AND deleted=0`, now, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("规则 %d 不存在或已删除", id)
	}
	return nil
}

// Get 按 ID 读取（不含已删除）。
func (st *Store) Get(ctx context.Context, id int64) (*Rule, error) {
	var r Rule
	err := st.db.QueryRowContext(ctx,
		`SELECT `+ruleCols+` FROM rules WHERE id=? AND deleted=0`, id).Scan(
		&r.ID, &r.Name, &r.Enabled, &r.Protocol, &r.ListenAddress, &r.ListenPort,
		&r.TargetAddress, &r.TargetPort, &r.CreatedAt, &r.UpdatedAt, &r.Deleted, &r.DeletedAt,
		&r.QuotaEnabled, &r.QuotaLimitBytes, &r.QuotaResetBaseline, &r.IPLimitEnabled, &r.IPLimitMax)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("规则 %d 不存在", id)
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// ListActive 返回所有未删除规则（含已停用）。
func (st *Store) ListActive(ctx context.Context) ([]*Rule, error) {
	rows, err := st.db.QueryContext(ctx,
		`SELECT `+ruleCols+` FROM rules WHERE deleted=0 ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Rule
	for rows.Next() {
		var r Rule
		if err := scanRule(rows, &r); err != nil {
			return nil, err
		}
		out = append(out, &r)
	}
	return out, rows.Err()
}

// ListEnabled 返回所有启用且未删除的规则。
func (st *Store) ListEnabled(ctx context.Context) ([]*Rule, error) {
	all, err := st.ListActive(ctx)
	if err != nil {
		return nil, err
	}
	var out []*Rule
	for _, r := range all {
		if r.Enabled {
			out = append(out, r)
		}
	}
	return out, nil
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}
