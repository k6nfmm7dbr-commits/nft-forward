package forward

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// Store 是规则在 SQLite 上的持久层。
//
// 关于历史 listen_address 列：老库里它是 `TEXT NOT NULL DEFAULT '0.0.0.0'`，
// 因此这里的 INSERT 不写该列也能成功（由默认值填充）。新代码从不读取它，
// 也不据它做任何判断 —— 转发规则已彻底没有「监听地址」概念。
type Store struct{ db *sql.DB }

// NewStore 构造规则存储。
func NewStore(db *sql.DB) *Store { return &Store{db: db} }

const ruleCols = `id,name,enabled,protocol,listen_port,
	target_address,target_port,created_at,updated_at,deleted,deleted_at,
	quota_enabled,quota_limit_bytes,quota_reset_baseline,ip_limit_enabled,ip_limit_max,
	resolved_ipv4,resolved_ipv6,resolved_at,resolve_status,resolve_error`

func scanRule(s interface{ Scan(...any) error }, r *Rule) error {
	var enabled, deleted, quotaEnabled, ipLimitEnabled int
	err := s.Scan(&r.ID, &r.Name, &enabled, &r.Protocol, &r.ListenPort,
		&r.TargetAddress, &r.TargetPort, &r.CreatedAt, &r.UpdatedAt, &deleted, &r.DeletedAt,
		&quotaEnabled, &r.QuotaLimitBytes, &r.QuotaResetBaseline, &ipLimitEnabled, &r.IPLimitMax,
		&r.ResolvedV4, &r.ResolvedV6, &r.ResolvedAt, &r.ResolveStatus, &r.ResolveError)
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
	return st.CreateTx(ctx, nil, r)
}

// execer 是 *sql.DB 与 *sql.Tx 的公共接口，便于同一份 SQL 在事务内外复用。
type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

func (st *Store) target(tx *sql.Tx) execer {
	if tx != nil {
		return tx
	}
	return st.db
}

// CreateTx 在给定事务（可为 nil）内插入新规则。
func (st *Store) CreateTx(ctx context.Context, tx *sql.Tx, r *Rule) (int64, error) {
	now := time.Now().Unix()
	r.CreatedAt = now
	r.UpdatedAt = now
	// NULL lets SQLite allocate the ID for non-runtime callers. Runtime
	// callers reserve an ID first so a rolled-back candidate's mark is never reused.
	var idArg any
	if r.ID != 0 {
		idArg = r.ID
	}
	res, err := st.target(tx).ExecContext(ctx,
		`INSERT INTO rules(id,name,enabled,protocol,listen_port,
            target_address,target_port,created_at,updated_at,deleted,deleted_at,
            quota_enabled,quota_limit_bytes,quota_reset_baseline,ip_limit_enabled,ip_limit_max,
            resolved_ipv4,resolved_ipv6,resolved_at,resolve_status,resolve_error)
            VALUES(?,?,?,?,?,?,?,?,?,0,0,?,?,?,?,?,?,?,?,?,?)`,
		idArg, r.Name, b2i(r.Enabled), r.Protocol, r.ListenPort,
		r.TargetAddress, r.TargetPort, r.CreatedAt, r.UpdatedAt,
		b2i(r.QuotaEnabled), r.QuotaLimitBytes, r.QuotaResetBaseline,
		b2i(r.IPLimitEnabled), r.IPLimitMax,
		r.ResolvedV4, r.ResolvedV6, r.ResolvedAt, r.ResolveStatus, r.ResolveError)

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
	return st.UpdateTx(ctx, nil, r)
}

// UpdateTx 在给定事务（可为 nil）内更新规则。
func (st *Store) UpdateTx(ctx context.Context, tx *sql.Tx, r *Rule) error {
	r.UpdatedAt = time.Now().Unix()
	res, err := st.target(tx).ExecContext(ctx,
		`UPDATE rules SET name=?,enabled=?,protocol=?,listen_port=?,
			target_address=?,target_port=?,updated_at=?,
			quota_enabled=?,quota_limit_bytes=?,quota_reset_baseline=?,
			ip_limit_enabled=?,ip_limit_max=?,
			resolved_ipv4=?,resolved_ipv6=?,resolved_at=?,resolve_status=?,resolve_error=?
			WHERE id=? AND deleted=0`,
		r.Name, b2i(r.Enabled), r.Protocol, r.ListenPort,
		r.TargetAddress, r.TargetPort, r.UpdatedAt,
		b2i(r.QuotaEnabled), r.QuotaLimitBytes, r.QuotaResetBaseline,
		b2i(r.IPLimitEnabled), r.IPLimitMax,
		r.ResolvedV4, r.ResolvedV6, r.ResolvedAt, r.ResolveStatus, r.ResolveError, r.ID)
	if err != nil {
		return err
	}
	return requireAffected(res, r.ID)
}

// ReserveID consumes an AUTOINCREMENT ID before it can be exposed to nft
// (and potentially to conntrack). A crash or rollback may leave a harmless gap.
func (st *Store) ReserveID(ctx context.Context) (int64, error) {
	tx, err := st.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT INTO sqlite_sequence(name,seq)
        SELECT 'rules',0 WHERE NOT EXISTS (SELECT 1 FROM sqlite_sequence WHERE name='rules')`); err != nil {
		return 0, err
	}
	var id int64
	if err := tx.QueryRowContext(ctx, `UPDATE sqlite_sequence SET seq=max(seq,coalesce((SELECT max(id) FROM rules),0))+1
        WHERE name='rules' AND seq < 4294967295 RETURNING seq`).Scan(&id); err != nil {
		return 0, err
	}
	if id <= 0 || id > 4294967295 {
		return 0, fmt.Errorf("规则 ID 超出 nft mark 范围: %d", id)
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return id, nil
}

// Mutation is the uncommitted rule state plus the read view needed by policy.
// SQLTx returns the same connection: policy must not wait on the single DB
// connection held by this transaction while it reads quota totals.
type Mutation interface {
	Create(*Rule) error
	Update(*Rule) error
	SoftDelete(int64) error
	UpdateResolved(ResolvedUpdate) error
	SQLTx() *sql.Tx
}

type mutation struct {
	ctx   context.Context
	store *Store
	tx    *sql.Tx
}

func (m mutation) Create(r *Rule) error      { _, err := m.store.CreateTx(m.ctx, m.tx, r); return err }
func (m mutation) Update(r *Rule) error      { return m.store.UpdateTx(m.ctx, m.tx, r) }
func (m mutation) SoftDelete(id int64) error { return m.store.SoftDeleteTx(m.ctx, m.tx, id) }
func (m mutation) UpdateResolved(u ResolvedUpdate) error {
	return m.store.updateResolved(m.ctx, m.tx, u)
}
func (m mutation) SQLTx() *sql.Tx { return m.tx }

// ErrCommitFailed marks a commit error after the callback ran. Its outcome
// must be checked from the authoritative, committed rule state.
type ErrCommitFailed struct{ Err error }

func (e *ErrCommitFailed) Error() string { return "事务提交失败: " + e.Err.Error() }
func (e *ErrCommitFailed) Unwrap() error { return e.Err }

func (st *Store) Transaction(ctx context.Context, edit func(Mutation) error) error {
	tx, err := st.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("开启事务失败: %w", err)
	}
	defer tx.Rollback()
	if err := edit(mutation{ctx: ctx, store: st, tx: tx}); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return &ErrCommitFailed{Err: err}
	}
	return nil
}

// ResolvedUpdate changes only an existing rule's observed DNS state.
type ResolvedUpdate struct {
	ID          int64
	V4, V6      string
	At          int64
	Status, Err string
}

func (st *Store) updateResolved(ctx context.Context, tx *sql.Tx, u ResolvedUpdate) error {
	res, err := st.target(tx).ExecContext(ctx, `UPDATE rules SET resolved_ipv4=?,resolved_ipv6=?,resolved_at=?,resolve_status=?,resolve_error=? WHERE id=? AND deleted=0`,
		u.V4, u.V6, u.At, u.Status, u.Err, u.ID)
	if err != nil {
		return err
	}
	return requireAffected(res, u.ID)
}

func requireAffected(res sql.Result, id int64) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return fmt.Errorf("规则 %d 不存在或已删除", id)
	}
	return nil
}

// SoftDelete 软删除：标记 deleted，保留历史。
func (st *Store) SoftDelete(ctx context.Context, id int64) error {
	return st.SoftDeleteTx(ctx, nil, id)
}

// SoftDeleteTx 在给定事务（可为 nil）内软删除。
func (st *Store) SoftDeleteTx(ctx context.Context, tx *sql.Tx, id int64) error {
	now := time.Now().Unix()
	res, err := st.target(tx).ExecContext(ctx,
		`UPDATE rules SET deleted=1,deleted_at=? WHERE id=? AND deleted=0`, now, id)
	if err != nil {
		return err
	}
	return requireAffected(res, id)
}

// Get 按 ID 读取（不含已删除）。
func (st *Store) Get(ctx context.Context, id int64) (*Rule, error) {
	var r Rule
	row := st.db.QueryRowContext(ctx,
		`SELECT `+ruleCols+` FROM rules WHERE id=? AND deleted=0`, id)
	if err := scanRule(row, &r); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("规则 %d 不存在", id)
		}
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
