package api

import (
	"context"
	"database/sql"
)

// queryDailyAll 返回最近 days 天所有规则汇总的每日流量（日期倒序）。
func queryDailyAll(ctx context.Context, db *sql.DB, days int) (*queryRows, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT day, SUM(upload_bytes), SUM(download_bytes) FROM traffic_daily
		 GROUP BY day ORDER BY day DESC LIMIT ?`, days)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := &queryRows{Rows: []DailyRow{}}
	for rows.Next() {
		var d DailyRow
		var up, down sql.NullInt64
		if err := rows.Scan(&d.Day, &up, &down); err != nil {
			return nil, err
		}
		d.Up = up.Int64
		d.Down = down.Int64
		out.Rows = append(out.Rows, d)
	}
	return out, rows.Err()
}

// queryDaily 返回某条规则最近 days 天的每日流量（日期倒序）。
// 软删除规则的历史也保留可查。
func queryDaily(ctx context.Context, db *sql.DB, ruleID int64, days int) (*queryRows, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT day, upload_bytes, download_bytes FROM traffic_daily
		 WHERE rule_id=? ORDER BY day DESC LIMIT ?`, ruleID, days)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := &queryRows{Rows: []DailyRow{}}
	for rows.Next() {
		var d DailyRow
		var up, down sql.NullInt64
		if err := rows.Scan(&d.Day, &up, &down); err != nil {
			return nil, err
		}
		d.Up = up.Int64
		d.Down = down.Int64
		out.Rows = append(out.Rows, d)
	}
	return out, rows.Err()
}
