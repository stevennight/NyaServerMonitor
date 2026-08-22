package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"nyaservermonitor/internal/shared/model"
)

var (
	ErrNodeNotFound = errors.New("node not found")
	ErrNodeRevoked  = errors.New("node revoked")
)

type User struct {
	ID           int64
	Username     string
	PasswordHash string
	TOTPSecret   string
	TOTPEnabled  bool
	CreatedAt    time.Time
}

type NodeCredential struct {
	Node      model.Node
	TokenHash string
	Revoked   bool
}

type Store struct {
	db *sql.DB
}

func Open(ctx context.Context, path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	s := &Store{db: db}
	if _, err := db.ExecContext(ctx, `PRAGMA busy_timeout = 5000; PRAGMA foreign_keys = ON;`); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := s.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate(ctx context.Context) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL,
			totp_secret TEXT NOT NULL DEFAULT '',
			totp_enabled INTEGER NOT NULL DEFAULT 0,
			created_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS settings (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS nodes (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			group_name TEXT NOT NULL DEFAULT '',
			tags_json TEXT NOT NULL DEFAULT '[]',
			token_hash TEXT NOT NULL,
			status TEXT NOT NULL,
			revoked INTEGER NOT NULL DEFAULT 0,
			agent_version TEXT NOT NULL DEFAULT '',
			last_ip TEXT NOT NULL DEFAULT '',
			last_seen TEXT NOT NULL DEFAULT '',
			first_seen TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			sequence INTEGER NOT NULL DEFAULT 0,
			system_json TEXT NOT NULL DEFAULT '{}',
			last_report_json TEXT NOT NULL DEFAULT '{}'
		);`,
		`CREATE TABLE IF NOT EXISTS metric_samples (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			node_id TEXT NOT NULL,
			observed_at TEXT NOT NULL,
			sequence INTEGER NOT NULL DEFAULT 0,
			snapshot_json TEXT NOT NULL,
			checks_json TEXT NOT NULL DEFAULT '[]'
		);`,
		`CREATE TABLE IF NOT EXISTS audit (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			actor TEXT NOT NULL,
			action TEXT NOT NULL,
			target TEXT NOT NULL,
			detail_json TEXT NOT NULL DEFAULT '{}',
			created_at TEXT NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS idx_nodes_status ON nodes(status);`,
		`CREATE INDEX IF NOT EXISTS idx_metric_node_time ON metric_samples(node_id, observed_at DESC);`,
		`CREATE INDEX IF NOT EXISTS idx_audit_time ON audit(created_at DESC);`,
	}
	for _, statement := range statements {
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) UserCount(ctx context.Context) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&count)
	return count, err
}

func (s *Store) CreateUser(ctx context.Context, username, passwordHash string) (User, error) {
	now := time.Now().UTC()
	result, err := s.db.ExecContext(ctx,
		`INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)`,
		username, passwordHash, now.Format(time.RFC3339Nano))
	if err != nil {
		return User{}, err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return User{}, err
	}
	return User{ID: id, Username: username, PasswordHash: passwordHash, CreatedAt: now}, nil
}

func (s *Store) FindUserByUsername(ctx context.Context, username string) (User, error) {
	var user User
	var enabled int
	var created string
	err := s.db.QueryRowContext(ctx,
		`SELECT id, username, password_hash, totp_secret, totp_enabled, created_at FROM users WHERE username = ?`, username,
	).Scan(&user.ID, &user.Username, &user.PasswordHash, &user.TOTPSecret, &enabled, &created)
	if err != nil {
		return User{}, err
	}
	user.TOTPEnabled = enabled == 1
	user.CreatedAt = parseTime(created)
	return user, nil
}

func (s *Store) SetTOTP(ctx context.Context, userID int64, secret string, enabled bool) error {
	_, err := s.db.ExecContext(ctx, `UPDATE users SET totp_secret = ?, totp_enabled = ? WHERE id = ?`, secret, boolInt(enabled), userID)
	return err
}

func (s *Store) GetSetting(ctx context.Context, key string) (string, bool, error) {
	var value string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	return value, err == nil, err
}

func (s *Store) SetSetting(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

func (s *Store) CreateNode(ctx context.Context, node model.Node, tokenHash string) error {
	now := time.Now().UTC()
	if node.CreatedAt.IsZero() {
		node.CreatedAt = now
	}
	if node.Status == "" {
		node.Status = model.NodePending
	}
	tags, err := json.Marshal(node.Tags)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO nodes (id, name, group_name, tags_json, token_hash, status, revoked, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?)`,
		node.ID, node.Name, node.Group, string(tags), tokenHash, node.Status,
		node.CreatedAt.UTC().Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
	return err
}

func (s *Store) GetNode(ctx context.Context, id string) (model.Node, error) {
	record, err := s.nodeRecord(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Node{}, ErrNodeNotFound
	}
	if err != nil {
		return model.Node{}, err
	}
	return record.Node, nil
}

func (s *Store) GetNodeCredential(ctx context.Context, id string) (NodeCredential, error) {
	record, err := s.nodeRecord(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return NodeCredential{}, ErrNodeNotFound
	}
	if err != nil {
		return NodeCredential{}, err
	}
	return NodeCredential{Node: record.Node, TokenHash: record.TokenHash, Revoked: record.Revoked}, nil
}

func (s *Store) ListNodes(ctx context.Context) ([]model.Node, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, group_name, tags_json, token_hash, status, revoked, agent_version, last_ip,
		       last_seen, first_seen, created_at, updated_at, sequence, system_json, last_report_json
		FROM nodes ORDER BY name COLLATE NOCASE, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var nodes []model.Node
	for rows.Next() {
		record, err := scanNodeRecord(rows)
		if err != nil {
			return nil, err
		}
		nodes = append(nodes, record.Node)
	}
	return nodes, rows.Err()
}

func (s *Store) UpdateReport(ctx context.Context, report model.Report, remoteIP string) error {
	reportJSON, err := json.Marshal(report)
	if err != nil {
		return err
	}
	systemJSON, err := json.Marshal(report.System)
	if err != nil {
		return err
	}
	snapshotJSON, err := json.Marshal(report.Metrics)
	if err != nil {
		return err
	}
	checksJSON, err := json.Marshal(report.Checks)
	if err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer rollback(tx)
	result, err := tx.ExecContext(ctx, `
		UPDATE nodes SET status = ?, agent_version = ?, last_ip = ?, last_seen = ?,
		first_seen = CASE WHEN first_seen = '' THEN ? ELSE first_seen END,
		updated_at = ?, sequence = ?, system_json = ?, last_report_json = ?
		WHERE id = ? AND revoked = 0`,
		model.NodeOnline, report.AgentVersion, remoteIP, now, now, now, report.Sequence,
		string(systemJSON), string(reportJSON), report.NodeID)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return s.nodeUpdateError(ctx, tx, report.NodeID)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO metric_samples (node_id, observed_at, sequence, snapshot_json, checks_json)
		VALUES (?, ?, ?, ?, ?)`, report.NodeID, now, report.Sequence, string(snapshotJSON), string(checksJSON)); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) nodeUpdateError(ctx context.Context, tx *sql.Tx, id string) error {
	var revoked int
	err := tx.QueryRowContext(ctx, `SELECT revoked FROM nodes WHERE id = ?`, id).Scan(&revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNodeNotFound
	}
	if err != nil {
		return err
	}
	if revoked == 1 {
		return ErrNodeRevoked
	}
	return ErrNodeNotFound
}

func (s *Store) SetNodeTokenHash(ctx context.Context, id, tokenHash string) error {
	result, err := s.db.ExecContext(ctx, `UPDATE nodes SET token_hash = ?, updated_at = ? WHERE id = ?`, tokenHash, time.Now().UTC().Format(time.RFC3339Nano), id)
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count == 0 {
		return ErrNodeNotFound
	}
	return nil
}

func (s *Store) SetNodeRevoked(ctx context.Context, id string, revoked bool) error {
	status := model.NodePending
	if revoked {
		status = model.NodeRevoked
	}
	result, err := s.db.ExecContext(ctx, `UPDATE nodes SET revoked = ?, status = ?, updated_at = ? WHERE id = ?`, boolInt(revoked), status, time.Now().UTC().Format(time.RFC3339Nano), id)
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count == 0 {
		return ErrNodeNotFound
	}
	return nil
}

func (s *Store) MarkOffline(ctx context.Context, before time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE nodes SET status = ?, updated_at = ? WHERE revoked = 0 AND status = ? AND last_seen <> '' AND last_seen < ?`,
		model.NodeOffline, time.Now().UTC().Format(time.RFC3339Nano), model.NodeOnline, before.UTC().Format(time.RFC3339Nano))
	return err
}

func (s *Store) ListMetrics(ctx context.Context, nodeID string, since time.Time, limit int) ([]model.MetricSample, error) {
	if limit < 1 {
		limit = 1
	}
	if limit > 2000 {
		limit = 2000
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT observed_at, sequence, snapshot_json, checks_json
		FROM metric_samples WHERE node_id = ? AND observed_at >= ?
		ORDER BY observed_at ASC LIMIT ?`, nodeID, since.UTC().Format(time.RFC3339Nano), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var samples []model.MetricSample
	for rows.Next() {
		var observed, snapshotJSON, checksJSON string
		var sequence uint64
		if err := rows.Scan(&observed, &sequence, &snapshotJSON, &checksJSON); err != nil {
			return nil, err
		}
		var snapshot model.MetricsSnapshot
		var checks []model.ServiceCheck
		if err := json.Unmarshal([]byte(snapshotJSON), &snapshot); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(checksJSON), &checks); err != nil {
			return nil, err
		}
		samples = append(samples, model.MetricSample{ObservedAt: parseTime(observed), Sequence: sequence, Metrics: snapshot, Checks: checks})
	}
	return samples, rows.Err()
}

func (s *Store) AddAudit(ctx context.Context, actor, action, target string, detail map[string]any) error {
	if len(actor) > 128 || len(action) > 128 || len(target) > 256 {
		return fmt.Errorf("audit field too long")
	}
	if detail == nil {
		detail = map[string]any{}
	}
	detailJSON, err := json.Marshal(detail)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO audit (actor, action, target, detail_json, created_at) VALUES (?, ?, ?, ?, ?)`,
		actor, action, target, string(detailJSON), time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

func (s *Store) ListAudit(ctx context.Context, limit int) ([]model.AuditEvent, error) {
	if limit < 1 {
		limit = 1
	}
	if limit > 500 {
		limit = 500
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, actor, action, target, detail_json, created_at FROM audit ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var events []model.AuditEvent
	for rows.Next() {
		var event model.AuditEvent
		var detailJSON, created string
		if err := rows.Scan(&event.ID, &event.Actor, &event.Action, &event.Target, &detailJSON, &created); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(detailJSON), &event.Detail)
		event.CreatedAt = parseTime(created)
		events = append(events, event)
	}
	return events, rows.Err()
}

func (s *Store) PruneMetrics(ctx context.Context, before time.Time) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM metric_samples WHERE observed_at < ?`, before.UTC().Format(time.RFC3339Nano))
	return err
}

type nodeRecord struct {
	Node      model.Node
	TokenHash string
	Revoked   bool
}

type scanner interface{ Scan(dest ...any) error }

func (s *Store) nodeRecord(ctx context.Context, id string) (nodeRecord, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, name, group_name, tags_json, token_hash, status, revoked, agent_version, last_ip,
		       last_seen, first_seen, created_at, updated_at, sequence, system_json, last_report_json
		FROM nodes WHERE id = ?`, id)
	return scanNodeRecord(row)
}

func scanNodeRecord(row scanner) (nodeRecord, error) {
	var record nodeRecord
	var tagsJSON, status string
	var revoked int
	var lastSeen, firstSeen, created, updated, systemJSON, reportJSON string
	if err := row.Scan(&record.Node.ID, &record.Node.Name, &record.Node.Group, &tagsJSON, &record.TokenHash,
		&status, &revoked, &record.Node.AgentVersion, &record.Node.LastIP, &lastSeen, &firstSeen,
		&created, &updated, &record.Node.Sequence, &systemJSON, &reportJSON); err != nil {
		return nodeRecord{}, err
	}
	record.Node.Status = model.NodeStatus(status)
	record.Revoked = revoked == 1
	_ = json.Unmarshal([]byte(tagsJSON), &record.Node.Tags)
	_ = json.Unmarshal([]byte(systemJSON), &record.Node.System)
	var report model.Report
	if json.Unmarshal([]byte(reportJSON), &report) == nil {
		record.Node.Metrics = report.Metrics
		record.Node.Checks = report.Checks
	}
	record.Node.LastSeen = parseTime(lastSeen)
	record.Node.FirstSeen = parseTime(firstSeen)
	record.Node.CreatedAt = parseTime(created)
	record.Node.UpdatedAt = parseTime(updated)
	return record, nil
}

func parseTime(value string) time.Time {
	if strings.TrimSpace(value) == "" {
		return time.Time{}
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}
	}
	return parsed
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func rollback(tx *sql.Tx) {
	_ = tx.Rollback()
}
