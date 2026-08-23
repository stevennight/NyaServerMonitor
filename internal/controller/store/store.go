package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"nyaservermonitor/internal/shared/model"
	sharedversion "nyaservermonitor/internal/shared/version"
)

var (
	ErrNodeNotFound                = errors.New("node not found")
	ErrNodeRevoked                 = errors.New("node revoked")
	ErrAlertRuleNotFound           = errors.New("alert rule not found")
	ErrNotificationChannelNotFound = errors.New("notification channel not found")
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
	Node            model.Node
	TokenHash       string
	TokenCiphertext string
	Revoked         bool
}

type NotificationChannelRecord struct {
	Channel          model.NotificationChannel
	TargetCiphertext string
	SecretCiphertext string
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
			token_ciphertext TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL,
			revoked INTEGER NOT NULL DEFAULT 0,
			agent_version TEXT NOT NULL DEFAULT '',
			last_ip TEXT NOT NULL DEFAULT '',
			ip_override TEXT NOT NULL DEFAULT '',
			country TEXT NOT NULL DEFAULT '',
			country_code TEXT NOT NULL DEFAULT '',
			country_lookup_ip TEXT NOT NULL DEFAULT '',
			country_override TEXT NOT NULL DEFAULT '',
			last_seen TEXT NOT NULL DEFAULT '',
			first_seen TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			sequence INTEGER NOT NULL DEFAULT 0,
			system_json TEXT NOT NULL DEFAULT '{}',
			last_report_json TEXT NOT NULL DEFAULT '{}',
			desired_version TEXT NOT NULL DEFAULT '',
			update_status TEXT NOT NULL DEFAULT '',
			update_error TEXT NOT NULL DEFAULT '',
			update_requested_at TEXT NOT NULL DEFAULT '',
			update_finished_at TEXT NOT NULL DEFAULT ''
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
		`CREATE TABLE IF NOT EXISTS alert_rules (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			type TEXT NOT NULL,
			enabled INTEGER NOT NULL DEFAULT 1,
			threshold REAL NOT NULL DEFAULT 0,
			duration_seconds INTEGER NOT NULL DEFAULT 0,
			cooldown_seconds INTEGER NOT NULL DEFAULT 300,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS notification_channels (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			type TEXT NOT NULL,
			enabled INTEGER NOT NULL DEFAULT 1,
			target_ciphertext TEXT NOT NULL,
			secret_ciphertext TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS alert_rule_channels (
			rule_id TEXT NOT NULL,
			channel_id TEXT NOT NULL,
			PRIMARY KEY (rule_id, channel_id),
			FOREIGN KEY (rule_id) REFERENCES alert_rules(id) ON DELETE CASCADE,
			FOREIGN KEY (channel_id) REFERENCES notification_channels(id) ON DELETE CASCADE
		);`,
		`CREATE TABLE IF NOT EXISTS alert_states (
			rule_id TEXT NOT NULL,
			node_id TEXT NOT NULL,
			status TEXT NOT NULL,
			value REAL NOT NULL DEFAULT 0,
			message TEXT NOT NULL DEFAULT '',
			fingerprint TEXT NOT NULL DEFAULT '',
			first_triggered_at TEXT NOT NULL DEFAULT '',
			last_evaluated_at TEXT NOT NULL,
			last_notified_at TEXT NOT NULL DEFAULT '',
			PRIMARY KEY (rule_id, node_id),
			FOREIGN KEY (rule_id) REFERENCES alert_rules(id) ON DELETE CASCADE,
			FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE
		);`,
		`CREATE TABLE IF NOT EXISTS alert_events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			rule_id TEXT NOT NULL,
			node_id TEXT NOT NULL,
			kind TEXT NOT NULL,
			value REAL NOT NULL DEFAULT 0,
			message TEXT NOT NULL,
			notified INTEGER NOT NULL DEFAULT 0,
			created_at TEXT NOT NULL,
			FOREIGN KEY (rule_id) REFERENCES alert_rules(id) ON DELETE CASCADE,
			FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE
		);`,
		`CREATE INDEX IF NOT EXISTS idx_nodes_status ON nodes(status);`,
		`CREATE INDEX IF NOT EXISTS idx_metric_node_time ON metric_samples(node_id, observed_at DESC);`,
		`CREATE INDEX IF NOT EXISTS idx_audit_time ON audit(created_at DESC);`,
		`CREATE INDEX IF NOT EXISTS idx_alert_events_time ON alert_events(created_at DESC);`,
		`CREATE INDEX IF NOT EXISTS idx_alert_states_status ON alert_states(status);`,
	}
	for _, statement := range statements {
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	if err := s.ensureNodeColumns(ctx); err != nil {
		return err
	}
	if err := s.seedAlertRules(ctx); err != nil {
		return err
	}
	return nil
}

func (s *Store) ensureNodeColumns(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `PRAGMA table_info(nodes)`)
	if err != nil {
		return err
	}
	defer rows.Close()
	columns := make(map[string]struct{})
	for rows.Next() {
		var cid int
		var name, columnType string
		var notNull, primaryKey int
		var defaultValue any
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			return err
		}
		columns[name] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for name, definition := range map[string]string{
		"token_ciphertext":    "TEXT NOT NULL DEFAULT ''",
		"ip_override":         "TEXT NOT NULL DEFAULT ''",
		"country":             "TEXT NOT NULL DEFAULT ''",
		"country_code":        "TEXT NOT NULL DEFAULT ''",
		"country_lookup_ip":   "TEXT NOT NULL DEFAULT ''",
		"country_override":    "TEXT NOT NULL DEFAULT ''",
		"desired_version":     "TEXT NOT NULL DEFAULT ''",
		"update_status":       "TEXT NOT NULL DEFAULT ''",
		"update_error":        "TEXT NOT NULL DEFAULT ''",
		"update_requested_at": "TEXT NOT NULL DEFAULT ''",
		"update_finished_at":  "TEXT NOT NULL DEFAULT ''",
	} {
		if _, ok := columns[name]; ok {
			continue
		}
		if _, err := s.db.ExecContext(ctx, `ALTER TABLE nodes ADD COLUMN `+name+` `+definition); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) seedAlertRules(ctx context.Context) error {
	defaults := []struct {
		id, name, kind string
		threshold      float64
		duration       int
		cooldown       int
	}{
		{"default-node-offline", "节点离线", model.AlertNodeOffline, 0, 0, 300},
		{"default-service-down", "服务检查失败", model.AlertServiceDown, 0, 0, 300},
		{"default-cpu-high", "CPU 持续过高", model.AlertCPUHigh, 90, 300, 900},
		{"default-memory-high", "内存持续过高", model.AlertMemoryHigh, 90, 300, 900},
		{"default-disk-high", "磁盘持续过高", model.AlertDiskHigh, 90, 300, 1800},
		{"default-latency-high", "检查延迟过高", model.AlertLatencyHigh, 500, 180, 900},
		{"default-packet-loss-high", "Ping 丢包率过高", model.AlertPacketLossHigh, 20, 0, 900},
		{"default-tls-expiring", "TLS 证书即将过期", model.AlertTLSExpiring, 14 * 24 * 60 * 60, 0, 3600},
		{"default-tls-changed", "TLS 证书发生变化", model.AlertTLSChanged, 0, 0, 3600},
		{"default-tls-invalid", "TLS 证书校验失败", model.AlertTLSInvalid, 0, 0, 900},
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for _, rule := range defaults {
		if _, err := s.db.ExecContext(ctx, `
			INSERT INTO alert_rules (id, name, type, enabled, threshold, duration_seconds, cooldown_seconds, created_at, updated_at)
			VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?)
			ON CONFLICT(id) DO NOTHING`, rule.id, rule.name, rule.kind, rule.threshold, rule.duration, rule.cooldown, now, now); err != nil {
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

func (s *Store) CreateNode(ctx context.Context, node model.Node, tokenHash string, tokenCiphertext ...string) error {
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
	ciphertext := ""
	if len(tokenCiphertext) > 0 {
		ciphertext = tokenCiphertext[0]
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO nodes (id, name, group_name, tags_json, token_hash, token_ciphertext, status, revoked, agent_version,
			last_ip, ip_override, country, country_code, country_lookup_ip, country_override, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, '', ?, '', '', '', ?, ?, ?)`,
		node.ID, node.Name, node.Group, string(tags), tokenHash, ciphertext, node.Status, node.AgentVersion,
		node.IPOverride, node.CountryOverride,
		node.CreatedAt.UTC().Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
	return err
}

func (s *Store) UpdateNodeMetadata(ctx context.Context, id, name, group string, tags []string) (model.Node, error) {
	tagsJSON, err := json.Marshal(tags)
	if err != nil {
		return model.Node{}, err
	}
	result, err := s.db.ExecContext(ctx, `
		UPDATE nodes SET name = ?, group_name = ?, tags_json = ?, updated_at = ?
		WHERE id = ?`, name, group, string(tagsJSON), time.Now().UTC().Format(time.RFC3339Nano), id)
	if err != nil {
		return model.Node{}, err
	}
	if count, _ := result.RowsAffected(); count == 0 {
		return model.Node{}, ErrNodeNotFound
	}
	return s.GetNode(ctx, id)
}

func (s *Store) UpdateNodeMetadataWithOverrides(ctx context.Context, id, name, group string, tags []string, ipOverride, countryOverride string) (model.Node, error) {
	tagsJSON, err := json.Marshal(tags)
	if err != nil {
		return model.Node{}, err
	}
	result, err := s.db.ExecContext(ctx, `
		UPDATE nodes SET name = ?, group_name = ?, tags_json = ?, ip_override = ?, country_override = ?,
		country = CASE WHEN (CASE WHEN ? <> '' THEN ? ELSE last_ip END) <> (CASE WHEN ip_override <> '' THEN ip_override ELSE last_ip END) THEN '' ELSE country END,
		country_code = CASE WHEN (CASE WHEN ? <> '' THEN ? ELSE last_ip END) <> (CASE WHEN ip_override <> '' THEN ip_override ELSE last_ip END) THEN '' ELSE country_code END,
		updated_at = ? WHERE id = ?`,
		name, group, string(tagsJSON), ipOverride, countryOverride,
		ipOverride, ipOverride, ipOverride, ipOverride,
		time.Now().UTC().Format(time.RFC3339Nano), id)
	if err != nil {
		return model.Node{}, err
	}
	if count, _ := result.RowsAffected(); count == 0 {
		return model.Node{}, ErrNodeNotFound
	}
	return s.GetNode(ctx, id)
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
	return NodeCredential{Node: record.Node, TokenHash: record.TokenHash, TokenCiphertext: record.TokenCiphertext, Revoked: record.Revoked}, nil
}

func (s *Store) ListNodes(ctx context.Context) ([]model.Node, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, group_name, tags_json, token_hash, token_ciphertext, status, revoked, agent_version, last_ip,
		       ip_override, country, country_code, country_lookup_ip, country_override,
		       last_seen, first_seen, created_at, updated_at, sequence, system_json, last_report_json,
		       desired_version, update_status, update_error, update_requested_at, update_finished_at
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
		country = CASE WHEN ip_override = '' AND last_ip <> ? THEN '' ELSE country END,
		country_code = CASE WHEN ip_override = '' AND last_ip <> ? THEN '' ELSE country_code END,
		first_seen = CASE WHEN first_seen = '' THEN ? ELSE first_seen END,
		updated_at = ?, sequence = ?, system_json = ?, last_report_json = ?
		WHERE id = ? AND revoked = 0`,
		model.NodeOnline, report.AgentVersion, remoteIP, now, remoteIP, remoteIP, now, now, report.Sequence,
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

func (s *Store) ClaimCountryLookup(ctx context.Context, id, ip string) (bool, error) {
	result, err := s.db.ExecContext(ctx, `
		UPDATE nodes SET country_lookup_ip = ?
		WHERE id = ? AND revoked = 0
		  AND (CASE WHEN ip_override <> '' THEN ip_override ELSE last_ip END) = ?
		  AND country_lookup_ip <> ?`, ip, id, ip, ip)
	if err != nil {
		return false, err
	}
	if count, _ := result.RowsAffected(); count > 0 {
		return true, nil
	}
	var exists int
	if err := s.db.QueryRowContext(ctx, `SELECT 1 FROM nodes WHERE id = ?`, id).Scan(&exists); errors.Is(err, sql.ErrNoRows) {
		return false, ErrNodeNotFound
	} else if err != nil {
		return false, err
	}
	return false, nil
}

func (s *Store) SaveNodeCountry(ctx context.Context, id, ip, country, countryCode string) error {
	result, err := s.db.ExecContext(ctx, `
		UPDATE nodes SET country = ?, country_code = ?, updated_at = ?
		WHERE id = ? AND revoked = 0
		  AND (CASE WHEN ip_override <> '' THEN ip_override ELSE last_ip END) = ?
		  AND country_lookup_ip = ?`,
		country, countryCode, time.Now().UTC().Format(time.RFC3339Nano), id, ip, ip)
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count == 0 {
		return ErrNodeNotFound
	}
	return nil
}

func (s *Store) ResetCountryLookup(ctx context.Context, id string) error {
	result, err := s.db.ExecContext(ctx, `
		UPDATE nodes SET country_lookup_ip = ''
		WHERE id = ? AND country = ''`, id)
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count == 0 {
		return ErrNodeNotFound
	}
	return nil
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

func (s *Store) SetNodeTokenHash(ctx context.Context, id, tokenHash string, tokenCiphertext ...string) error {
	ciphertext := ""
	if len(tokenCiphertext) > 0 {
		ciphertext = tokenCiphertext[0]
	}
	result, err := s.db.ExecContext(ctx, `UPDATE nodes SET token_hash = ?, token_ciphertext = ?, updated_at = ? WHERE id = ?`, tokenHash, ciphertext, time.Now().UTC().Format(time.RFC3339Nano), id)
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count == 0 {
		return ErrNodeNotFound
	}
	return nil
}

func (s *Store) RequestNodeUpdate(ctx context.Context, id, version string) (model.Node, error) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	result, err := s.db.ExecContext(ctx, `
		UPDATE nodes SET desired_version = ?, update_status = ?, update_error = '',
		update_requested_at = ?, update_finished_at = '', updated_at = ?
		WHERE id = ? AND revoked = 0`,
		version, model.NodeUpdateRequested, now, now, id)
	if err != nil {
		return model.Node{}, err
	}
	if count, _ := result.RowsAffected(); count == 0 {
		return model.Node{}, ErrNodeNotFound
	}
	return s.GetNode(ctx, id)
}

func (s *Store) UpdateNodeReport(ctx context.Context, id string, report model.NodeUpdateReport) error {
	now := time.Now().UTC()
	finished := report.CompletedAt
	if finished.IsZero() && (report.Status == model.NodeUpdateSucceeded || report.Status == model.NodeUpdateFailed) {
		finished = now
	}
	result, err := s.db.ExecContext(ctx, `
		UPDATE nodes SET update_status = ?, update_error = ?,
		update_finished_at = CASE WHEN ? <> '' THEN ? ELSE update_finished_at END,
		updated_at = ? WHERE id = ? AND revoked = 0`,
		report.Status, report.Error, formatTime(finished), formatTime(finished), now.Format(time.RFC3339Nano), id)
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count == 0 {
		return ErrNodeNotFound
	}
	return nil
}

func (s *Store) MarkNodeSeen(ctx context.Context, id string, system model.SystemInfo, version string) error {
	now := time.Now().UTC()
	systemJSON, err := json.Marshal(system)
	if err != nil {
		return err
	}
	var desiredVersion string
	if err := s.db.QueryRowContext(ctx, `SELECT desired_version FROM nodes WHERE id = ? AND revoked = 0`, id).Scan(&desiredVersion); errors.Is(err, sql.ErrNoRows) {
		return ErrNodeNotFound
	} else if err != nil {
		return err
	}
	reached := desiredVersion != "" && !sharedversion.NeedsUpdate(version, desiredVersion)
	status := ""
	if reached {
		status = string(model.NodeUpdateSucceeded)
	}
	result, err := s.db.ExecContext(ctx, `
		UPDATE nodes SET status = ?, agent_version = ?, last_seen = ?,
		first_seen = CASE WHEN first_seen = '' THEN ? ELSE first_seen END,
		updated_at = ?, system_json = ?,
		update_status = CASE WHEN ? <> '' THEN ? ELSE update_status END,
		update_error = CASE WHEN ? <> '' THEN '' ELSE update_error END,
		update_finished_at = CASE WHEN ? <> '' THEN ? ELSE update_finished_at END
		WHERE id = ? AND revoked = 0`,
		model.NodeOnline, version, now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano), string(systemJSON),
		status, status, status, status, formatTime(now), id)
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
	now := time.Now().UTC()
	if since.IsZero() || since.After(now) {
		since = now.Add(-24 * time.Hour)
	}
	bucketWidth := now.Sub(since) / time.Duration(limit)
	if bucketWidth < time.Second {
		bucketWidth = time.Second
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT observed_at, sequence, snapshot_json, checks_json
		FROM metric_samples WHERE node_id = ? AND observed_at >= ?
		ORDER BY observed_at ASC`, nodeID, since.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type metricBucket struct {
		sample       model.MetricSample
		count        int
		cpu          float64
		load1        float64
		load5        float64
		load15       float64
		memoryTotal  float64
		memoryUsed   float64
		swapTotal    float64
		swapUsed     float64
		processCount float64
	}
	buckets := make(map[int64]*metricBucket)
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
		observedAt := parseTime(observed)
		if observedAt.IsZero() {
			continue
		}
		bucketID := int64(observedAt.Sub(since) / bucketWidth)
		bucket, exists := buckets[bucketID]
		if !exists {
			bucket = &metricBucket{sample: model.MetricSample{ObservedAt: observedAt, Sequence: sequence, Metrics: snapshot, Checks: checks}}
			buckets[bucketID] = bucket
		}
		bucket.count++
		bucket.cpu += snapshot.CPUPercent
		bucket.load1 += snapshot.Load1
		bucket.load5 += snapshot.Load5
		bucket.load15 += snapshot.Load15
		bucket.memoryTotal += float64(snapshot.MemoryTotalBytes)
		bucket.memoryUsed += float64(snapshot.MemoryUsedBytes)
		bucket.swapTotal += float64(snapshot.SwapTotalBytes)
		bucket.swapUsed += float64(snapshot.SwapUsedBytes)
		bucket.processCount += float64(snapshot.ProcessCount)
		bucket.sample.ObservedAt = observedAt
		bucket.sample.Sequence = sequence
		bucket.sample.Metrics.Disks = snapshot.Disks
		bucket.sample.Metrics.Networks = snapshot.Networks
		bucket.sample.Metrics.UptimeSeconds = snapshot.UptimeSeconds
		bucket.sample.Checks = checks
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	keys := make([]int64, 0, len(buckets))
	for key := range buckets {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(left, right int) bool { return keys[left] < keys[right] })
	samples := make([]model.MetricSample, 0, len(keys))
	for _, key := range keys {
		bucket := buckets[key]
		if bucket.count > 1 {
			count := float64(bucket.count)
			bucket.sample.Metrics.CPUPercent = bucket.cpu / count
			bucket.sample.Metrics.Load1 = bucket.load1 / count
			bucket.sample.Metrics.Load5 = bucket.load5 / count
			bucket.sample.Metrics.Load15 = bucket.load15 / count
			bucket.sample.Metrics.MemoryTotalBytes = uint64(bucket.memoryTotal / count)
			bucket.sample.Metrics.MemoryUsedBytes = uint64(bucket.memoryUsed / count)
			bucket.sample.Metrics.SwapTotalBytes = uint64(bucket.swapTotal / count)
			bucket.sample.Metrics.SwapUsedBytes = uint64(bucket.swapUsed / count)
			bucket.sample.Metrics.ProcessCount = int(bucket.processCount / count)
		}
		samples = append(samples, bucket.sample)
	}
	return samples, nil
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

func (s *Store) ListAlertRules(ctx context.Context) ([]model.AlertRule, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, type, enabled, threshold, duration_seconds, cooldown_seconds, created_at, updated_at
		FROM alert_rules ORDER BY name COLLATE NOCASE, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var rules []model.AlertRule
	for rows.Next() {
		var rule model.AlertRule
		var enabled int
		var created, updated string
		if err := rows.Scan(&rule.ID, &rule.Name, &rule.Type, &enabled, &rule.Threshold, &rule.DurationSeconds, &rule.CooldownSeconds, &created, &updated); err != nil {
			return nil, err
		}
		rule.Enabled = enabled == 1
		rule.CreatedAt = parseTime(created)
		rule.UpdatedAt = parseTime(updated)
		rules = append(rules, rule)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	channelRows, err := s.db.QueryContext(ctx, `SELECT rule_id, channel_id FROM alert_rule_channels ORDER BY rule_id, channel_id`)
	if err != nil {
		return nil, err
	}
	defer channelRows.Close()
	channels := make(map[string][]string)
	for channelRows.Next() {
		var ruleID, channelID string
		if err := channelRows.Scan(&ruleID, &channelID); err != nil {
			return nil, err
		}
		channels[ruleID] = append(channels[ruleID], channelID)
	}
	if err := channelRows.Err(); err != nil {
		return nil, err
	}
	for index := range rules {
		rules[index].ChannelIDs = channels[rules[index].ID]
	}
	return rules, nil
}

func (s *Store) CreateAlertRule(ctx context.Context, rule model.AlertRule) error {
	now := time.Now().UTC()
	if rule.CreatedAt.IsZero() {
		rule.CreatedAt = now
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer rollback(tx)
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO alert_rules (id, name, type, enabled, threshold, duration_seconds, cooldown_seconds, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, rule.ID, rule.Name, rule.Type, boolInt(rule.Enabled), rule.Threshold,
		rule.DurationSeconds, rule.CooldownSeconds, rule.CreatedAt.UTC().Format(time.RFC3339Nano), now.Format(time.RFC3339Nano)); err != nil {
		return err
	}
	if err := insertRuleChannels(ctx, tx, rule.ID, rule.ChannelIDs); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) UpdateAlertRule(ctx context.Context, rule model.AlertRule) error {
	now := time.Now().UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer rollback(tx)
	result, err := tx.ExecContext(ctx, `
		UPDATE alert_rules SET name = ?, type = ?, enabled = ?, threshold = ?, duration_seconds = ?, cooldown_seconds = ?, updated_at = ?
		WHERE id = ?`, rule.Name, rule.Type, boolInt(rule.Enabled), rule.Threshold, rule.DurationSeconds, rule.CooldownSeconds, now.Format(time.RFC3339Nano), rule.ID)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected == 0 {
		return ErrAlertRuleNotFound
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM alert_rule_channels WHERE rule_id = ?`, rule.ID); err != nil {
		return err
	}
	if err := insertRuleChannels(ctx, tx, rule.ID, rule.ChannelIDs); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) DeleteAlertRule(ctx context.Context, id string) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM alert_rules WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected == 0 {
		return ErrAlertRuleNotFound
	}
	return nil
}

func insertRuleChannels(ctx context.Context, tx *sql.Tx, ruleID string, channelIDs []string) error {
	for _, channelID := range channelIDs {
		if _, err := tx.ExecContext(ctx, `INSERT INTO alert_rule_channels (rule_id, channel_id) VALUES (?, ?)`, ruleID, channelID); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) CreateNotificationChannel(ctx context.Context, record NotificationChannelRecord) error {
	now := time.Now().UTC()
	if record.Channel.CreatedAt.IsZero() {
		record.Channel.CreatedAt = now
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO notification_channels (id, name, type, enabled, target_ciphertext, secret_ciphertext, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, record.Channel.ID, record.Channel.Name, record.Channel.Type, boolInt(record.Channel.Enabled),
		record.TargetCiphertext, record.SecretCiphertext, record.Channel.CreatedAt.UTC().Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
	return err
}

func (s *Store) ListNotificationChannels(ctx context.Context) ([]model.NotificationChannel, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, type, enabled, created_at, updated_at
		FROM notification_channels ORDER BY name COLLATE NOCASE, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var channels []model.NotificationChannel
	for rows.Next() {
		var channel model.NotificationChannel
		var enabled int
		var created, updated string
		if err := rows.Scan(&channel.ID, &channel.Name, &channel.Type, &enabled, &created, &updated); err != nil {
			return nil, err
		}
		channel.Enabled = enabled == 1
		channel.Target = "已配置的" + channel.Type + "渠道"
		channel.CreatedAt = parseTime(created)
		channel.UpdatedAt = parseTime(updated)
		channels = append(channels, channel)
	}
	return channels, rows.Err()
}

func (s *Store) ListNotificationChannelRecords(ctx context.Context) ([]NotificationChannelRecord, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, type, enabled, target_ciphertext, secret_ciphertext, created_at, updated_at
		FROM notification_channels ORDER BY name COLLATE NOCASE, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var channels []NotificationChannelRecord
	for rows.Next() {
		var record NotificationChannelRecord
		var enabled int
		var created, updated string
		if err := rows.Scan(&record.Channel.ID, &record.Channel.Name, &record.Channel.Type, &enabled, &record.TargetCiphertext, &record.SecretCiphertext, &created, &updated); err != nil {
			return nil, err
		}
		record.Channel.Enabled = enabled == 1
		record.Channel.CreatedAt = parseTime(created)
		record.Channel.UpdatedAt = parseTime(updated)
		channels = append(channels, record)
	}
	return channels, rows.Err()
}

func (s *Store) DeleteNotificationChannel(ctx context.Context, id string) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM notification_channels WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected == 0 {
		return ErrNotificationChannelNotFound
	}
	return nil
}

func (s *Store) GetAlertState(ctx context.Context, ruleID, nodeID string) (model.AlertState, bool, error) {
	var state model.AlertState
	var fingerprint, first, evaluated, notified string
	err := s.db.QueryRowContext(ctx, `
		SELECT rule_id, node_id, status, value, message, fingerprint, first_triggered_at, last_evaluated_at, last_notified_at
		FROM alert_states WHERE rule_id = ? AND node_id = ?`, ruleID, nodeID).Scan(&state.RuleID, &state.NodeID, &state.Status, &state.Value, &state.Message, &fingerprint, &first, &evaluated, &notified)
	if errors.Is(err, sql.ErrNoRows) {
		return model.AlertState{}, false, nil
	}
	if err != nil {
		return model.AlertState{}, false, err
	}
	state.FirstTriggeredAt = parseTime(first)
	state.Fingerprint = fingerprint
	state.LastEvaluatedAt = parseTime(evaluated)
	state.LastNotifiedAt = parseTime(notified)
	return state, true, nil
}

func (s *Store) UpsertAlertState(ctx context.Context, state model.AlertState) error {
	if state.LastEvaluatedAt.IsZero() {
		state.LastEvaluatedAt = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO alert_states (rule_id, node_id, status, value, message, fingerprint, first_triggered_at, last_evaluated_at, last_notified_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(rule_id, node_id) DO UPDATE SET status = excluded.status, value = excluded.value, message = excluded.message,
		fingerprint = excluded.fingerprint, first_triggered_at = excluded.first_triggered_at, last_evaluated_at = excluded.last_evaluated_at, last_notified_at = excluded.last_notified_at`,
		state.RuleID, state.NodeID, state.Status, state.Value, state.Message, state.Fingerprint, formatTime(state.FirstTriggeredAt), state.LastEvaluatedAt.UTC().Format(time.RFC3339Nano), formatTime(state.LastNotifiedAt))
	return err
}

func (s *Store) AddAlertEvent(ctx context.Context, event model.AlertEvent) (int64, error) {
	result, err := s.db.ExecContext(ctx, `
		INSERT INTO alert_events (rule_id, node_id, kind, value, message, notified, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, event.RuleID, event.NodeID, event.Kind, event.Value, event.Message, boolInt(event.Notified), event.CreatedAt.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

func (s *Store) MarkAlertEventNotified(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE alert_events SET notified = 1 WHERE id = ?`, id)
	return err
}

func (s *Store) ListAlertEvents(ctx context.Context, limit int) ([]model.AlertEvent, error) {
	if limit < 1 {
		limit = 1
	}
	if limit > 500 {
		limit = 500
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT e.id, e.rule_id, r.name, e.node_id, n.name, e.kind, e.value, e.message, e.notified, e.created_at
		FROM alert_events e
		JOIN alert_rules r ON r.id = e.rule_id
		JOIN nodes n ON n.id = e.node_id
		ORDER BY e.id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var events []model.AlertEvent
	for rows.Next() {
		var event model.AlertEvent
		var notified int
		var created string
		if err := rows.Scan(&event.ID, &event.RuleID, &event.RuleName, &event.NodeID, &event.NodeName, &event.Kind, &event.Value, &event.Message, &notified, &created); err != nil {
			return nil, err
		}
		event.Notified = notified == 1
		event.CreatedAt = parseTime(created)
		events = append(events, event)
	}
	return events, rows.Err()
}

func (s *Store) CountActiveAlerts(ctx context.Context) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM alert_states a JOIN nodes n ON n.id = a.node_id
		WHERE a.status = 'firing' AND n.revoked = 0`).Scan(&count)
	return count, err
}

type nodeRecord struct {
	Node            model.Node
	TokenHash       string
	TokenCiphertext string
	CountryLookupIP string
	Revoked         bool
}

type scanner interface{ Scan(dest ...any) error }

func (s *Store) nodeRecord(ctx context.Context, id string) (nodeRecord, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, name, group_name, tags_json, token_hash, token_ciphertext, status, revoked, agent_version, last_ip,
		       ip_override, country, country_code, country_lookup_ip, country_override,
		       last_seen, first_seen, created_at, updated_at, sequence, system_json, last_report_json,
		       desired_version, update_status, update_error, update_requested_at, update_finished_at
		FROM nodes WHERE id = ?`, id)
	return scanNodeRecord(row)
}

func scanNodeRecord(row scanner) (nodeRecord, error) {
	var record nodeRecord
	var tagsJSON, status string
	var revoked int
	var lastSeen, firstSeen, created, updated, systemJSON, reportJSON string
	var updateStatus, updateRequestedAt, updateFinishedAt string
	if err := row.Scan(&record.Node.ID, &record.Node.Name, &record.Node.Group, &tagsJSON, &record.TokenHash, &record.TokenCiphertext,
		&status, &revoked, &record.Node.AgentVersion, &record.Node.LastIP, &record.Node.IPOverride,
		&record.Node.Country, &record.Node.CountryCode, &record.CountryLookupIP, &record.Node.CountryOverride,
		&lastSeen, &firstSeen,
		&created, &updated, &record.Node.Sequence, &systemJSON, &reportJSON, &record.Node.DesiredVersion,
		&updateStatus, &record.Node.UpdateError, &updateRequestedAt, &updateFinishedAt); err != nil {
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
	record.Node.UpdateStatus = model.NodeUpdateStatus(updateStatus)
	record.Node.UpdateRequestedAt = parseTime(updateRequestedAt)
	record.Node.UpdateFinishedAt = parseTime(updateFinishedAt)
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

func formatTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
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
