package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"
	"time"

	"nyaservermonitor/internal/shared/model"
)

func insertMetricBucketTestSample(t *testing.T, st *Store, nodeID string, observedAt time.Time, sequence uint64, snapshot model.MetricsSnapshot) {
	t.Helper()
	snapshotJSON, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := st.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := upsertMetricBuckets(context.Background(), tx, nodeID, observedAt, sequence, snapshot, snapshotJSON, []byte("[]")); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func TestNodeReportRoundTripAndRevoke(t *testing.T) {
	ctx := context.Background()
	st, err := Open(ctx, t.TempDir()+"/monitor.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	node := model.Node{ID: "node_test", Name: "Test node", Status: model.NodePending, Tags: []string{"lab"}}
	if err := st.CreateNode(ctx, node, "hash"); err != nil {
		t.Fatal(err)
	}
	report := model.Report{ProtocolVersion: model.ProtocolVersion, NodeID: node.ID, SentAtUnix: time.Now().Unix(), Sequence: 7, AgentVersion: "dev", System: model.SystemInfo{Hostname: "host"}, Metrics: model.MetricsSnapshot{CPUPercent: 10}}
	if err := st.UpdateReport(ctx, report, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetNode(ctx, node.ID)
	if err != nil || got.Status != model.NodeOnline || got.Sequence != 7 || got.Metrics.CPUPercent != 10 {
		t.Fatalf("unexpected node: %#v, err=%v", got, err)
	}
	if err := st.SetNodeRevoked(ctx, node.ID, true); err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateReport(ctx, report, "127.0.0.1"); err != ErrNodeRevoked {
		t.Fatalf("expected revoked error, got %v", err)
	}
}

func TestUpdateNodeMetadata(t *testing.T) {
	ctx := context.Background()
	st, err := Open(ctx, t.TempDir()+"/metadata.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	node := model.Node{ID: "node_metadata", Name: "Before", Group: "old", Tags: []string{"one"}, Status: model.NodePending}
	if err := st.CreateNode(ctx, node, "hash"); err != nil {
		t.Fatal(err)
	}
	got, err := st.UpdateNodeMetadata(ctx, node.ID, "After", "production", []string{"web", "linux"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "After" || got.Group != "production" || len(got.Tags) != 2 || got.Tags[0] != "web" || got.Tags[1] != "linux" {
		t.Fatalf("updated node metadata = %#v", got)
	}
	if _, err := st.UpdateNodeMetadata(ctx, "missing", "Name", "", nil); err != ErrNodeNotFound {
		t.Fatalf("missing node error = %v", err)
	}
}

func TestNodeIPAndCountryOverridesAndLookupClaims(t *testing.T) {
	ctx := context.Background()
	st, err := Open(ctx, t.TempDir()+"/network.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	node := model.Node{ID: "node_network", Name: "Network node", Status: model.NodePending}
	if err := st.CreateNode(ctx, node, "hash"); err != nil {
		t.Fatal(err)
	}
	report := model.Report{
		ProtocolVersion: model.ProtocolVersion,
		NodeID:          node.ID,
		SentAtUnix:      time.Now().Unix(),
		Sequence:        1,
		AgentVersion:    "dev",
		System:          model.SystemInfo{IP: "10.0.0.5"},
	}
	if err := st.UpdateReport(ctx, report, "198.51.100.10"); err != nil {
		t.Fatal(err)
	}
	claimed, err := st.ClaimCountryLookup(ctx, node.ID, "198.51.100.10")
	if err != nil || !claimed {
		t.Fatalf("first country lookup claim = %v, err=%v", claimed, err)
	}
	if err := st.SaveNodeCountry(ctx, node.ID, "198.51.100.10", "Exampleland", "EX"); err != nil {
		t.Fatal(err)
	}
	claimed, err = st.ClaimCountryLookup(ctx, node.ID, "198.51.100.10")
	if err != nil || claimed {
		t.Fatalf("same-IP country lookup claim = %v, err=%v", claimed, err)
	}
	got, err := st.GetNode(ctx, node.ID)
	if err != nil || got.LastIP != "198.51.100.10" || got.Country != "Exampleland" || got.CountryCode != "EX" {
		t.Fatalf("automatic network metadata = %#v, err=%v", got, err)
	}
	if err := st.UpdateReport(ctx, report, "203.0.113.20"); err != nil {
		t.Fatal(err)
	}
	got, err = st.GetNode(ctx, node.ID)
	if err != nil || got.Country != "" || got.CountryCode != "" {
		t.Fatalf("country was not cleared after IP change = %#v, err=%v", got, err)
	}
	claimed, err = st.ClaimCountryLookup(ctx, node.ID, "203.0.113.20")
	if err != nil || !claimed {
		t.Fatalf("changed-IP country lookup claim = %v, err=%v", claimed, err)
	}
	if _, err := st.UpdateNodeMetadataWithOverrides(ctx, node.ID, node.Name, "", nil, "192.0.2.10", "Manual country"); err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateReport(ctx, report, "198.51.100.30"); err != nil {
		t.Fatal(err)
	}
	got, err = st.GetNode(ctx, node.ID)
	if err != nil || got.IPOverride != "192.0.2.10" || got.CountryOverride != "Manual country" {
		t.Fatalf("manual overrides were overwritten = %#v, err=%v", got, err)
	}
	if _, err := st.UpdateNodeMetadataWithOverrides(ctx, node.ID, node.Name, "", nil, "", ""); err != nil {
		t.Fatal(err)
	}
	got, err = st.GetNode(ctx, node.ID)
	if err != nil || got.IPOverride != "" || got.CountryOverride != "" || got.LastIP != "198.51.100.30" {
		t.Fatalf("manual overrides were not cleared = %#v, err=%v", got, err)
	}
}

func TestMetricBucketsAggregateAndSelectResolution(t *testing.T) {
	ctx := context.Background()
	st, err := Open(ctx, t.TempDir()+"/metrics.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	now := time.Now().UTC().Truncate(time.Second)
	insertMetricBucketTestSample(t, st, "node_metrics", now, 1, model.MetricsSnapshot{
		CPUPercent:       10,
		Load1:            1,
		MemoryTotalBytes: 1000,
		MemoryUsedBytes:  200,
		UptimeSeconds:    100,
		ProcessCount:     10,
		Disks:            []model.DiskMetric{{Device: "vda", TotalBytes: 1000, UsedBytes: 200}},
		Networks:         []model.NetworkMetric{{Name: "eth0", BytesIn: 100, BytesOut: 50}},
	})
	insertMetricBucketTestSample(t, st, "node_metrics", now.Add(5*time.Second), 2, model.MetricsSnapshot{
		CPUPercent:       30,
		Load1:            3,
		MemoryTotalBytes: 1200,
		MemoryUsedBytes:  400,
		UptimeSeconds:    105,
		ProcessCount:     20,
		Disks:            []model.DiskMetric{{Device: "vda", TotalBytes: 1000, UsedBytes: 300}},
		Networks:         []model.NetworkMetric{{Name: "eth0", BytesIn: 300, BytesOut: 150}},
	})

	samples, err := st.ListMetrics(ctx, "node_metrics", now.Add(-time.Hour), 2000)
	if err != nil {
		t.Fatal(err)
	}
	if len(samples) != 1 {
		t.Fatalf("aggregated samples = %d, want 1: %#v", len(samples), samples)
	}
	got := samples[0]
	if got.Sequence != 2 || got.Metrics.CPUPercent != 20 || got.Metrics.Load1 != 2 || got.Metrics.MemoryUsedBytes != 300 || got.Metrics.ProcessCount != 15 {
		t.Fatalf("unexpected aggregate: %#v", got)
	}
	if got.Metrics.UptimeSeconds != 105 || len(got.Metrics.Networks) != 1 || got.Metrics.Networks[0].BytesIn != 300 || got.Metrics.Disks[0].UsedBytes != 300 {
		t.Fatalf("last snapshot was not retained: %#v", got.Metrics)
	}

	var sampleCount int
	if err := st.db.QueryRowContext(ctx, `SELECT sample_count FROM metric_buckets WHERE node_id = ? AND resolution_seconds = 60`, "node_metrics").Scan(&sampleCount); err != nil {
		t.Fatal(err)
	}
	if sampleCount != 2 {
		t.Fatalf("bucket sample_count = %d, want 2", sampleCount)
	}

	resolutionCases := []struct {
		name     string
		duration time.Duration
		limit    int
		want     int64
	}{
		{name: "hour", duration: time.Hour, limit: 2000, want: 60},
		{name: "six hours plus request skew", duration: 6*time.Hour + time.Second, limit: 2000, want: 60},
		{name: "half day", duration: 12 * time.Hour, limit: 2000, want: 300},
		{name: "one day plus request skew", duration: 24*time.Hour + time.Second, limit: 2000, want: 300},
		{name: "two days", duration: 48 * time.Hour, limit: 2000, want: 1800},
		{name: "two weeks", duration: 14 * 24 * time.Hour, limit: 2000, want: 7200},
	}
	for _, test := range resolutionCases {
		t.Run(test.name, func(t *testing.T) {
			if got := metricResolutionFor(now.Add(-test.duration), now, test.limit); got != test.want {
				t.Fatalf("metric resolution = %d, want %d", got, test.want)
			}
		})
	}
}

func TestMetricPruneRemovesExpiredTiers(t *testing.T) {
	ctx := context.Background()
	st, err := Open(ctx, t.TempDir()+"/prune.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	now := time.Now().UTC().Truncate(time.Second)
	snapshot := model.MetricsSnapshot{CPUPercent: 12}
	insertMetricBucketTestSample(t, st, "node_prune", now.Add(-48*time.Hour), 1, snapshot)
	insertMetricBucketTestSample(t, st, "node_prune", now, 2, snapshot)
	if err := st.PruneMetrics(ctx, now.Add(-30*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	for _, tier := range metricBucketTiers {
		var count int
		if err := st.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM metric_buckets WHERE node_id = ? AND resolution_seconds = ?`, "node_prune", tier.seconds).Scan(&count); err != nil {
			t.Fatal(err)
		}
		want := 1
		if tier.seconds == 30*60 || tier.seconds == 2*60*60 {
			want = 2
		}
		if count != want {
			t.Fatalf("resolution %d bucket count = %d, want %d", tier.seconds, count, want)
		}
	}
	if err := st.PruneMetrics(ctx, now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	var remaining int
	if err := st.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM metric_buckets WHERE node_id = ?`, "node_prune").Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != len(metricBucketTiers) {
		t.Fatalf("global retention did not remove old coarse buckets: %d", remaining)
	}
}

func TestLegacyMetricSamplesAreCompactedOnOpen(t *testing.T) {
	ctx := context.Background()
	path := t.TempDir() + "/legacy.db"
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `CREATE TABLE metric_samples (id INTEGER PRIMARY KEY AUTOINCREMENT, node_id TEXT NOT NULL, observed_at TEXT NOT NULL, sequence INTEGER NOT NULL DEFAULT 0, snapshot_json TEXT NOT NULL, checks_json TEXT NOT NULL DEFAULT '[]')`); err != nil {
		t.Fatal(err)
	}
	snapshotJSON, err := json.Marshal(model.MetricsSnapshot{CPUPercent: 42, MemoryTotalBytes: 100, MemoryUsedBytes: 40})
	if err != nil {
		t.Fatal(err)
	}
	legacyTime := time.Now().UTC().Add(-2 * time.Hour)
	if _, err := db.ExecContext(ctx, `INSERT INTO metric_samples (node_id, observed_at, sequence, snapshot_json, checks_json) VALUES (?, ?, ?, ?, '[]')`, "node_legacy", legacyTime.Format(time.RFC3339Nano), 9, string(snapshotJSON)); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	st, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var legacyCount, bucketCount int
	if err := st.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM metric_samples`).Scan(&legacyCount); err != nil {
		t.Fatal(err)
	}
	if err := st.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM metric_buckets WHERE node_id = ?`, "node_legacy").Scan(&bucketCount); err != nil {
		t.Fatal(err)
	}
	if legacyCount != 0 || bucketCount != len(metricBucketTiers) {
		t.Fatalf("legacy compaction counts = legacy %d, buckets %d", legacyCount, bucketCount)
	}
	samples, err := st.ListMetrics(ctx, "node_legacy", time.Now().UTC().Add(-3*time.Hour), 2000)
	if err != nil {
		t.Fatal(err)
	}
	if len(samples) != 1 || samples[0].Metrics.CPUPercent != 42 || samples[0].Sequence != 9 {
		t.Fatalf("compacted legacy sample = %#v", samples)
	}
}

func TestAlertRulesChannelsStatesAndEvents(t *testing.T) {
	ctx := context.Background()
	st, err := Open(ctx, t.TempDir()+"/alerts.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	node := model.Node{ID: "node_alerts", Name: "Alert node", Status: model.NodePending}
	if err := st.CreateNode(ctx, node, "hash"); err != nil {
		t.Fatal(err)
	}
	rules, err := st.ListAlertRules(ctx)
	if err != nil || len(rules) < 9 {
		t.Fatalf("default alert rules = %d, err=%v", len(rules), err)
	}
	channel := model.NotificationChannel{ID: "channel_test", Name: "Test webhook", Type: "webhook", Enabled: true}
	if err := st.CreateNotificationChannel(ctx, NotificationChannelRecord{Channel: channel, TargetCiphertext: "target-cipher", SecretCiphertext: "secret-cipher"}); err != nil {
		t.Fatal(err)
	}
	rule := model.AlertRule{ID: "rule_test", Name: "Test rule", Type: model.AlertCPUHigh, Enabled: true, Threshold: 80, CooldownSeconds: 60, ChannelIDs: []string{channel.ID}}
	if err := st.CreateAlertRule(ctx, rule); err != nil {
		t.Fatal(err)
	}
	gotRules, err := st.ListAlertRules(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, got := range gotRules {
		if got.ID == rule.ID {
			found = true
			if len(got.ChannelIDs) != 1 || got.ChannelIDs[0] != channel.ID {
				t.Fatalf("rule channels = %#v", got.ChannelIDs)
			}
		}
	}
	if !found {
		t.Fatal("created alert rule was not returned")
	}
	now := time.Now().UTC()
	state := model.AlertState{RuleID: rule.ID, NodeID: node.ID, Status: "firing", Value: 92, Message: "high", FirstTriggeredAt: now, LastEvaluatedAt: now, Fingerprint: "fingerprint"}
	if err := st.UpsertAlertState(ctx, state); err != nil {
		t.Fatal(err)
	}
	gotState, exists, err := st.GetAlertState(ctx, rule.ID, node.ID)
	if err != nil || !exists || gotState.Fingerprint != state.Fingerprint || gotState.Status != state.Status {
		t.Fatalf("alert state = %#v, exists=%v, err=%v", gotState, exists, err)
	}
	eventID, err := st.AddAlertEvent(ctx, model.AlertEvent{RuleID: rule.ID, NodeID: node.ID, Kind: "firing", Value: 92, Message: "high", CreatedAt: now})
	if err != nil || eventID == 0 {
		t.Fatalf("add alert event id=%d err=%v", eventID, err)
	}
	events, err := st.ListAlertEvents(ctx, 10)
	if err != nil || len(events) != 1 || events[0].RuleName != rule.Name || events[0].NodeName != node.Name {
		t.Fatalf("alert events = %#v, err=%v", events, err)
	}
	active, err := st.CountActiveAlerts(ctx)
	if err != nil || active != 1 {
		t.Fatalf("active alerts = %d, err=%v", active, err)
	}
}
