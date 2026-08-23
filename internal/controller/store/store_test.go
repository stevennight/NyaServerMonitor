package store

import (
	"context"
	"testing"
	"time"

	"nyaservermonitor/internal/shared/model"
)

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
