package controller

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"nyaservermonitor/internal/controller/store"
	"nyaservermonitor/internal/shared/model"
)

func TestAlertEngineFiresAndResolvesResourceRule(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, t.TempDir()+"/alerts.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	node := model.Node{ID: "node_alert", Name: "Alert node", Status: model.NodePending}
	if err := st.CreateNode(ctx, node, "hash"); err != nil {
		t.Fatal(err)
	}
	rule := model.AlertRule{ID: "rule_resource", Name: "Resource test", Type: model.AlertCPUHigh, Enabled: true, Threshold: 80}
	if err := st.CreateAlertRule(ctx, rule); err != nil {
		t.Fatal(err)
	}
	engine := newAlertEngine(st, nil, testLogger())
	for sequence, cpu := range []float64{95, 20} {
		report := model.Report{
			ProtocolVersion: model.ProtocolVersion,
			NodeID:          node.ID,
			SentAtUnix:      time.Now().Unix(),
			Sequence:        uint64(sequence + 1),
			AgentVersion:    "test",
			Metrics:         model.MetricsSnapshot{CPUPercent: cpu},
		}
		if err := st.UpdateReport(ctx, report); err != nil {
			t.Fatal(err)
		}
		if err := engine.evaluateNode(ctx, node.ID); err != nil {
			t.Fatal(err)
		}
	}
	events, err := st.ListAlertEvents(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	var firing, resolved bool
	for _, event := range events {
		if event.RuleID != rule.ID {
			continue
		}
		firing = firing || event.Kind == "firing"
		resolved = resolved || event.Kind == "resolved"
	}
	if !firing || !resolved {
		t.Fatalf("resource alert events = %#v", events)
	}
}

func TestAlertEngineSkipsMutedNode(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, t.TempDir()+"/alerts.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	node := model.Node{ID: "node_muted", Name: "Muted node", Status: model.NodePending}
	if err := st.CreateNode(ctx, node, "hash"); err != nil {
		t.Fatal(err)
	}
	rule := model.AlertRule{ID: "rule_muted", Name: "Muted test", Type: model.AlertCPUHigh, Enabled: true, Threshold: 80}
	if err := st.CreateAlertRule(ctx, rule); err != nil {
		t.Fatal(err)
	}
	engine := newAlertEngine(st, nil, testLogger())
	report := func(sequence uint64, cpu float64) {
		t.Helper()
		if err := st.UpdateReport(ctx, model.Report{
			ProtocolVersion: model.ProtocolVersion,
			NodeID:          node.ID,
			SentAtUnix:      time.Now().Unix(),
			Sequence:        sequence,
			AgentVersion:    "test",
			Metrics:         model.MetricsSnapshot{CPUPercent: cpu},
		}); err != nil {
			t.Fatal(err)
		}
		if err := engine.evaluateNode(ctx, node.ID); err != nil {
			t.Fatal(err)
		}
	}
	countEvents := func() int {
		t.Helper()
		events, err := st.ListAlertEvents(ctx, 100)
		if err != nil {
			t.Fatal(err)
		}
		return len(events)
	}

	report(1, 95)
	if active, err := st.CountActiveAlerts(ctx); err != nil || active != 1 {
		t.Fatalf("active alerts before mute = %d, %v", active, err)
	}
	firedEvents := countEvents()

	muted, err := st.SetNodeAlertsMuted(ctx, node.ID, true)
	if err != nil || !muted.AlertsMuted {
		t.Fatalf("mute node = %#v, %v", muted, err)
	}
	if active, err := st.CountActiveAlerts(ctx); err != nil || active != 0 {
		t.Fatalf("active alerts after mute = %d, %v", active, err)
	}
	report(2, 99)
	report(3, 10)
	if got := countEvents(); got != firedEvents {
		t.Fatalf("muted node produced events: %d -> %d", firedEvents, got)
	}
	state, _, err := st.GetAlertState(ctx, rule.ID, node.ID)
	if err != nil || state.Status != "resolved" {
		t.Fatalf("muted alert state = %#v, %v", state, err)
	}

	if _, err := st.SetNodeAlertsMuted(ctx, node.ID, false); err != nil {
		t.Fatal(err)
	}
	report(4, 97)
	if got := countEvents(); got != firedEvents+1 {
		t.Fatalf("unmuted node events = %d, want %d", got, firedEvents+1)
	}
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
