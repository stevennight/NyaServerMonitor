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
		if err := st.UpdateReport(ctx, report, "127.0.0.1"); err != nil {
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

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
