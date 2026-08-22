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
