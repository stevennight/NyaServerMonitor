package controller

import (
	"encoding/json"
	"strings"
	"testing"

	"nyaservermonitor/internal/shared/model"
)

func TestPublicTelemetryStreamSanitizesPrivateFields(t *testing.T) {
	hub := newTelemetryHub()
	_, events, unsubscribe := hub.Subscribe(true)
	defer unsubscribe()

	hub.Publish(model.LiveTelemetry{
		NodeID:              "node_secret_id",
		Sequence:            8,
		ObservedAtUnixMilli: 123,
		AgentVersion:        "v-private",
		System:              model.SystemInfo{Hostname: "private-host", IP: "192.0.2.10"},
		MetricsAvailable:    true,
		Metrics:             model.MetricsSnapshot{CPUPercent: 42.4, MemoryTotalBytes: 100, MemoryUsedBytes: 50},
		Networks:            []model.LiveNetworkMetric{{Name: "eth0", BytesInPerSecond: 2048, BytesOutPerSecond: 1024}},
	})

	event := <-events
	line := strings.TrimSpace(strings.TrimPrefix(strings.Split(string(event), "\n")[1], "data: "))
	var received map[string]any
	if err := json.Unmarshal([]byte(line), &received); err != nil {
		t.Fatal(err)
	}
	if received["node_id"] != publicNodeID("node_secret_id") {
		t.Fatalf("public node id = %#v", received["node_id"])
	}
	if received["cpu_percent"] != float64(42) || received["memory_percent"] != float64(50) {
		t.Fatalf("public metrics = %#v", received)
	}
	for _, key := range []string{"agent_version", "system", "metrics"} {
		if _, ok := received[key]; ok {
			t.Fatalf("private field %q leaked: %#v", key, received)
		}
	}
	if strings.Contains(string(event), "node_secret_id") || strings.Contains(string(event), "private-host") || strings.Contains(string(event), "192.0.2.10") || strings.Contains(string(event), "eth0") {
		t.Fatalf("private telemetry value leaked: %s", event)
	}
}
