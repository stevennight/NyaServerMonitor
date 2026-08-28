package node

import (
	"os"
	"testing"
	"time"
)

func TestLoadChecksRejectsUnknownTypes(t *testing.T) {
	path := t.TempDir() + "/checks.json"
	if err := os.WriteFile(path, []byte(`[{"id":"x","name":"x","type":"shell","target":"id"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadChecks(path); err == nil {
		t.Fatal("shell checks must be rejected")
	}
}

func TestLoadChecksAppliesPingDefaults(t *testing.T) {
	path := t.TempDir() + "/checks.json"
	if err := os.WriteFile(path, []byte(`[{"id":"gateway","name":"Gateway","type":"ping","target":"1.1.1.1"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	checks, err := loadChecks(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(checks) != 1 || checks[0].TimeoutSeconds != 5 || checks[0].Attempts != 3 {
		t.Fatalf("ping defaults = %#v", checks)
	}
}

func TestLoadChecksAcceptsTLSChecks(t *testing.T) {
	path := t.TempDir() + "/checks.json"
	if err := os.WriteFile(path, []byte(`[{"id":"certificate","name":"Certificate","type":"tls","target":"https://example.com"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadChecks(path); err != nil {
		t.Fatal(err)
	}
}

func TestServiceCheckLatencyPreservesPingAverage(t *testing.T) {
	if got := serviceCheckLatency("ping", 18, 75*time.Millisecond); got != 18 {
		t.Fatalf("ping latency = %d, want measured average 18", got)
	}
	if got := serviceCheckLatency("http", 18, 75*time.Millisecond); got != 75 {
		t.Fatalf("http latency = %d, want elapsed duration 75", got)
	}
}
