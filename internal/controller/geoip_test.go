package controller

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"nyaservermonitor/internal/controller/store"
	"nyaservermonitor/internal/shared/model"
)

func TestGeoIPLookupParsesCountry(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/8.8.8.8" {
			t.Fatalf("unexpected geoip path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"country":"Exampleland","country_code":"EX"}`))
	}))
	defer server.Close()

	lookup := newGeoIPLookup(server.URL + "/{ip}")
	country, code, err := lookup.lookup(context.Background(), "8.8.8.8")
	if err != nil || country != "Exampleland" || code != "EX" {
		t.Fatalf("geoip result = %q/%q, err=%v", country, code, err)
	}
}

func TestGeoIPLookupSkipsPrivateIP(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
	}))
	defer server.Close()

	lookup := newGeoIPLookup(server.URL + "/{ip}")
	if _, _, err := lookup.lookup(context.Background(), "10.0.0.5"); err == nil {
		t.Fatal("private IP lookup should fail without an HTTP request")
	}
	if requests.Load() != 0 {
		t.Fatalf("private IP lookup made %d HTTP requests", requests.Load())
	}
}

func TestNodeCountryLookupRunsOncePerObservedIP(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, t.TempDir()+"/geoip.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	const nodeID = "node_geoip"
	if err := st.CreateNode(ctx, model.Node{ID: nodeID, Name: "GeoIP node", Status: model.NodePending}, "hash"); err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"country":"Exampleland","country_code":"EX"}`))
	}))
	defer server.Close()
	s := NewServer(Config{GeoIPURL: server.URL + "/{ip}", SessionLifetime: time.Hour, OfflineAfter: time.Minute, CleanupInterval: time.Minute, MetricsRetention: time.Hour}, st)
	report := model.Report{ProtocolVersion: model.ProtocolVersion, NodeID: nodeID, SentAtUnix: time.Now().Unix(), Sequence: 1, AgentVersion: "test"}
	if err := st.UpdateReport(ctx, report, "8.8.8.8"); err != nil {
		t.Fatal(err)
	}
	if err := s.queueNodeCountryLookup(ctx, nodeID, "8.8.8.8"); err != nil {
		t.Fatal(err)
	}
	waitForNodeCountry(t, st, nodeID, "Exampleland")
	if err := s.queueNodeCountryLookup(ctx, nodeID, "8.8.8.8"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if requests.Load() != 1 {
		t.Fatalf("same-IP lookup count = %d, want 1", requests.Load())
	}
	if err := st.UpdateReport(ctx, report, "1.1.1.1"); err != nil {
		t.Fatal(err)
	}
	if err := s.queueNodeCountryLookup(ctx, nodeID, "1.1.1.1"); err != nil {
		t.Fatal(err)
	}
	waitForNodeCountry(t, st, nodeID, "Exampleland")
	if requests.Load() != 2 {
		t.Fatalf("changed-IP lookup count = %d, want 2", requests.Load())
	}
	if _, err := st.UpdateNodeMetadataWithOverrides(ctx, nodeID, "GeoIP node", "", nil, "8.8.4.4", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.queueNodeCountryLookup(ctx, nodeID, "8.8.4.4"); err != nil {
		t.Fatal(err)
	}
	waitForRequestCount(t, &requests, 3)
	if err := st.UpdateReport(ctx, report, "9.9.9.9"); err != nil {
		t.Fatal(err)
	}
	if err := s.queueNodeCountryLookup(ctx, nodeID, "8.8.4.4"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if requests.Load() != 3 {
		t.Fatalf("automatic IP change overwrote manual IP lookup count = %d, want 3", requests.Load())
	}
}

func waitForNodeCountry(t *testing.T, st *store.Store, nodeID, want string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		node, err := st.GetNode(context.Background(), nodeID)
		if err == nil && node.Country == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	node, _ := st.GetNode(context.Background(), nodeID)
	t.Fatalf("node country = %#v, want %q", node, want)
}

func waitForRequestCount(t *testing.T, requests *atomic.Int32, want int32) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if requests.Load() == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("geoip request count = %d, want %d", requests.Load(), want)
}
