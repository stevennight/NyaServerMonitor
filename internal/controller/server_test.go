package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"nyaservermonitor/internal/controller/store"
	sharedcrypto "nyaservermonitor/internal/shared/crypto"
	"nyaservermonitor/internal/shared/model"
)

func TestAgentReportAuthenticatesAndRejectsReplay(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, t.TempDir()+"/server.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	const token = "01234567890123456789012345678901"
	if err := st.CreateNode(ctx, model.Node{ID: "node_test", Name: "Test", Status: model.NodePending}, sharedcrypto.HashToken(token)); err != nil {
		t.Fatal(err)
	}
	s := NewServer(Config{PublicURL: "http://127.0.0.1:8080", SessionLifetime: time.Hour, OfflineAfter: time.Minute, CleanupInterval: time.Minute, MetricsRetention: time.Hour}, st)
	report := model.Report{ProtocolVersion: model.ProtocolVersion, NodeID: "node_test", SentAtUnix: time.Now().Unix(), Sequence: 1, AgentVersion: "test", System: model.SystemInfo{Hostname: "host"}, Metrics: model.MetricsSnapshot{CPUPercent: 12}}
	body, _ := json.Marshal(report)
	timestamp := time.Now().Unix()
	nonce := "abcdefghijklmnop"
	signature := sharedcrypto.ReportSignature(sharedcrypto.HashToken(token), http.MethodPost, reportPath, formatInt(timestamp), nonce, body)
	request := httptest.NewRequest(http.MethodPost, reportPath, strings.NewReader(string(body)))
	request.RemoteAddr = "127.0.0.1:1234"
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-NyaSM-Node-ID", "node_test")
	request.Header.Set("X-NyaSM-Timestamp", formatInt(timestamp))
	request.Header.Set("X-NyaSM-Nonce", nonce)
	request.Header.Set("X-NyaSM-Signature", signature)
	response := httptest.NewRecorder()
	s.handleAgentReport(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("first report status: %d %s", response.Code, response.Body.String())
	}
	request = httptest.NewRequest(http.MethodPost, reportPath, strings.NewReader(string(body)))
	request.RemoteAddr = "127.0.0.1:1234"
	for key, values := range map[string]string{"Content-Type": "application/json", "X-NyaSM-Node-ID": "node_test", "X-NyaSM-Timestamp": formatInt(timestamp), "X-NyaSM-Nonce": nonce, "X-NyaSM-Signature": signature} {
		request.Header.Set(key, values)
	}
	response = httptest.NewRecorder()
	s.handleAgentReport(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("replayed report status: %d", response.Code)
	}
}

func TestPublicDashboardOmitsSensitiveNodeDetails(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, t.TempDir()+"/public.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.CreateNode(ctx, model.Node{ID: "node_public", Name: "Public status", Group: "production", Tags: []string{"web", "edge"}, CountryOverride: "日本", Status: model.NodePending}, "hash"); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateNode(ctx, model.Node{ID: "node_revoked", Name: "Hidden revoked", Status: model.NodeRevoked}, "hash"); err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateReport(ctx, model.Report{
		ProtocolVersion: model.ProtocolVersion,
		NodeID:          "node_public",
		SentAtUnix:      time.Now().Unix(),
		Sequence:        1,
		AgentVersion:    "private-agent",
		System:          model.SystemInfo{Hostname: "internal-host", IP: "10.0.0.5", OS: "linux", Kernel: "private-kernel"},
		Metrics: model.MetricsSnapshot{
			CPUPercent:       37.4,
			MemoryUsedBytes:  60,
			MemoryTotalBytes: 100,
			Disks:            []model.DiskMetric{{Mount: "/", UsedBytes: 80, TotalBytes: 100}},
			Networks:         []model.NetworkMetric{{Name: "eth0", BytesIn: 4096, BytesOut: 2048}},
		},
		Checks: []model.ServiceCheck{{Name: "private-db", Target: "10.0.0.6:5432", Status: "down"}},
	}, "10.0.0.5"); err != nil {
		t.Fatal(err)
	}
	s := NewServer(Config{PublicURL: "http://127.0.0.1:8080", SessionLifetime: time.Hour, OfflineAfter: time.Minute, CleanupInterval: time.Minute, MetricsRetention: time.Hour}, st)
	request := httptest.NewRequest(http.MethodGet, "/api/public/dashboard", nil)
	response := httptest.NewRecorder()
	s.mux.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("public dashboard status: %d %s", response.Code, response.Body.String())
	}
	var dashboard model.PublicDashboard
	if err := json.Unmarshal(response.Body.Bytes(), &dashboard); err != nil {
		t.Fatal(err)
	}
	if dashboard.TotalNodes != 1 || len(dashboard.Nodes) != 1 {
		t.Fatalf("unexpected public dashboard: %#v", dashboard)
	}
	publicNode := dashboard.Nodes[0]
	if publicNode.Name != "Public status" || publicNode.Status != model.NodeOnline || publicNode.Group != "production" || len(publicNode.Tags) != 2 || publicNode.Country != "日本" || publicNode.CPUPercent != 37 || publicNode.MemoryPercent != 60 || publicNode.DiskPercent != 80 || publicNode.NetworkInBytes != 4096 || publicNode.NetworkOutBytes != 2048 || publicNode.ChecksUp != 0 || publicNode.ChecksTotal != 1 {
		t.Fatalf("unexpected public node: %#v", publicNode)
	}
	body := response.Body.String()
	for _, secret := range []string{"node_public", "10.0.0.5", "internal-host", "private-agent", "private-db", "10.0.0.6:5432"} {
		if strings.Contains(body, secret) {
			t.Fatalf("public response leaked %q: %s", secret, body)
		}
	}
	metricsRequest := httptest.NewRequest(http.MethodGet, "/api/public/nodes/"+publicNode.ID+"/metrics?hours=24&limit=10", nil)
	metricsResponse := httptest.NewRecorder()
	s.mux.ServeHTTP(metricsResponse, metricsRequest)
	if metricsResponse.Code != http.StatusOK {
		t.Fatalf("public metrics status: %d %s", metricsResponse.Code, metricsResponse.Body.String())
	}
	var publicMetrics struct {
		Samples []model.PublicMetricSample `json:"samples"`
	}
	if err := json.Unmarshal(metricsResponse.Body.Bytes(), &publicMetrics); err != nil {
		t.Fatal(err)
	}
	if len(publicMetrics.Samples) != 1 || publicMetrics.Samples[0].CPUPercent != 37.4 || publicMetrics.Samples[0].MemoryPercent != 60 || publicMetrics.Samples[0].NetworkInBytes != 4096 || publicMetrics.Samples[0].NetworkOutBytes != 2048 {
		t.Fatalf("unexpected public metrics: %#v", publicMetrics)
	}
	for _, secret := range []string{"node_public", "10.0.0.5", "internal-host", "private-db", "10.0.0.6:5432"} {
		if strings.Contains(metricsResponse.Body.String(), secret) {
			t.Fatalf("public metrics leaked %q: %s", secret, metricsResponse.Body.String())
		}
	}
	if response.Header().Get("Cache-Control") != "public, max-age=5, stale-while-revalidate=15" {
		t.Fatalf("unexpected public cache policy: %q", response.Header().Get("Cache-Control"))
	}
	privateRequest := httptest.NewRequest(http.MethodGet, "/api/dashboard", nil)
	privateResponse := httptest.NewRecorder()
	s.mux.ServeHTTP(privateResponse, privateRequest)
	if privateResponse.Code != http.StatusUnauthorized {
		t.Fatalf("private dashboard should require auth, got %d", privateResponse.Code)
	}
	setupRequest := httptest.NewRequest(http.MethodPost, "/api/setup", strings.NewReader(`{"username":"admin","password":"correct-horse-battery-staple"}`))
	setupRequest.Header.Set("Content-Type", "application/json")
	setupResponse := httptest.NewRecorder()
	s.mux.ServeHTTP(setupResponse, setupRequest)
	if setupResponse.Code != http.StatusCreated {
		t.Fatalf("setup status: %d %s", setupResponse.Code, setupResponse.Body.String())
	}
	cookies := setupResponse.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected one session cookie, got %d", len(cookies))
	}
	privateRequest = httptest.NewRequest(http.MethodGet, "/api/dashboard", nil)
	privateRequest.AddCookie(cookies[0])
	privateResponse = httptest.NewRecorder()
	s.mux.ServeHTTP(privateResponse, privateRequest)
	if privateResponse.Code != http.StatusOK {
		t.Fatalf("authenticated private dashboard status: %d %s", privateResponse.Code, privateResponse.Body.String())
	}
	privateBody := privateResponse.Body.String()
	for _, secret := range []string{"node_public", "10.0.0.5", "internal-host"} {
		if !strings.Contains(privateBody, secret) {
			t.Fatalf("authenticated private dashboard omitted %q: %s", secret, privateBody)
		}
	}
}

func TestPublicDiskPercentAggregatesPhysicalDisks(t *testing.T) {
	disks := []model.DiskMetric{
		{Device: "vda", UsedBytes: 50, TotalBytes: 100},
		{Device: "vdb", UsedBytes: 30, TotalBytes: 300},
	}
	if got := publicDiskPercent(disks); got != 20 {
		t.Fatalf("expected weighted disk usage of 20%%, got %d%%", got)
	}
}

func TestPublicNodeSortModes(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	nodes := []model.Node{
		{ID: "node_b", Name: "Alpha", CreatedAt: base.Add(2 * time.Hour)},
		{ID: "node_a", Name: "Zulu", CreatedAt: base},
	}
	if got := publicNodeSort(""); got != "name" {
		t.Fatalf("default public sort: got %q, want name", got)
	}
	if got := publicNodeSort("created"); got != "created" {
		t.Fatalf("created public sort: got %q, want created", got)
	}
	sortPublicNodes(nodes, "created")
	if nodes[0].ID != "node_a" || nodes[1].ID != "node_b" {
		t.Fatalf("created sort order: %#v", nodes)
	}
	sortPublicNodes(nodes, "name")
	if nodes[0].ID != "node_b" || nodes[1].ID != "node_a" {
		t.Fatalf("name sort order: %#v", nodes)
	}
}

func TestUnauthenticatedPrivateAPIsRequireSession(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, t.TempDir()+"/auth.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	s := NewServer(Config{PublicURL: "http://127.0.0.1:8080", SessionLifetime: time.Hour, OfflineAfter: time.Minute, CleanupInterval: time.Minute, MetricsRetention: time.Hour}, st)

	protected := []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/api/auth/logout"},
		{http.MethodGet, "/api/me"},
		{http.MethodPost, "/api/settings/totp/setup"},
		{http.MethodPost, "/api/settings/totp/enable"},
		{http.MethodPost, "/api/settings/totp/disable"},
		{http.MethodGet, "/api/dashboard"},
		{http.MethodGet, "/api/audit"},
		{http.MethodGet, "/api/alerts"},
		{http.MethodGet, "/api/alerts/events"},
		{http.MethodPost, "/api/alerts/rules"},
		{http.MethodPut, "/api/alerts/rules/rule_secret"},
		{http.MethodDelete, "/api/alerts/rules/rule_secret"},
		{http.MethodPost, "/api/alerts/channels"},
		{http.MethodDelete, "/api/alerts/channels/channel_secret"},
		{http.MethodGet, "/api/controller/info"},
		{http.MethodGet, "/api/nodes"},
		{http.MethodPost, "/api/nodes"},
		{http.MethodGet, "/api/nodes/node_secret"},
		{http.MethodPut, "/api/nodes/node_secret"},
		{http.MethodGet, "/api/nodes/node_secret/metrics"},
		{http.MethodPost, "/api/nodes/node_secret/rotate-token"},
		{http.MethodPost, "/api/nodes/node_secret/install"},
		{http.MethodPost, "/api/nodes/node_secret/update"},
		{http.MethodPost, "/api/nodes/node_secret/revoke"},
		{http.MethodPost, "/api/nodes/node_secret/restore"},
	}
	for _, endpoint := range protected {
		request := httptest.NewRequest(endpoint.method, endpoint.path, nil)
		response := httptest.NewRecorder()
		s.mux.ServeHTTP(response, request)
		if response.Code != http.StatusUnauthorized {
			t.Errorf("%s %s status: got %d, want %d (%s)", endpoint.method, endpoint.path, response.Code, http.StatusUnauthorized, response.Body.String())
		}
		for _, secret := range []string{"node_secret", "10.0.0.5", "private-host", "private-agent"} {
			if strings.Contains(response.Body.String(), secret) {
				t.Errorf("%s %s leaked %q: %s", endpoint.method, endpoint.path, secret, response.Body.String())
			}
		}
	}

	setupRequest := httptest.NewRequest(http.MethodGet, "/api/setup/status", nil)
	setupResponse := httptest.NewRecorder()
	s.mux.ServeHTTP(setupResponse, setupRequest)
	if setupResponse.Code != http.StatusOK {
		t.Fatalf("setup status: got %d", setupResponse.Code)
	}
	var setupBody map[string]json.RawMessage
	if err := json.Unmarshal(setupResponse.Body.Bytes(), &setupBody); err != nil {
		t.Fatal(err)
	}
	if len(setupBody) != 1 {
		t.Fatalf("setup status exposed unexpected fields: %s", setupResponse.Body.String())
	}
	if _, ok := setupBody["needs_setup"]; !ok {
		t.Fatalf("setup status missing needs_setup: %s", setupResponse.Body.String())
	}
}

func formatInt(value int64) string { return strconv.FormatInt(value, 10) }
