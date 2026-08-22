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

func formatInt(value int64) string { return strconv.FormatInt(value, 10) }
