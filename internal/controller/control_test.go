package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"

	"nyaservermonitor/internal/controller/store"
	sharedcrypto "nyaservermonitor/internal/shared/crypto"
	"nyaservermonitor/internal/shared/model"
	sharedprotocol "nyaservermonitor/internal/shared/protocol"
	sharedversion "nyaservermonitor/internal/shared/version"
)

func TestInstallCommandReusesEncryptedNodeToken(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	s := NewServer(Config{PublicURL: "https://monitor.example.test", NodeTokenKey: "stable-node-token-key", SessionLifetime: time.Hour, OfflineAfter: time.Minute, CleanupInterval: time.Minute, MetricsRetention: time.Hour}, st)
	cookie := setupTestAdmin(t, s)

	create := httptest.NewRequest(http.MethodPost, "/api/nodes", strings.NewReader(`{"name":"reusable install"}`))
	create.Header.Set("Content-Type", "application/json")
	create.AddCookie(cookie)
	created := httptest.NewRecorder()
	s.mux.ServeHTTP(created, create)
	if created.Code != http.StatusCreated {
		t.Fatalf("create status: %d %s", created.Code, created.Body.String())
	}
	var first nodeCredential
	if err := json.Unmarshal(created.Body.Bytes(), &first); err != nil {
		t.Fatal(err)
	}

	install := httptest.NewRequest(http.MethodPost, "/api/nodes/"+first.Node.ID+"/install", nil)
	install.AddCookie(cookie)
	installed := httptest.NewRecorder()
	s.mux.ServeHTTP(installed, install)
	if installed.Code != http.StatusOK {
		t.Fatalf("install status: %d %s", installed.Code, installed.Body.String())
	}
	var second nodeCredential
	if err := json.Unmarshal(installed.Body.Bytes(), &second); err != nil {
		t.Fatal(err)
	}
	if second.Token != first.Token || second.InstallCommand != first.InstallCommand {
		t.Fatalf("install command changed token: first=%#v second=%#v", first, second)
	}

	rotate := httptest.NewRequest(http.MethodPost, "/api/nodes/"+first.Node.ID+"/rotate-token", nil)
	rotate.AddCookie(cookie)
	rotated := httptest.NewRecorder()
	s.mux.ServeHTTP(rotated, rotate)
	if rotated.Code != http.StatusOK {
		t.Fatalf("rotate status: %d %s", rotated.Code, rotated.Body.String())
	}
	var third nodeCredential
	if err := json.Unmarshal(rotated.Body.Bytes(), &third); err != nil {
		t.Fatal(err)
	}
	if third.Token == first.Token {
		t.Fatal("token rotation did not change token")
	}

	unauthenticated := httptest.NewRecorder()
	s.mux.ServeHTTP(unauthenticated, httptest.NewRequest(http.MethodPost, "/api/nodes/"+first.Node.ID+"/install", nil))
	if unauthenticated.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated install status: %d", unauthenticated.Code)
	}
}

func TestUpdateNodeMetadataEndpoint(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	s := NewServer(Config{SessionLifetime: time.Hour, OfflineAfter: time.Minute, CleanupInterval: time.Minute, MetricsRetention: time.Hour}, st)
	cookie := setupTestAdmin(t, s)
	const nodeID = "node_metadata"
	if err := st.CreateNode(ctx, model.Node{ID: nodeID, Name: "Before", Status: model.NodePending}, "hash"); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPut, "/api/nodes/"+nodeID, strings.NewReader(`{"name":" After ","group":" production ","tags":[" web ","linux"]}`))
	request.Header.Set("Content-Type", "application/json")
	request.AddCookie(cookie)
	response := httptest.NewRecorder()
	s.mux.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("update status: %d %s", response.Code, response.Body.String())
	}
	var updated model.Node
	if err := json.Unmarshal(response.Body.Bytes(), &updated); err != nil {
		t.Fatal(err)
	}
	if updated.Name != "After" || updated.Group != "production" || len(updated.Tags) != 2 || updated.Tags[0] != "web" {
		t.Fatalf("updated response = %#v", updated)
	}
	stored, err := st.GetNode(ctx, nodeID)
	if err != nil || stored.Name != "After" || stored.Group != "production" {
		t.Fatalf("stored node = %#v, err=%v", stored, err)
	}
}

func TestNodeWebSocketAuthenticatesAndMarksNodeSeen(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	token := strings.Repeat("n", 32)
	if err := st.CreateNode(ctx, model.Node{ID: "node_ws", Name: "WebSocket node", Status: model.NodePending}, sharedcrypto.HashToken(token)); err != nil {
		t.Fatal(err)
	}
	s := NewServer(Config{PublicURL: "http://127.0.0.1:8080", SessionLifetime: time.Hour, OfflineAfter: time.Minute, CleanupInterval: time.Minute, MetricsRetention: time.Hour}, st)
	server := httptest.NewServer(s.mux)
	defer server.Close()

	conn, err := newTestNodeWS(ctx, server.URL, "node_ws", token)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "test complete")
	hello := sharedprotocol.ControlMessage{Type: "hello", NodeID: "node_ws", Version: "v0.1.0", System: model.SystemInfo{OS: "linux", Arch: "amd64"}}
	if err := wsjson.Write(ctx, conn, hello); err != nil {
		t.Fatal(err)
	}
	heartbeat := sharedprotocol.ControlMessage{Type: "heartbeat", NodeID: "node_ws", Version: "v0.1.0", System: hello.System}
	if err := wsjson.Write(ctx, conn, heartbeat); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		node, err := st.GetNode(ctx, "node_ws")
		if err == nil && node.Status == model.NodeOnline {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	node, _ := st.GetNode(ctx, "node_ws")
	t.Fatalf("node was not marked online: %#v", node)
}

func TestNodeWebSocketReceivesSignedUpdate(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	publicKey, privateKey, err := sharedcrypto.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	oldKey := sharedversion.UpdatePublicKey
	sharedversion.UpdatePublicKey = publicKey
	defer func() { sharedversion.UpdatePublicKey = oldKey }()

	token := strings.Repeat("u", 32)
	if err := st.CreateNode(ctx, model.Node{ID: "node_update", Name: "Update node", Status: model.NodePending}, sharedcrypto.HashToken(token)); err != nil {
		t.Fatal(err)
	}
	if _, err := st.RequestNodeUpdate(ctx, "node_update", "v0.2.0"); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	payload := []byte("signed-update-node")
	if err := os.WriteFile(filepath.Join(dir, "nyasm-node-linux-amd64"), payload, 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := model.NodeReleaseManifest{Version: "v0.2.0", Artifacts: []model.NodeReleaseArtifact{{OS: "linux", Arch: "amd64", SHA256: sha256Hex(payload), Size: int64(len(payload))}}}
	signature, err := sharedcrypto.SignJSON(privateKey, manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	for path, content := range map[string][]byte{
		filepath.Join(dir, nodeReleaseManifestFilename):  manifestBytes,
		filepath.Join(dir, nodeReleaseSignatureFilename): []byte(signature),
		filepath.Join(dir, nodeReleasePublicKeyFilename): []byte(publicKey),
	} {
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	s := NewServer(Config{PublicURL: "http://127.0.0.1:8080", NodeBinaryDir: dir, SessionLifetime: time.Hour, OfflineAfter: time.Minute, CleanupInterval: time.Minute, MetricsRetention: time.Hour}, st)
	server := httptest.NewServer(s.mux)
	defer server.Close()
	conn, err := newTestNodeWS(ctx, server.URL, "node_update", token)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "test complete")
	if err := wsjson.Write(ctx, conn, sharedprotocol.ControlMessage{Type: "hello", NodeID: "node_update", Version: "v0.1.0", System: model.SystemInfo{OS: "linux", Arch: "amd64"}}); err != nil {
		t.Fatal(err)
	}

	readCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var message sharedprotocol.ControlMessage
	if err := wsjson.Read(readCtx, conn, &message); err != nil {
		t.Fatal(err)
	}
	if message.Type != "update" || message.Update == nil {
		t.Fatalf("unexpected update message: %#v", message)
	}
	if message.Update.Version != manifest.Version || message.Update.SigningKeyID != publicKey {
		t.Fatalf("unexpected update metadata: %#v", message.Update)
	}
	if err := sharedcrypto.VerifyJSON(publicKey, message.Update.Manifest, message.Update.Signature); err != nil {
		t.Fatalf("controller sent an invalid update signature: %v", err)
	}
}

func TestNodeWebSocketRejectsMissingCredential(t *testing.T) {
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	s := NewServer(Config{PublicURL: "http://127.0.0.1:8080", SessionLifetime: time.Hour, OfflineAfter: time.Minute, CleanupInterval: time.Minute, MetricsRetention: time.Hour}, st)
	response := httptest.NewRecorder()
	s.mux.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/node/ws", nil))
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("missing credential status: %d %s", response.Code, response.Body.String())
	}
}

func TestNodeReleaseVerifiesManifestAndArtifacts(t *testing.T) {
	publicKey, privateKey, err := sharedcrypto.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	oldKey := sharedversion.UpdatePublicKey
	sharedversion.UpdatePublicKey = publicKey
	defer func() { sharedversion.UpdatePublicKey = oldKey }()

	dir := t.TempDir()
	payload := []byte("signed-node-binary")
	path := filepath.Join(dir, "nyasm-node-linux-amd64")
	if err := os.WriteFile(path, payload, 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := model.NodeReleaseManifest{Version: "v0.2.0", Artifacts: []model.NodeReleaseArtifact{{OS: "linux", Arch: "amd64", SHA256: sha256Hex(payload), Size: int64(len(payload))}}}
	signature, err := sharedcrypto.SignJSON(privateKey, manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifestBytes, _ := json.Marshal(manifest)
	if err := os.WriteFile(filepath.Join(dir, nodeReleaseManifestFilename), manifestBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, nodeReleaseSignatureFilename), []byte(signature), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, nodeReleasePublicKeyFilename), []byte(publicKey), 0o600); err != nil {
		t.Fatal(err)
	}
	s := &Server{cfg: Config{NodeBinaryDir: dir}}
	release := s.nodeReleaseUncached()
	if !release.UpdateEnabled || release.Manifest.Version != manifest.Version {
		t.Fatalf("release was not enabled: %#v", release)
	}
}

func setupTestAdmin(t *testing.T, s *Server) *http.Cookie {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/api/setup", strings.NewReader(`{"username":"admin","password":"correct-horse-battery-staple"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	s.mux.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("setup status: %d %s", response.Code, response.Body.String())
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("setup cookies: %d", len(cookies))
	}
	return cookies[0]
}

func newTestNodeWS(ctx context.Context, controllerURL, nodeID, token string) (*websocket.Conn, error) {
	parsed, err := url.Parse(controllerURL)
	if err != nil {
		return nil, err
	}
	parsed.Scheme = "ws"
	parsed.Path = "/api/node/ws"
	parsed.RawQuery = ""
	parsed.Fragment = ""
	headers := http.Header{}
	headers.Set("X-NyaSM-Node-ID", nodeID)
	headers.Set("X-NyaSM-Node-Token", token)
	conn, response, err := websocket.Dial(ctx, parsed.String(), &websocket.DialOptions{HTTPHeader: headers})
	if err != nil && response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
	return conn, err
}

func sha256Hex(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}
