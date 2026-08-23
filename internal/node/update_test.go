package node

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	sharedcrypto "nyaservermonitor/internal/shared/crypto"
	"nyaservermonitor/internal/shared/model"
	sharedversion "nyaservermonitor/internal/shared/version"
)

func TestHandleUpdateCommandRequiresTrustedSignedManifest(t *testing.T) {
	publicKey, privateKey, err := sharedcrypto.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	restore := setNodeUpdatePublicKey(t, publicKey)
	defer restore()

	payload := []byte("new-node-binary")
	sum := sha256.Sum256(payload)
	manifest := model.NodeReleaseManifest{Version: "v0.2.0", Artifacts: []model.NodeReleaseArtifact{{OS: runtime.GOOS, Arch: runtime.GOARCH, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(payload))}}}
	signature, err := sharedcrypto.SignJSON(privateKey, manifest)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cfg := Config{ControllerURL: "https://monitor.example.test", NodeID: "node-1", NodeToken: strings.Repeat("t", 32), UpdateRequestPath: filepath.Join(dir, "request.json"), UpdateStatusPath: filepath.Join(dir, "status.json")}
	if err := handleUpdateCommand(cfg, model.NodeUpdateCommand{Version: manifest.Version, Manifest: manifest, Signature: signature, SigningKeyID: publicKey}); err != nil {
		t.Fatal(err)
	}
	request, err := loadUpdateRequest(cfg.UpdateRequestPath)
	if err != nil {
		t.Fatal(err)
	}
	if request.TargetVersion != manifest.Version || request.SHA256 != manifest.Artifacts[0].SHA256 {
		t.Fatalf("unexpected update request: %#v", request)
	}
	status, err := loadUpdateStatus(cfg.UpdateStatusPath)
	if err != nil {
		t.Fatal(err)
	}
	if status.Status != model.NodeUpdateRequested {
		t.Fatalf("unexpected update status: %#v", status)
	}

	otherPublicKey, otherPrivateKey, err := sharedcrypto.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	otherSignature, err := sharedcrypto.SignJSON(otherPrivateKey, manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := handleUpdateCommand(cfg, model.NodeUpdateCommand{Version: manifest.Version, Manifest: manifest, Signature: otherSignature, SigningKeyID: otherPublicKey}); err == nil {
		t.Fatal("untrusted update signer was accepted")
	}
}

func TestPerformUpdateVerifiesManifestAndDigest(t *testing.T) {
	publicKey, privateKey, err := sharedcrypto.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	restore := setNodeUpdatePublicKey(t, publicKey)
	defer restore()
	payload := []byte("new-node-binary")
	sum := sha256.Sum256(payload)
	artifact := model.NodeReleaseArtifact{OS: runtime.GOOS, Arch: runtime.GOARCH, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(payload))}
	manifest := model.NodeReleaseManifest{Version: "v0.2.0", Artifacts: []model.NodeReleaseArtifact{artifact}}
	signature, err := sharedcrypto.SignJSON(privateKey, manifest)
	if err != nil {
		t.Fatal(err)
	}
	release := model.SignedNodeRelease{Manifest: manifest, Signature: signature, SigningKeyID: publicKey, UpdateEnabled: true}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/downloads/nyasm-node/manifest":
			_ = json.NewEncoder(w).Encode(release)
		case "/downloads/nyasm-node":
			if r.URL.Query().Get("os") != runtime.GOOS || r.URL.Query().Get("arch") != runtime.GOARCH {
				http.Error(w, "invalid download target", http.StatusBadRequest)
				return
			}
			gz := gzip.NewWriter(w)
			_, _ = gz.Write(payload)
			_ = gz.Close()
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	binaryPath := filepath.Join(t.TempDir(), "nyasm-node")
	if err := os.WriteFile(binaryPath, []byte("old-node-binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	request := model.NodeUpdateRequest{ControllerURL: server.URL, NodeID: "node-1", NodeToken: strings.Repeat("t", 32), TargetVersion: manifest.Version, OS: runtime.GOOS, Arch: runtime.GOARCH, SHA256: artifact.SHA256}
	if err := performUpdate(context.Background(), request, binaryPath); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("updated binary = %q", got)
	}
}

func TestValidateUpdateRequestBindsToNodeConfiguration(t *testing.T) {
	cfg := Config{ControllerURL: "https://monitor.example.test", NodeID: "node-1", NodeToken: strings.Repeat("t", 32)}
	request := model.NodeUpdateRequest{ControllerURL: cfg.ControllerURL, NodeID: cfg.NodeID, NodeToken: cfg.NodeToken, TargetVersion: "v0.2.0", OS: runtime.GOOS, Arch: runtime.GOARCH, SHA256: strings.Repeat("a", sha256.Size*2)}
	if err := validateUpdateRequest(cfg, request); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}
	for name, mutate := range map[string]func(*model.NodeUpdateRequest){
		"controller": func(value *model.NodeUpdateRequest) { value.ControllerURL = "https://attacker.example.test" },
		"node id":    func(value *model.NodeUpdateRequest) { value.NodeID = "node-2" },
		"token":      func(value *model.NodeUpdateRequest) { value.NodeToken = strings.Repeat("x", 32) },
		"platform":   func(value *model.NodeUpdateRequest) { value.Arch = "other" },
		"digest":     func(value *model.NodeUpdateRequest) { value.SHA256 = "not-a-digest" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := request
			mutate(&candidate)
			if err := validateUpdateRequest(cfg, candidate); err == nil {
				t.Fatal("invalid update request was accepted")
			}
		})
	}
}

func setNodeUpdatePublicKey(t *testing.T, value string) func() {
	t.Helper()
	old := sharedversion.UpdatePublicKey
	sharedversion.UpdatePublicKey = value
	return func() { sharedversion.UpdatePublicKey = old }
}
