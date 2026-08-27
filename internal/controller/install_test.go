package controller

import (
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"nyaservermonitor/internal/controller/store"
)

func TestInstallScriptInstallsAndRestartsNodeService(t *testing.T) {
	script := installScript()
	for _, required := range []string{
		"controller URL must use HTTPS unless it points to localhost",
		"chmod 600 /etc/nyasm/node.env",
		"command -v sha256sum",
		"digest_line=\"$(sha256sum \"$tmpdir/nyasm-node\")\"",
		"format=sha256",
		"-in \"$tmpdir/nyasm-node.digest\" -sigfile \"$tmpdir/nyasm-node.sha256.sig\"",
		"systemd-detect-virt --container",
		"filesystem_sandbox='ProtectSystem=strict\nProtectHome=true\nPrivateTmp=true'",
		"filesystem_sandbox='ProtectSystem=off\nProtectHome=false\nPrivateTmp=false'",
		"Detected container runtime",
		"NoNewPrivileges=true",
		"ProtectSystem=strict",
		"ProtectHome=true",
		"PrivateTmp=true",
		"ReadWritePaths=/var/lib/nyasm",
		"pkeyutl_help=\"$(openssl pkeyutl -help 2>&1 || true)\"",
		"*-rawin*)",
		"command -v python3",
		"dependency-free",
		"Ed25519 verification failed",
		"systemctl daemon-reload\nsystemctl enable nyasm-node\nsystemctl restart nyasm-node",
	} {
		if !strings.Contains(script, required) {
			t.Fatalf("install script is missing %q:\n%s", required, script)
		}
	}
	if strings.Contains(script, "-in \"$tmpdir/nyasm-node\" -sigfile") {
		t.Fatal("installer must verify the signed digest instead of the full binary")
	}
	if strings.Contains(script, "systemctl enable --now nyasm-node") {
		t.Fatal("installer must restart an existing node so a rotated token is loaded")
	}
}

func TestInstallScriptIsValidPOSIXShell(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell syntax test is not run on Windows")
	}
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh is not installed")
	}
	command := exec.Command(sh, "-n")
	command.Stdin = strings.NewReader(installScript())
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("generated install script is invalid: %v\n%s", err, output)
	}
}

func TestInstallScriptPythonEd25519Fallback(t *testing.T) {
	python := ""
	for _, candidate := range []string{"python3", "python"} {
		candidatePath, err := exec.LookPath(candidate)
		if err == nil && exec.Command(candidatePath, "--version").Run() == nil {
			python = candidatePath
			break
		}
	}
	if python == "" {
		t.Skip("python3 is not installed or runnable")
	}

	script := installScript()
	marker := "python3 - \"$public_key_path\" \"$tmpdir/nyasm-node.digest\" \"$tmpdir/nyasm-node.sha256.sig\" <<'PY'\n"
	start := strings.Index(script, marker)
	if start < 0 {
		t.Fatal("python fallback is missing from install script")
	}
	pythonSourceStart := start + len(marker)
	end := strings.Index(script[pythonSourceStart:], "\nPY\n")
	if end < 0 {
		t.Fatal("python fallback heredoc is not terminated")
	}
	pythonSource := script[pythonSourceStart : pythonSourceStart+end]

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	digest := []byte(strings.Repeat("a", 64))
	signature := ed25519.Sign(privateKey, digest)
	dir := t.TempDir()
	publicPath := filepath.Join(dir, "public.pem")
	digestPath := filepath.Join(dir, "digest")
	signaturePath := filepath.Join(dir, "signature")
	if err := os.WriteFile(publicPath, publicPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(digestPath, digest, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(signaturePath, signature, 0o600); err != nil {
		t.Fatal(err)
	}

	runVerifier := func() ([]byte, error) {
		command := exec.Command(python, "-", publicPath, digestPath, signaturePath)
		command.Stdin = strings.NewReader(pythonSource)
		return command.CombinedOutput()
	}
	output, err := runVerifier()
	if err != nil {
		t.Fatalf("python Ed25519 fallback failed: %v\n%s", err, output)
	}
	signature[0] ^= 1
	if err := os.WriteFile(signaturePath, signature, 0o600); err != nil {
		t.Fatal(err)
	}
	if output, err := runVerifier(); err == nil {
		t.Fatalf("python Ed25519 fallback accepted a modified signature:\n%s", output)
	}
}

func TestInstallCommandShellQuotesArguments(t *testing.T) {
	controllerURL := "https://monitor.example.test/base"
	nodeID := "node'; touch /tmp/nyasm-pwned; #"
	token := "token'; touch /tmp/nyasm-token; #"
	got := installCommand(controllerURL, nodeID, token)
	want := "curl -fsS " + shellQuote(installScriptURL(controllerURL)) +
		" | sudo sh -s -- --controller " + shellQuote(controllerURL) +
		" --id " + shellQuote(nodeID) + " --token " + shellQuote(token)
	if got != want {
		t.Fatalf("install command = %q, want %q", got, want)
	}
	if got == "" || !strings.Contains(got, "'\"'\"'") {
		t.Fatalf("install command did not shell-quote apostrophes: %q", got)
	}
	if installCommand("", "node", token) != "" {
		t.Fatal("empty controller URL should not produce an install command")
	}
}

func TestInstallEndpointsArePublicButDoNotContainToken(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	const token = "secret-node-token-that-must-not-be-public"
	binaryPath := filepath.Join(t.TempDir(), "nyasm-node")
	if err := os.WriteFile(binaryPath, []byte("node-binary-without-credentials"), 0o755); err != nil {
		t.Fatal(err)
	}
	s := NewServer(Config{
		PublicURL:        "https://monitor.example.test",
		NodeBinaryPath:   binaryPath,
		SessionLifetime:  time.Hour,
		OfflineAfter:     time.Minute,
		CleanupInterval:  time.Minute,
		MetricsRetention: time.Hour,
	}, st)

	installRequest := httptest.NewRequest(http.MethodGet, "/install.sh", nil)
	installResponse := httptest.NewRecorder()
	s.mux.ServeHTTP(installResponse, installRequest)
	if installResponse.Code != http.StatusOK {
		t.Fatalf("install script status: %d %s", installResponse.Code, installResponse.Body.String())
	}
	if strings.Contains(installResponse.Body.String(), token) {
		t.Fatalf("public install script leaked token: %s", installResponse.Body.String())
	}
	if got := installResponse.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("install script cache policy = %q", got)
	}

	binaryRequest := httptest.NewRequest(http.MethodGet, "/downloads/nyasm-node", nil)
	binaryResponse := httptest.NewRecorder()
	s.mux.ServeHTTP(binaryResponse, binaryRequest)
	if binaryResponse.Code != http.StatusOK {
		t.Fatalf("binary status: %d %s", binaryResponse.Code, binaryResponse.Body.String())
	}
	if strings.Contains(binaryResponse.Body.String(), token) {
		t.Fatalf("public binary response leaked token")
	}
	if got := binaryResponse.Body.String(); got != "node-binary-without-credentials" {
		t.Fatalf("binary body = %q", got)
	}
}

func TestDownloadNodeBinaryCanStreamGzip(t *testing.T) {
	dir := t.TempDir()
	content := []byte("nyasm-node-binary")
	path := filepath.Join(dir, "nyasm-node-linux-amd64")
	if err := os.WriteFile(path, content, 0o755); err != nil {
		t.Fatal(err)
	}
	s := &Server{cfg: Config{NodeBinaryDir: dir}}
	request := httptest.NewRequest(http.MethodGet, "/downloads/nyasm-node?os=linux&arch=x86_64&compress=gzip", nil)
	response := httptest.NewRecorder()
	s.handleDownloadNodeBinary(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("gzip download status: %d %s", response.Code, response.Body.String())
	}
	if got := response.Header().Get("Content-Type"); got != "application/gzip" {
		t.Fatalf("gzip content type = %q", got)
	}
	reader, err := gzip.NewReader(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reader.Close() }()
	decoded, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if string(decoded) != string(content) {
		t.Fatalf("decoded binary = %q, want %q", decoded, content)
	}
}

func TestDownloadNodeBinarySignatureSupportsSHA256Format(t *testing.T) {
	dir := t.TempDir()
	rawSignature := make([]byte, ed25519.SignatureSize)
	encodedSignature := base64.RawURLEncoding.EncodeToString(rawSignature)
	path := filepath.Join(dir, "nyasm-node-linux-amd64.sha256.sig")
	if err := os.WriteFile(path, []byte(encodedSignature), 0o600); err != nil {
		t.Fatal(err)
	}
	s := &Server{cfg: Config{NodeBinaryDir: dir}}
	request := httptest.NewRequest(http.MethodGet, "/downloads/nyasm-node/signature?os=linux&arch=amd64&format=sha256", nil)
	response := httptest.NewRecorder()
	s.handleDownloadNodeBinarySignature(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("digest signature status: %d %s", response.Code, response.Body.String())
	}
	if got := response.Body.Bytes(); string(got) != string(rawSignature) {
		t.Fatalf("digest signature body does not match: %x", got)
	}
	if got := response.Header().Get("Content-Disposition"); !strings.Contains(got, ".sha256.sig") {
		t.Fatalf("digest signature filename = %q", got)
	}
}

func TestNodeBinaryPathForRequestAllowsExplicitCrossPlatformBinary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nyasm-node-linux-amd64")
	s := &Server{cfg: Config{NodeBinaryPath: path}}
	request := httptest.NewRequest(http.MethodGet, "/downloads/nyasm-node?os=linux&arch=amd64", nil)

	gotPath, gotName, err := s.nodeBinaryPathForRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != path || gotName != "nyasm-node-linux-amd64" {
		t.Fatalf("binary target = %q, %q", gotPath, gotName)
	}
}

func TestCreateNodeResponseIncludesOneTimeInstaller(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	s := NewServer(Config{
		PublicURL:        "https://monitor.example.test/",
		SessionLifetime:  time.Hour,
		OfflineAfter:     time.Minute,
		CleanupInterval:  time.Minute,
		MetricsRetention: time.Hour,
	}, st)

	setupRequest := httptest.NewRequest(http.MethodPost, "/api/setup", strings.NewReader(`{"username":"admin","password":"correct-horse-battery-staple"}`))
	setupRequest.Header.Set("Content-Type", "application/json")
	setupResponse := httptest.NewRecorder()
	s.mux.ServeHTTP(setupResponse, setupRequest)
	if setupResponse.Code != http.StatusCreated {
		t.Fatalf("setup status: %d %s", setupResponse.Code, setupResponse.Body.String())
	}
	cookies := setupResponse.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("setup returned %d cookies", len(cookies))
	}

	createRequest := httptest.NewRequest(http.MethodPost, "/api/nodes", strings.NewReader(`{"name":"installer test"}`))
	createRequest.Header.Set("Content-Type", "application/json")
	createRequest.AddCookie(cookies[0])
	createResponse := httptest.NewRecorder()
	s.mux.ServeHTTP(createResponse, createRequest)
	if createResponse.Code != http.StatusCreated {
		t.Fatalf("create status: %d %s", createResponse.Code, createResponse.Body.String())
	}
	var credential nodeCredential
	if err := json.Unmarshal(createResponse.Body.Bytes(), &credential); err != nil {
		t.Fatal(err)
	}
	if credential.Token == "" || credential.InstallCommand == "" || credential.InstallScriptURL != "https://monitor.example.test/install.sh" || credential.BinaryURL != "https://monitor.example.test/downloads/nyasm-node" {
		t.Fatalf("missing installer fields: %#v", credential)
	}
	if !strings.Contains(credential.InstallCommand, shellQuote(credential.Token)) {
		t.Fatalf("install command does not contain the one-time token: %q", credential.InstallCommand)
	}
	if !strings.Contains(credential.Env, credential.Token) {
		t.Fatalf("environment file does not contain the one-time token")
	}
	if strings.Contains(credential.InstallScriptURL, credential.Token) || strings.Contains(credential.BinaryURL, credential.Token) {
		t.Fatal("download URLs must not contain the node token")
	}
}
