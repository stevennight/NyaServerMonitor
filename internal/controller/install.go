package controller

import (
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const maxNodeBinaryBytes = 128 << 20

func installScript() string {
	return strings.TrimLeft(`#!/bin/sh
set -eu

controller=""
node_id=""
node_token=""

usage() {
	cat <<'EOF'
Usage: install.sh --controller https://monitor.example.com --id node_x --token node_token
EOF
}

while [ "$#" -gt 0 ]; do
	case "$1" in
		--controller)
			controller="${2:-}"
			shift 2
			;;
		--id|--node-id)
			node_id="${2:-}"
			shift 2
			;;
		--token)
			node_token="${2:-}"
			shift 2
			;;
		-h|--help)
			usage
			exit 0
			;;
		*)
			echo "unknown argument: $1" >&2
			usage >&2
			exit 1
			;;
	esac
done

if [ -z "$controller" ] || [ -z "$node_id" ] || [ -z "$node_token" ]; then
	echo "missing required arguments" >&2
	usage >&2
	exit 1
fi

case "$controller" in
	https://*) ;;
	http://127.0.0.1|http://127.0.0.1:*|http://localhost|http://localhost:*) ;;
	*) echo "controller URL must use HTTPS unless it points to localhost" >&2; exit 1 ;;
esac

if [ "$(id -u)" -ne 0 ]; then
	echo "please run as root" >&2
	exit 1
fi

command -v curl >/dev/null 2>&1 || { echo "curl is required" >&2; exit 1; }
command -v gzip >/dev/null 2>&1 || { echo "gzip is required" >&2; exit 1; }
command -v systemctl >/dev/null 2>&1 || { echo "systemd is required" >&2; exit 1; }
command -v install >/dev/null 2>&1 || { echo "install is required" >&2; exit 1; }

curl_progress=""
if curl --progress-meter --version >/dev/null 2>&1; then
	curl_progress="--progress-meter"
fi

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

os="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$os" in
	linux) os="linux" ;;
	*) echo "unsupported operating system: $os" >&2; exit 1 ;;
esac

arch="$(uname -m)"
case "$arch" in
	x86_64|amd64) arch="amd64" ;;
	aarch64|arm64) arch="arm64" ;;
	*) echo "unsupported architecture: $arch" >&2; exit 1 ;;
esac

binary_url="${controller%/}/downloads/nyasm-node?os=${os}&arch=${arch}&compress=gzip"
echo "[1/6] Downloading nyasm-node for ${os}/${arch}"
curl -fsS $curl_progress --retry 3 --retry-delay 2 --connect-timeout 10 --max-time 120 "$binary_url" -o "$tmpdir/nyasm-node.gz"
echo "[2/6] Decompressing nyasm-node"
gzip -dc "$tmpdir/nyasm-node.gz" > "$tmpdir/nyasm-node"
echo "[3/6] Installing nyasm-node"
install -m 0755 "$tmpdir/nyasm-node" /usr/local/bin/nyasm-node

echo "[4/6] Writing node configuration"
install -d -m 0755 /etc/nyasm
install -d -m 0755 /var/lib/nyasm
if [ ! -e /etc/nyasm/checks.json ]; then
	printf '%s\n' '[]' > /etc/nyasm/checks.json
	chmod 600 /etc/nyasm/checks.json
fi
cat > /etc/nyasm/node.env <<EOF
NYASM_CONTROLLER=$controller
NYASM_NODE_ID=$node_id
NYASM_NODE_TOKEN=$node_token
NYASM_DATA=/var/lib/nyasm
NYASM_CHECKS=/etc/nyasm/checks.json
NYASM_LOG_LEVEL=info
EOF
chmod 600 /etc/nyasm/node.env

echo "[5/6] Installing systemd service"
cat > /etc/systemd/system/nyasm-node.service <<'EOF'
[Unit]
Description=NyaServerMonitor node agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=/etc/nyasm/node.env
ExecStart=/usr/local/bin/nyasm-node
Restart=always
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/nyasm

[Install]
WantedBy=multi-user.target
EOF

echo "[6/6] Starting nyasm-node"
systemctl daemon-reload
systemctl enable nyasm-node
systemctl restart nyasm-node
echo "nyasm node installed"
`, "\n")
}

func installCommand(controllerURL, nodeID, token string) string {
	controllerURL = strings.TrimRight(controllerURL, "/")
	if controllerURL == "" {
		return ""
	}
	return fmt.Sprintf(
		"curl -fsS %s | sudo sh -s -- --controller %s --id %s --token %s",
		shellQuote(installScriptURL(controllerURL)),
		shellQuote(controllerURL),
		shellQuote(nodeID),
		shellQuote(token),
	)
}

func installScriptURL(controllerURL string) string {
	controllerURL = strings.TrimRight(controllerURL, "/")
	if controllerURL == "" {
		return "/install.sh"
	}
	return controllerURL + "/install.sh"
}

func nodeBinaryURL(controllerURL string) string {
	controllerURL = strings.TrimRight(controllerURL, "/")
	if controllerURL == "" {
		return "/downloads/nyasm-node"
	}
	return controllerURL + "/downloads/nyasm-node"
}

func shellQuote(value string) string {
	if value == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func (s *Server) handleInstallScript(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="install.sh"`)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(installScript()))
}

func (s *Server) handleDownloadNodeBinary(w http.ResponseWriter, r *http.Request) {
	path, filename, err := s.nodeBinaryPathForRequest(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		writeError(w, http.StatusNotFound, "node binary is not configured")
		return
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxNodeBinaryBytes {
		writeError(w, http.StatusInternalServerError, "node binary is invalid")
		return
	}
	if r.URL.Query().Get("compress") == "gzip" {
		serveGzippedNodeBinary(w, r, path, filename)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	w.Header().Set("Cache-Control", "no-store")
	http.ServeFile(w, r, path)
}

func (s *Server) nodeBinaryPathForRequest(r *http.Request) (string, string, error) {
	targetOS := strings.TrimSpace(r.URL.Query().Get("os"))
	targetArch := strings.TrimSpace(r.URL.Query().Get("arch"))
	if targetOS == "" && targetArch == "" {
		return configuredNodeBinaryPath(s.cfg), "nyasm-node", nil
	}
	if targetOS == "" || targetArch == "" {
		return "", "", errors.New("node binary os and arch must be provided together")
	}
	targetOS, targetArch, err := normalizeNodeBinaryTarget(targetOS, targetArch)
	if err != nil {
		return "", "", err
	}
	if strings.TrimSpace(s.cfg.NodeBinaryDir) != "" {
		return filepath.Join(filepath.Clean(s.cfg.NodeBinaryDir), fmt.Sprintf("nyasm-node-%s-%s", targetOS, targetArch)), fmt.Sprintf("nyasm-node-%s-%s", targetOS, targetArch), nil
	}
	if strings.TrimSpace(s.cfg.NodeBinaryPath) != "" {
		// An explicit single binary path is an operator assertion that the file
		// matches the requested target, even when the controller runs elsewhere.
		return configuredNodeBinaryPath(s.cfg), fmt.Sprintf("nyasm-node-%s-%s", targetOS, targetArch), nil
	}
	if targetOS != runtime.GOOS || targetArch != runtime.GOARCH {
		return "", "", fmt.Errorf("node binary for %s/%s is not configured", targetOS, targetArch)
	}
	return configuredNodeBinaryPath(s.cfg), fmt.Sprintf("nyasm-node-%s-%s", targetOS, targetArch), nil
}

func configuredNodeBinaryPath(cfg Config) string {
	if path := strings.TrimSpace(cfg.NodeBinaryPath); path != "" {
		return filepath.Clean(path)
	}
	executable, err := os.Executable()
	if err != nil {
		return ""
	}
	directory := filepath.Dir(executable)
	for _, name := range []string{"nyasm-node", "nyasm-node.exe"} {
		path := filepath.Join(directory, name)
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() {
			return path
		}
	}
	return ""
}

func normalizeNodeBinaryTarget(targetOS, targetArch string) (string, string, error) {
	switch strings.ToLower(strings.TrimSpace(targetOS)) {
	case "linux":
		targetOS = "linux"
	default:
		return "", "", fmt.Errorf("unsupported node binary operating system: %s", targetOS)
	}
	switch strings.ToLower(strings.TrimSpace(targetArch)) {
	case "amd64", "x86_64":
		targetArch = "amd64"
	case "arm64", "aarch64":
		targetArch = "arm64"
	default:
		return "", "", fmt.Errorf("unsupported node binary architecture: %s", targetArch)
	}
	return targetOS, targetArch, nil
}

func serveGzippedNodeBinary(w http.ResponseWriter, r *http.Request, path, filename string) {
	file, err := os.Open(path)
	if err != nil {
		writeError(w, http.StatusNotFound, "node binary is not configured")
		return
	}
	defer func() { _ = file.Close() }()
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.gz"`, filename))
	w.Header().Set("Cache-Control", "no-store")
	gz := gzip.NewWriter(w)
	defer func() { _ = gz.Close() }()
	_, _ = io.Copy(gz, file)
}
