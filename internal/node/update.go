package node

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	sharedcrypto "nyaservermonitor/internal/shared/crypto"
	"nyaservermonitor/internal/shared/model"
	sharedversion "nyaservermonitor/internal/shared/version"
)

const defaultNodeBinaryPath = "/usr/local/bin/nyasm-node"

const (
	maxNodeBinaryBytes    = 128 << 20
	maxControllerJSONSize = 1 << 20
	maxUpdateVersionBytes = 128
	maxUpdateURLBytes     = 2048
)

var updateHTTPClient = &http.Client{
	Timeout: 30 * time.Second,
	CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

func handleUpdateCommand(cfg Config, command model.NodeUpdateCommand) error {
	if strings.TrimSpace(sharedversion.UpdatePublicKey) == "" {
		return errors.New("node update public key is not configured")
	}
	if strings.TrimSpace(command.Version) == "" || command.Manifest.Version != command.Version {
		return errors.New("update command version does not match its signed manifest")
	}
	if command.SigningKeyID != sharedversion.UpdatePublicKey {
		return errors.New("update signing key does not match trusted key")
	}
	if err := sharedcrypto.VerifyJSON(sharedversion.UpdatePublicKey, command.Manifest, command.Signature); err != nil {
		return fmt.Errorf("verify update manifest: %w", err)
	}
	artifact, ok := findUpdateArtifact(command.Manifest, runtime.GOOS, runtime.GOARCH)
	if !ok {
		return fmt.Errorf("no update artifact for %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	if err := validateUpdateArtifact(artifact); err != nil {
		return err
	}
	if !sharedversion.NeedsUpdate(sharedversion.Version, command.Version) {
		return nil
	}
	if err := saveUpdateStatus(cfg.UpdateStatusPath, model.NodeUpdateReport{Status: model.NodeUpdateRequested, Version: command.Version}); err != nil {
		return err
	}
	return writeUpdateRequest(cfg.UpdateRequestPath, model.NodeUpdateRequest{
		ControllerURL: cfg.ControllerURL,
		NodeID:        cfg.NodeID,
		NodeToken:     cfg.NodeToken,
		TargetVersion: command.Version,
		OS:            runtime.GOOS,
		Arch:          runtime.GOARCH,
		SHA256:        artifact.SHA256,
		RequestedAt:   time.Now().UTC(),
	})
}

func findUpdateArtifact(manifest model.NodeReleaseManifest, targetOS, targetArch string) (model.NodeReleaseArtifact, bool) {
	var found model.NodeReleaseArtifact
	foundValue := false
	for _, artifact := range manifest.Artifacts {
		if artifact.OS == targetOS && artifact.Arch == targetArch {
			if foundValue {
				return model.NodeReleaseArtifact{}, false
			}
			found = artifact
			foundValue = true
		}
	}
	return found, foundValue
}

func validateUpdateArtifact(artifact model.NodeReleaseArtifact) error {
	if artifact.OS != runtime.GOOS || artifact.Arch != runtime.GOARCH {
		return fmt.Errorf("update target platform %s/%s does not match local platform %s/%s", artifact.OS, artifact.Arch, runtime.GOOS, runtime.GOARCH)
	}
	if artifact.Size <= 0 || artifact.Size > maxNodeBinaryBytes {
		return errors.New("node release artifact size is invalid")
	}
	if len(artifact.SHA256) != sha256.Size*2 {
		return errors.New("node release artifact digest is invalid")
	}
	if _, err := hex.DecodeString(artifact.SHA256); err != nil {
		return errors.New("node release artifact digest is invalid")
	}
	return nil
}

func writeUpdateRequest(path string, request model.NodeUpdateRequest) error {
	if strings.TrimSpace(request.TargetVersion) == "" {
		return errors.New("update target version is required")
	}
	payload, err := json.MarshalIndent(request, "", "  ")
	if err != nil {
		return err
	}
	return writePrivateFileAtomic(path, payload)
}

func loadUpdateRequest(path string) (model.NodeUpdateRequest, error) {
	payload, err := readFileLimited(path, maxControllerJSONSize)
	if err != nil {
		return model.NodeUpdateRequest{}, err
	}
	var request model.NodeUpdateRequest
	if err := json.Unmarshal(payload, &request); err != nil {
		return model.NodeUpdateRequest{}, err
	}
	return request, nil
}

func saveUpdateStatus(path string, report model.NodeUpdateReport) error {
	if report.CompletedAt.IsZero() && (report.Status == model.NodeUpdateSucceeded || report.Status == model.NodeUpdateFailed) {
		report.CompletedAt = time.Now().UTC()
	}
	payload, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	return writePrivateFileAtomic(path, payload)
}

func loadUpdateStatus(path string) (model.NodeUpdateReport, error) {
	payload, err := readFileLimited(path, maxControllerJSONSize)
	if err != nil {
		return model.NodeUpdateReport{}, err
	}
	var report model.NodeUpdateReport
	if err := json.Unmarshal(payload, &report); err != nil {
		return model.NodeUpdateReport{}, err
	}
	return report, nil
}

func runUpdate(ctx context.Context, cfg Config) error {
	request, err := loadUpdateRequest(cfg.UpdateRequestPath)
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(cfg.UpdateRequestPath) }()
	if err := validateUpdateRequest(cfg, request); err != nil {
		_ = saveUpdateStatus(cfg.UpdateStatusPath, model.NodeUpdateReport{Status: model.NodeUpdateFailed, Version: request.TargetVersion, Error: err.Error()})
		return err
	}
	if err := saveUpdateStatus(cfg.UpdateStatusPath, model.NodeUpdateReport{Status: model.NodeUpdateRunning, Version: request.TargetVersion}); err != nil {
		return err
	}
	if err := performUpdate(ctx, request, cfg.NodeBinaryPath); err != nil {
		_ = saveUpdateStatus(cfg.UpdateStatusPath, model.NodeUpdateReport{Status: model.NodeUpdateFailed, Version: request.TargetVersion, Error: err.Error()})
		return err
	}
	return saveUpdateStatus(cfg.UpdateStatusPath, model.NodeUpdateReport{Status: model.NodeUpdateSucceeded, Version: request.TargetVersion})
}

func validateUpdateRequest(cfg Config, request model.NodeUpdateRequest) error {
	if strings.TrimSpace(request.TargetVersion) == "" || len(request.TargetVersion) > maxUpdateVersionBytes {
		return errors.New("update target version is invalid")
	}
	if !sharedversion.NeedsUpdate(sharedversion.Version, request.TargetVersion) {
		return errors.New("update target version is not newer than the installed version")
	}
	if len(request.ControllerURL) > maxUpdateURLBytes || !sameControllerURL(request.ControllerURL, cfg.ControllerURL) {
		return errors.New("update controller does not match node configuration")
	}
	if request.NodeID == "" || request.NodeID != cfg.NodeID {
		return errors.New("update node id does not match node configuration")
	}
	if request.NodeToken == "" || request.NodeToken != cfg.NodeToken {
		return errors.New("update node token does not match node configuration")
	}
	if request.OS != runtime.GOOS || request.Arch != runtime.GOARCH {
		return fmt.Errorf("update target platform %s/%s does not match local platform %s/%s", request.OS, request.Arch, runtime.GOOS, runtime.GOARCH)
	}
	if len(request.SHA256) != sha256.Size*2 {
		return errors.New("update artifact digest is invalid")
	}
	if _, err := hex.DecodeString(request.SHA256); err != nil {
		return errors.New("update artifact digest is invalid")
	}
	return nil
}

func sameControllerURL(left, right string) bool {
	leftURL, leftErr := validateControllerURL(left)
	rightURL, rightErr := validateControllerURL(right)
	return leftErr == nil && rightErr == nil && leftURL.String() == rightURL.String()
}

func performUpdate(ctx context.Context, request model.NodeUpdateRequest, binaryPath string) error {
	release, err := fetchNodeRelease(ctx, request)
	if err != nil {
		return err
	}
	if !release.UpdateEnabled {
		return errors.New("node release is unavailable")
	}
	if release.SigningKeyID != sharedversion.UpdatePublicKey {
		return errors.New("release signing key does not match trusted key")
	}
	if release.Manifest.Version != request.TargetVersion {
		return fmt.Errorf("release version %s does not match requested %s", release.Manifest.Version, request.TargetVersion)
	}
	if err := sharedcrypto.VerifyJSON(sharedversion.UpdatePublicKey, release.Manifest, release.Signature); err != nil {
		return fmt.Errorf("verify release manifest: %w", err)
	}
	artifact, ok := findUpdateArtifact(release.Manifest, request.OS, request.Arch)
	if !ok {
		return fmt.Errorf("no artifact for %s/%s", request.OS, request.Arch)
	}
	if err := validateUpdateArtifact(artifact); err != nil {
		return err
	}
	if !strings.EqualFold(request.SHA256, artifact.SHA256) {
		return errors.New("requested artifact digest does not match release manifest")
	}
	payload, err := downloadUpdateBinary(ctx, request)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(payload)
	if !strings.EqualFold(hex.EncodeToString(sum[:]), artifact.SHA256) {
		return errors.New("downloaded node binary sha256 mismatch")
	}
	if int64(len(payload)) != artifact.Size {
		return fmt.Errorf("downloaded node binary size %d does not match manifest size %d", len(payload), artifact.Size)
	}
	return replaceBinary(binaryPath, payload)
}

func fetchNodeRelease(ctx context.Context, request model.NodeUpdateRequest) (model.SignedNodeRelease, error) {
	var release model.SignedNodeRelease
	if err := doUpdateJSON(ctx, request, http.MethodGet, "/downloads/nyasm-node/manifest", &release); err != nil {
		return model.SignedNodeRelease{}, err
	}
	return release, nil
}

func downloadUpdateBinary(ctx context.Context, request model.NodeUpdateRequest) ([]byte, error) {
	path := fmt.Sprintf("/downloads/nyasm-node?os=%s&arch=%s&compress=gzip", request.OS, request.Arch)
	httpRequest, err := newUpdateRequest(ctx, request, http.MethodGet, path)
	if err != nil {
		return nil, err
	}
	response, err := updateHTTPClient.Do(httpRequest)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode >= 300 {
		return nil, fmt.Errorf("download node binary failed: %s", response.Status)
	}
	if response.ContentLength > maxNodeBinaryBytes {
		return nil, errors.New("compressed node binary is too large")
	}
	reader, err := gzip.NewReader(response.Body)
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	payload, err := io.ReadAll(io.LimitReader(reader, maxNodeBinaryBytes+1))
	if err != nil {
		return nil, err
	}
	if len(payload) > maxNodeBinaryBytes {
		return nil, errors.New("downloaded node binary is too large")
	}
	return payload, nil
}

func doUpdateJSON(ctx context.Context, request model.NodeUpdateRequest, method, path string, destination any) error {
	httpRequest, err := newUpdateRequest(ctx, request, method, path)
	if err != nil {
		return err
	}
	response, err := updateHTTPClient.Do(httpRequest)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode >= 300 {
		return fmt.Errorf("controller request failed: %s", response.Status)
	}
	return json.NewDecoder(io.LimitReader(response.Body, maxControllerJSONSize)).Decode(destination)
}

func newUpdateRequest(ctx context.Context, request model.NodeUpdateRequest, method, path string) (*http.Request, error) {
	base, err := validateControllerURL(request.ControllerURL)
	if err != nil {
		return nil, err
	}
	parsedPath, err := url.Parse(path)
	if err != nil || parsedPath.IsAbs() || parsedPath.Host != "" || !strings.HasPrefix(parsedPath.Path, "/") || strings.ContainsAny(path, "\r\n") {
		return nil, errors.New("invalid controller request path")
	}
	base.Path = parsedPath.Path
	base.RawPath = parsedPath.RawPath
	base.RawQuery = parsedPath.RawQuery
	httpRequest, err := http.NewRequestWithContext(ctx, method, base.String(), nil)
	if err != nil {
		return nil, err
	}
	httpRequest.Header.Set("X-NyaSM-Node-ID", request.NodeID)
	httpRequest.Header.Set("X-NyaSM-Node-Token", request.NodeToken)
	return httpRequest, nil
}

func replaceBinary(path string, payload []byte) error {
	if path == "" || !filepath.IsAbs(path) {
		return errors.New("node binary path must be absolute")
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".nyasm-node-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	if _, err := temporary.Write(payload); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Chmod(0o755); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}

func readFileLimited(path string, maxBytes int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	payload, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(payload)) > maxBytes {
		return nil, errors.New("update file is too large")
	}
	return payload, nil
}

func writePrivateFileAtomic(path string, payload []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".nyasm-private-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(payload); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}
