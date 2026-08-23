package controller

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	sharedcrypto "nyaservermonitor/internal/shared/crypto"
	"nyaservermonitor/internal/shared/model"
	sharedversion "nyaservermonitor/internal/shared/version"
)

const nodeReleaseCacheTTL = time.Minute

const (
	maxNodeReleaseManifestBytes = 1 << 20
	maxNodeReleaseMetadataBytes = 16 << 10
	maxNodeReleaseArtifactBytes = 128 << 20
)

const (
	nodeReleaseManifestFilename  = "node-release-manifest.json"
	nodeReleaseSignatureFilename = "node-release-manifest.sig"
	nodeReleasePublicKeyFilename = "node-release-public.key"
)

func (s *Server) nodeRelease() model.SignedNodeRelease {
	s.releaseMu.Lock()
	defer s.releaseMu.Unlock()
	if !s.releaseCachedAt.IsZero() && time.Since(s.releaseCachedAt) < nodeReleaseCacheTTL {
		return s.releaseCache
	}
	release := s.nodeReleaseUncached()
	s.releaseCache = release
	s.releaseCachedAt = time.Now()
	return release
}

func (s *Server) nodeReleaseUncached() model.SignedNodeRelease {
	release := model.SignedNodeRelease{}
	if strings.TrimSpace(s.cfg.NodeBinaryDir) == "" {
		release.DisabledReason = "node release directory is not configured"
		return release
	}
	if strings.TrimSpace(sharedversion.UpdatePublicKey) == "" {
		release.DisabledReason = "node update public key is not configured"
		return release
	}
	manifest, err := readNodeReleaseManifest(filepath.Join(s.cfg.NodeBinaryDir, nodeReleaseManifestFilename))
	if err != nil {
		release.DisabledReason = err.Error()
		return release
	}
	release.Manifest = manifest
	release.Signature, err = readTrimmedReleaseFile(filepath.Join(s.cfg.NodeBinaryDir, nodeReleaseSignatureFilename), "node release signature is not bundled")
	if err != nil {
		release.DisabledReason = err.Error()
		return release
	}
	release.SigningKeyID, err = readTrimmedReleaseFile(filepath.Join(s.cfg.NodeBinaryDir, nodeReleasePublicKeyFilename), "node release public key is not bundled")
	if err != nil {
		release.DisabledReason = err.Error()
		return release
	}
	if release.SigningKeyID != sharedversion.UpdatePublicKey {
		release.DisabledReason = "node release signing key does not match trusted key"
		return release
	}
	if err := sharedcrypto.VerifyJSON(sharedversion.UpdatePublicKey, manifest, release.Signature); err != nil {
		release.DisabledReason = "node release manifest signature is invalid"
		return release
	}
	if err := verifyNodeReleaseArtifacts(s.cfg.NodeBinaryDir, manifest); err != nil {
		release.DisabledReason = err.Error()
		return release
	}
	release.UpdateEnabled = true
	return release
}

func readNodeReleaseManifest(path string) (model.NodeReleaseManifest, error) {
	payload, err := readNodeReleaseFile(path, maxNodeReleaseManifestBytes)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return model.NodeReleaseManifest{}, errors.New("node release manifest is not bundled")
		}
		return model.NodeReleaseManifest{}, err
	}
	var manifest model.NodeReleaseManifest
	if err := json.Unmarshal(payload, &manifest); err != nil {
		return model.NodeReleaseManifest{}, fmt.Errorf("read node release manifest: %w", err)
	}
	if manifest.Version == "" || len(manifest.Artifacts) == 0 {
		return model.NodeReleaseManifest{}, errors.New("node release manifest is incomplete")
	}
	return manifest, nil
}

func verifyNodeReleaseArtifacts(directory string, manifest model.NodeReleaseManifest) error {
	seen := make(map[string]struct{}, len(manifest.Artifacts))
	for _, artifact := range manifest.Artifacts {
		osName, arch, err := normalizeNodeBinaryTarget(artifact.OS, artifact.Arch)
		if err != nil || osName != artifact.OS || arch != artifact.Arch {
			return fmt.Errorf("node release artifact %s/%s has invalid target", artifact.OS, artifact.Arch)
		}
		key := artifact.OS + "/" + artifact.Arch
		if _, ok := seen[key]; ok {
			return fmt.Errorf("node release artifact %s/%s is duplicated", artifact.OS, artifact.Arch)
		}
		seen[key] = struct{}{}
		if artifact.Size <= 0 || artifact.Size > maxNodeReleaseArtifactBytes || len(artifact.SHA256) != sha256.Size*2 {
			return fmt.Errorf("node release artifact %s/%s is invalid", artifact.OS, artifact.Arch)
		}
		if _, err := hex.DecodeString(artifact.SHA256); err != nil {
			return fmt.Errorf("node release artifact %s/%s has invalid digest", artifact.OS, artifact.Arch)
		}
		path := filepath.Join(directory, fmt.Sprintf("nyasm-node-%s-%s", artifact.OS, artifact.Arch))
		actual, err := hashReleaseArtifact(path)
		if err != nil || actual.Size != artifact.Size || !strings.EqualFold(actual.SHA256, artifact.SHA256) {
			return fmt.Errorf("node release artifact %s/%s does not match manifest", artifact.OS, artifact.Arch)
		}
	}
	return nil
}

func hashReleaseArtifact(path string) (model.NodeReleaseArtifact, error) {
	file, err := os.Open(path)
	if err != nil {
		return model.NodeReleaseArtifact{}, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxNodeReleaseArtifactBytes {
		return model.NodeReleaseArtifact{}, errors.New("invalid node release artifact")
	}
	hash := sha256.New()
	readBytes, err := io.Copy(hash, io.LimitReader(file, maxNodeReleaseArtifactBytes+1))
	if err != nil || readBytes != info.Size() {
		return model.NodeReleaseArtifact{}, errors.New("unable to hash node release artifact")
	}
	return model.NodeReleaseArtifact{OS: "linux", Arch: "", SHA256: hex.EncodeToString(hash.Sum(nil)), Size: readBytes}, nil
}

func readTrimmedReleaseFile(path, missingMessage string) (string, error) {
	payload, err := readNodeReleaseFile(path, maxNodeReleaseMetadataBytes)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", errors.New(missingMessage)
		}
		return "", err
	}
	return strings.TrimSpace(string(payload)), nil
}

func readNodeReleaseFile(path string, maxBytes int64) ([]byte, error) {
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
		return nil, errors.New("node release metadata is too large")
	}
	return payload, nil
}

func (s *Server) handleDownloadNodeReleaseManifest(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	release := s.nodeRelease()
	if !release.UpdateEnabled {
		release.DisabledReason = "node release is unavailable"
	}
	writeJSON(w, http.StatusOK, release)
}

func (s *Server) handleDownloadNodeBinarySignature(w http.ResponseWriter, r *http.Request) {
	osName, arch, err := normalizeNodeBinaryTarget(r.URL.Query().Get("os"), r.URL.Query().Get("arch"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if strings.TrimSpace(s.cfg.NodeBinaryDir) == "" {
		writeError(w, http.StatusNotFound, "node binary signature is not configured")
		return
	}
	filename := fmt.Sprintf("nyasm-node-%s-%s.sig", osName, arch)
	payload, err := readTrimmedReleaseFile(filepath.Join(s.cfg.NodeBinaryDir, filename), "node binary signature is not configured")
	if err != nil {
		writeError(w, http.StatusNotFound, "node binary signature is not configured")
		return
	}
	signature, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil || len(signature) != ed25519.SignatureSize {
		writeError(w, http.StatusNotFound, "node binary signature is invalid")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(signature)
}
