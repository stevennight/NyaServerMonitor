package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	sharedcrypto "nyaservermonitor/internal/shared/crypto"
	"nyaservermonitor/internal/shared/model"
)

func main() {
	var nodeDir, version, commit, buildDate, privateKeyFile, expectedPublicKey, manifestPath, signaturePath, publicKeyPath, githubOutput string
	flag.StringVar(&nodeDir, "node-dir", "dist", "directory containing node binaries")
	flag.StringVar(&version, "version", "", "release version")
	flag.StringVar(&commit, "commit", "", "git commit")
	flag.StringVar(&buildDate, "build-date", "", "build date")
	flag.StringVar(&privateKeyFile, "private-key-file", "", "base64url Ed25519 private key file")
	flag.StringVar(&expectedPublicKey, "expected-public-key", "", "expected base64url Ed25519 public key")
	flag.StringVar(&manifestPath, "manifest", "", "manifest output path")
	flag.StringVar(&signaturePath, "signature", "", "manifest signature output path")
	flag.StringVar(&publicKeyPath, "public-key", "", "public key output path")
	flag.StringVar(&githubOutput, "github-output", "", "GitHub Actions output file")
	flag.Parse()
	if version == "" {
		fatal("version is required")
	}

	manifest := model.NodeReleaseManifest{Version: version, Commit: commit, BuildDate: buildDate}
	var binaries [][]byte
	for _, target := range []struct{ os, arch string }{{"linux", "amd64"}, {"linux", "arm64"}} {
		path := filepath.Join(nodeDir, fmt.Sprintf("nyasm-node-%s-%s", target.os, target.arch))
		payload, err := os.ReadFile(path)
		if err != nil {
			fatal(err.Error())
		}
		sum := sha256.Sum256(payload)
		manifest.Artifacts = append(manifest.Artifacts, model.NodeReleaseArtifact{OS: target.os, Arch: target.arch, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(payload))})
		binaries = append(binaries, payload)
	}
	if manifestPath != "" {
		writeJSON(manifestPath, manifest)
	}

	privateKey := ""
	if privateKeyFile != "" {
		payload, err := os.ReadFile(privateKeyFile)
		if err != nil {
			fatal(err.Error())
		}
		privateKey = compact(string(payload))
	}
	expectedPublicKey = compact(expectedPublicKey)
	if (privateKey == "") != (expectedPublicKey == "") {
		fatal("update signing private key and public key must be configured together")
	}
	var signature, publicKey string
	if privateKey != "" {
		private, err := sharedcrypto.DecodePrivateKey(privateKey)
		if err != nil {
			fatal(err.Error())
		}
		public, ok := private.Public().(ed25519.PublicKey)
		if !ok {
			fatal("invalid Ed25519 private key")
		}
		publicKey = sharedcrypto.EncodeKey(public)
		if publicKey != expectedPublicKey {
			fatal("update signing private key does not match update public key")
		}
		signature, err = sharedcrypto.SignJSON(privateKey, manifest)
		if err != nil {
			fatal(err.Error())
		}
		for index, artifact := range manifest.Artifacts {
			artifactSignature, err := sharedcrypto.SignBytes(privateKey, binaries[index])
			if err != nil {
				fatal(err.Error())
			}
			writeText(filepath.Join(nodeDir, fmt.Sprintf("nyasm-node-%s-%s.sig", artifact.OS, artifact.Arch)), artifactSignature+"\n")
			digestSignature, err := signNodeArtifactDigest(privateKey, artifact)
			if err != nil {
				fatal(err.Error())
			}
			writeText(filepath.Join(nodeDir, fmt.Sprintf("nyasm-node-%s-%s.sha256.sig", artifact.OS, artifact.Arch)), digestSignature+"\n")
		}
		if signaturePath != "" {
			writeText(signaturePath, signature+"\n")
		}
		if publicKeyPath != "" {
			writeText(publicKeyPath, publicKey+"\n")
		}
	}
	if githubOutput != "" {
		appendText(githubOutput, fmt.Sprintf("signature=%s\npublic_key=%s\n", signature, publicKey))
	}
}

func signNodeArtifactDigest(privateKey string, artifact model.NodeReleaseArtifact) (string, error) {
	// Sign the fixed-length digest text so OpenSSL 1.1.1 can verify it.
	return sharedcrypto.SignBytes(privateKey, []byte(artifact.SHA256))
}

func compact(value string) string { return strings.Join(strings.Fields(value), "") }

func writeJSON(path string, value any) {
	payload, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		fatal(err.Error())
	}
	writeText(path, string(payload)+"\n")
}

func writeText(path, value string) {
	if err := os.WriteFile(path, []byte(value), 0o644); err != nil {
		fatal(err.Error())
	}
}

func appendText(path, value string) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		fatal(err.Error())
	}
	defer file.Close()
	if _, err := file.WriteString(value); err != nil {
		fatal(err.Error())
	}
}

func fatal(message string) {
	_, _ = fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}
