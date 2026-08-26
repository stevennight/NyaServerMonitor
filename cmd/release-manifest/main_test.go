package main

import (
	"testing"

	sharedcrypto "nyaservermonitor/internal/shared/crypto"
	"nyaservermonitor/internal/shared/model"
)

func TestSignNodeArtifactDigestSignsDigestText(t *testing.T) {
	publicKey, privateKey, err := sharedcrypto.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	artifact := model.NodeReleaseArtifact{SHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}
	signature, err := signNodeArtifactDigest(privateKey, artifact)
	if err != nil {
		t.Fatal(err)
	}
	if err := sharedcrypto.VerifyBytes(publicKey, []byte(artifact.SHA256), signature); err != nil {
		t.Fatalf("digest signature did not verify: %v", err)
	}
	if err := sharedcrypto.VerifyBytes(publicKey, []byte("node-binary"), signature); err == nil {
		t.Fatal("digest signature verified an unrelated payload")
	}
}
