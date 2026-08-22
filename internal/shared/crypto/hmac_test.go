package crypto

import "testing"

func TestReportSignatureBindsBodyAndMetadata(t *testing.T) {
	body := []byte(`{"node_id":"node_a"}`)
	sig := ReportSignature("secret", "POST", "/api/agent/v1/report", "1700000000", "nonce", body)
	if !VerifyReportSignature("secret", "POST", "/api/agent/v1/report", "1700000000", "nonce", body, sig) {
		t.Fatal("signature should verify")
	}
	if VerifyReportSignature("secret", "POST", "/api/agent/v1/report", "1700000000", "nonce", []byte(`changed`), sig) {
		t.Fatal("changed body should not verify")
	}
	if VerifyReportSignature("secret", "POST", "/api/agent/v1/report", "1700000001", "nonce", body, sig) {
		t.Fatal("changed timestamp should not verify")
	}
}
