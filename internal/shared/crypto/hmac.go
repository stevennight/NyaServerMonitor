package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// ReportSignature binds the request metadata and body to a node-only secret.
// The controller never sends a value signed with this secret back to a node.
func ReportSignature(secret, method, path, timestamp, nonce string, body []byte) string {
	bodyHash := sha256.Sum256(body)
	canonical := strings.Join([]string{
		strings.ToUpper(method),
		path,
		timestamp,
		nonce,
		hex.EncodeToString(bodyHash[:]),
	}, "\n")
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(canonical))
	return hex.EncodeToString(mac.Sum(nil))
}

func VerifyReportSignature(secret, method, path, timestamp, nonce string, body []byte, got string) bool {
	want := ReportSignature(secret, method, path, timestamp, nonce, body)
	return hmac.Equal([]byte(strings.ToLower(strings.TrimSpace(got))), []byte(want))
}

func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
