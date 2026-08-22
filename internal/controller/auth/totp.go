package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

func GenerateTOTPSecret() (string, error) {
	raw := make([]byte, 20)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return strings.TrimRight(base32.StdEncoding.EncodeToString(raw), "="), nil
}

func TOTPURL(issuer, account, secret string) string {
	values := url.Values{}
	values.Set("secret", secret)
	values.Set("issuer", issuer)
	values.Set("algorithm", "SHA1")
	values.Set("digits", "6")
	values.Set("period", "30")
	return "otpauth://totp/" + url.PathEscape(issuer+":"+account) + "?" + values.Encode()
}

func VerifyTOTP(secret, code string, now time.Time) bool {
	code = strings.TrimSpace(code)
	for offset := -1; offset <= 1; offset++ {
		if GenerateTOTPCode(secret, now.Add(time.Duration(offset)*30*time.Second)) == code {
			return true
		}
	}
	return false
}

func GenerateTOTPCode(secret string, now time.Time) string {
	padding := strings.Repeat("=", (8-len(secret)%8)%8)
	key, err := base32.StdEncoding.DecodeString(strings.ToUpper(secret) + padding)
	if err != nil {
		return ""
	}
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(now.Unix()/30))
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(counter[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := (uint32(sum[offset])&0x7f)<<24 |
		(uint32(sum[offset+1])&0xff)<<16 |
		(uint32(sum[offset+2])&0xff)<<8 |
		(uint32(sum[offset+3]) & 0xff)
	return fmt.Sprintf("%06d", value%1000000)
}
