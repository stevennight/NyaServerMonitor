package node

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestPublicIPDetectorUsesIndependentBackoff(t *testing.T) {
	detector := newPublicIPDetector()
	clock := time.Unix(1000, 0)
	detector.now = func() time.Time { return clock }
	var ipv4Calls, ipv6Calls atomic.Int32
	var failIPv4 atomic.Bool
	detector.probe = func(_ context.Context, family publicIPFamily, _ []publicIPProvider) (string, error) {
		switch family {
		case publicIPv4Family:
			attempt := ipv4Calls.Add(1)
			if failIPv4.Load() {
				return "", errors.New("IPv4 unavailable")
			}
			if attempt == 1 {
				return "198.51.100.10", nil
			}
			return "198.51.100.11", nil
		case publicIPv6Family:
			attempt := ipv6Calls.Add(1)
			if attempt == 1 {
				return "", errors.New("IPv6 unavailable")
			}
			return "2001:db8::10", nil
		default:
			return "", errors.New("unexpected address family")
		}
	}

	got := detector.PublicIP(context.Background())
	if got.IPv4 != "198.51.100.10" || got.IPv6 != "" || ipv4Calls.Load() != 1 || ipv6Calls.Load() != 1 {
		t.Fatalf("initial public IP = %#v, calls = %d/%d", got, ipv4Calls.Load(), ipv6Calls.Load())
	}

	clock = clock.Add(119 * time.Second)
	got = detector.PublicIP(context.Background())
	if got.IPv4 != "198.51.100.10" || got.IPv6 != "" || ipv4Calls.Load() != 1 || ipv6Calls.Load() != 1 {
		t.Fatalf("backoff public IP = %#v, calls = %d/%d", got, ipv4Calls.Load(), ipv6Calls.Load())
	}

	clock = clock.Add(time.Second)
	got = detector.PublicIP(context.Background())
	if got.IPv4 != "198.51.100.10" || got.IPv6 != "2001:db8::10" || ipv4Calls.Load() != 1 || ipv6Calls.Load() != 2 {
		t.Fatalf("IPv6 retry public IP = %#v, calls = %d/%d", got, ipv4Calls.Load(), ipv6Calls.Load())
	}

	failIPv4.Store(true)
	clock = clock.Add(3 * time.Minute)
	got = detector.PublicIP(context.Background())
	if got.IPv4 != "198.51.100.10" || got.IPv6 != "2001:db8::10" || ipv4Calls.Load() != 2 || ipv6Calls.Load() != 2 {
		t.Fatalf("failed IPv4 probe should keep cached value = %#v, calls = %d/%d", got, ipv4Calls.Load(), ipv6Calls.Load())
	}

	failIPv4.Store(false)
	clock = clock.Add(2 * time.Minute)
	got = detector.PublicIP(context.Background())
	if got.IPv4 != "198.51.100.11" || got.IPv6 != "2001:db8::10" || ipv4Calls.Load() != 3 || ipv6Calls.Load() != 3 {
		t.Fatalf("IPv4 retry public IP = %#v, calls = %d/%d", got, ipv4Calls.Load(), ipv6Calls.Load())
	}
}

func TestProbePublicIPFamilyFallsBackAndParsesCloudflareTrace(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		switch r.URL.Path {
		case "/bad":
			_, _ = w.Write([]byte("not an IP"))
		case "/trace":
			_, _ = w.Write([]byte("fl=abc\nip=198.51.100.20\nts=123\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	got, err := probePublicIPFamily(context.Background(), publicIPv4Family, []publicIPProvider{
		{Name: "bad", URL: server.URL + "/bad"},
		{Name: "trace", URL: server.URL + "/trace"},
	})
	if err != nil || got != "198.51.100.20" {
		t.Fatalf("fallback public IP = %q, err=%v", got, err)
	}
	if requests.Load() != 2 {
		t.Fatalf("provider request count = %d, want 2", requests.Load())
	}
}

func TestNormalizePublicIPChecksAddressFamily(t *testing.T) {
	if got, err := normalizePublicIP(" 198.51.100.21\n", publicIPv4Family); err != nil || got != "198.51.100.21" {
		t.Fatalf("IPv4 normalization = %q, err=%v", got, err)
	}
	if got, err := normalizePublicIP("2001:db8::21", publicIPv6Family); err != nil || got != "2001:db8::21" {
		t.Fatalf("IPv6 normalization = %q, err=%v", got, err)
	}
	if _, err := normalizePublicIP("2001:db8::21", publicIPv4Family); err == nil {
		t.Fatal("IPv6 should not be accepted as IPv4")
	}
	if _, err := normalizePublicIP("198.51.100.21", publicIPv6Family); err == nil {
		t.Fatal("IPv4 should not be accepted as IPv6")
	}
}
