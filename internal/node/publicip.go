package node

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"nyaservermonitor/internal/shared/model"
)

type publicIPFamily string

const (
	publicIPv4Family publicIPFamily = "ipv4"
	publicIPv6Family publicIPFamily = "ipv6"
)

const (
	publicIPSuccessInterval = 5 * time.Minute
	publicIPFailureInterval = 2 * time.Minute
	publicIPRequestTimeout  = 5 * time.Second
	publicIPDialTimeout     = 3 * time.Second
	publicIPProbeTimeout    = 15 * time.Second
	publicIPMaxBody         = 4 << 10
)

type publicIPProvider struct {
	Name string
	URL  string
}

var defaultPublicIPProviders = map[publicIPFamily][]publicIPProvider{
	publicIPv4Family: {
		{Name: "ip.sb", URL: "https://api.ip.sb/ip"},
		{Name: "Cloudflare", URL: "https://cloudflare.com/cdn-cgi/trace"},
		{Name: "ipify", URL: "https://api.ipify.org"},
		{Name: "icanhazip", URL: "https://ipv4.icanhazip.com"},
		{Name: "ifconfig.me", URL: "https://ifconfig.me/ip"},
	},
	publicIPv6Family: {
		{Name: "ip.sb", URL: "https://api.ip.sb/ip"},
		{Name: "Cloudflare", URL: "https://cloudflare.com/cdn-cgi/trace"},
		{Name: "ipify", URL: "https://api6.ipify.org"},
		{Name: "icanhazip", URL: "https://ipv6.icanhazip.com"},
		{Name: "ifconfig.me", URL: "https://ifconfig.me/ip"},
	},
}

type publicIPFamilyState struct {
	mu          sync.Mutex
	providers   []publicIPProvider
	value       string
	nextAttempt time.Time
	inFlight    bool
	done        chan struct{}
}

type publicIPProbe func(context.Context, publicIPFamily, []publicIPProvider) (string, error)

type publicIPDetector struct {
	families map[publicIPFamily]*publicIPFamilyState
	now      func() time.Time
	probe    publicIPProbe
}

func newPublicIPDetector() *publicIPDetector {
	return &publicIPDetector{
		families: map[publicIPFamily]*publicIPFamilyState{
			publicIPv4Family: {providers: append([]publicIPProvider(nil), defaultPublicIPProviders[publicIPv4Family]...)},
			publicIPv6Family: {providers: append([]publicIPProvider(nil), defaultPublicIPProviders[publicIPv6Family]...)},
		},
		now:   time.Now,
		probe: probePublicIPFamily,
	}
}

func (d *publicIPDetector) PublicIP(ctx context.Context) model.PublicIP {
	if d == nil {
		return model.PublicIP{}
	}
	var result model.PublicIP
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		result.IPv4 = d.cachedFamily(ctx, publicIPv4Family)
	}()
	go func() {
		defer wg.Done()
		result.IPv6 = d.cachedFamily(ctx, publicIPv6Family)
	}()
	wg.Wait()
	return result
}

func (d *publicIPDetector) cachedFamily(ctx context.Context, family publicIPFamily) string {
	state := d.families[family]
	if state == nil {
		return ""
	}
	for {
		now := d.now()
		state.mu.Lock()
		if now.Before(state.nextAttempt) {
			value := state.value
			state.mu.Unlock()
			return value
		}
		if state.inFlight {
			done := state.done
			value := state.value
			state.mu.Unlock()
			select {
			case <-done:
				continue
			case <-ctx.Done():
				return value
			}
		}
		state.inFlight = true
		state.done = make(chan struct{})
		done := state.done
		providers := append([]publicIPProvider(nil), state.providers...)
		state.mu.Unlock()

		value, err := d.probe(ctx, family, providers)
		state.mu.Lock()
		if err == nil && strings.TrimSpace(value) != "" {
			state.value = value
			state.nextAttempt = d.now().Add(publicIPSuccessInterval)
		} else {
			state.nextAttempt = d.now().Add(publicIPFailureInterval)
		}
		cached := state.value
		state.inFlight = false
		close(done)
		state.mu.Unlock()
		return cached
	}
}

func probePublicIPFamily(ctx context.Context, family publicIPFamily, providers []publicIPProvider) (string, error) {
	if len(providers) == 0 {
		return "", fmt.Errorf("no public %s providers configured", family)
	}
	probeCtx, cancel := context.WithTimeout(ctx, publicIPProbeTimeout)
	defer cancel()
	client := newPublicIPHTTPClient(family)
	defer client.CloseIdleConnections()
	var lastErr error
	for _, provider := range providers {
		if err := probeCtx.Err(); err != nil {
			return "", err
		}
		value, err := fetchPublicIP(probeCtx, client, family, provider.URL)
		if err == nil {
			return value, nil
		}
		lastErr = fmt.Errorf("%s: %w", provider.Name, err)
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("all public %s providers failed", family)
	}
	return "", lastErr
}

func newPublicIPHTTPClient(family publicIPFamily) *http.Client {
	network := "tcp4"
	if family == publicIPv6Family {
		network = "tcp6"
	}
	dialer := &net.Dialer{Timeout: publicIPDialTimeout}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, address)
		},
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}
	return &http.Client{Transport: transport, Timeout: publicIPRequestTimeout}
}

func fetchPublicIP(ctx context.Context, client *http.Client, family publicIPFamily, endpoint string) (string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	request.Header.Set("Accept", "text/plain")
	response, err := client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return "", fmt.Errorf("HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, publicIPMaxBody+1))
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}
	if len(body) > publicIPMaxBody {
		return "", fmt.Errorf("response is too large")
	}
	return parsePublicIPResponse(body, family)
}

func parsePublicIPResponse(body []byte, family publicIPFamily) (string, error) {
	value := strings.TrimSpace(string(body))
	if parsed, err := normalizePublicIP(value, family); err == nil {
		return parsed, nil
	}
	for _, line := range strings.Split(value, "\n") {
		key, candidate, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok || strings.TrimSpace(key) != "ip" {
			continue
		}
		return normalizePublicIP(candidate, family)
	}
	return "", fmt.Errorf("response did not contain a valid %s address", family)
}

func normalizePublicIP(value string, family publicIPFamily) (string, error) {
	parsed := net.ParseIP(strings.TrimSpace(value))
	if parsed == nil {
		return "", fmt.Errorf("invalid IP address")
	}
	if family == publicIPv4Family {
		if ipv4 := parsed.To4(); ipv4 != nil {
			return ipv4.String(), nil
		}
		return "", fmt.Errorf("address is not IPv4")
	}
	if family == publicIPv6Family {
		if parsed.To4() == nil {
			return parsed.String(), nil
		}
		return "", fmt.Errorf("address is not IPv6")
	}
	return "", fmt.Errorf("unknown address family %q", family)
}
