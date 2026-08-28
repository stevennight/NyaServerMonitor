package node

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"nyaservermonitor/internal/shared/model"
)

type CheckConfig struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Type           string `json:"type"`
	Target         string `json:"target"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty"`
	ExpectedStatus int    `json:"expected_status,omitempty"`
	Attempts       int    `json:"attempts,omitempty"`
}

func loadChecks(path string) ([]CheckConfig, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 128*1024))
	decoder.DisallowUnknownFields()
	var checks []CheckConfig
	if err := decoder.Decode(&checks); err != nil {
		return nil, err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, errors.New("checks file must contain one JSON array")
	}
	if len(checks) > 50 {
		return nil, errors.New("at most 50 service checks are allowed")
	}
	for index := range checks {
		applyCheckDefaults(&checks[index])
		if err := validateCheck(checks[index]); err != nil {
			return nil, fmt.Errorf("check %d: %w", index, err)
		}
	}
	return checks, nil
}

func applyCheckDefaults(check *CheckConfig) {
	if check.TimeoutSeconds == 0 {
		check.TimeoutSeconds = 5
	}
	if check.Attempts == 0 {
		check.Attempts = 1
		if check.Type == "ping" {
			check.Attempts = 3
		}
	}
}

func validateCheck(check CheckConfig) error {
	if len(check.ID) == 0 || len(check.ID) > 64 || strings.ContainsAny(check.ID, " /\\") {
		return errors.New("invalid id")
	}
	if len(check.Name) == 0 || len(check.Name) > 128 {
		return errors.New("invalid name")
	}
	if check.Type != "http" && check.Type != "tcp" && check.Type != "ping" && check.Type != "tls" {
		return errors.New("type must be http, tcp, ping, or tls")
	}
	if len(check.Target) == 0 || len(check.Target) > 512 {
		return errors.New("invalid target")
	}
	if check.TimeoutSeconds < 1 || check.TimeoutSeconds > 30 {
		return errors.New("timeout_seconds must be between 1 and 30")
	}
	if check.Attempts < 1 || check.Attempts > 10 {
		return errors.New("attempts must be between 1 and 10")
	}
	if check.Type == "http" {
		parsed, err := url.Parse(check.Target)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
			return errors.New("target must be an http or https URL")
		}
		if check.ExpectedStatus != 0 && (check.ExpectedStatus < 100 || check.ExpectedStatus > 599) {
			return errors.New("invalid expected_status")
		}
	} else if check.Type == "tcp" {
		if _, _, err := net.SplitHostPort(check.Target); err != nil {
			return errors.New("tcp target must be host:port")
		}
	} else if check.Type == "ping" {
		if strings.ContainsAny(check.Target, "/\\?#") || len(check.Target) > 253 {
			return errors.New("ping target must be a host or IP address")
		}
	} else if _, _, err := tlsTarget(check.Target); err != nil {
		return fmt.Errorf("invalid tls target: %w", err)
	}
	return nil
}

func runChecks(ctx context.Context, configs []CheckConfig) []model.ServiceCheck {
	if len(configs) == 0 {
		return nil
	}
	results := make([]model.ServiceCheck, len(configs))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 16)
	for index, config := range configs {
		index, config := index, config
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[index] = runCheck(ctx, config)
		}()
	}
	wg.Wait()
	return results
}

func runCheck(parent context.Context, config CheckConfig) model.ServiceCheck {
	started := time.Now()
	result := model.ServiceCheck{ID: config.ID, Name: config.Name, Type: config.Type, Target: config.Target, Status: "unknown", CheckedAtUnix: started.Unix()}
	timeout := time.Duration(config.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	attempts := config.Attempts
	if attempts <= 0 {
		attempts = 1
	}
	result.Attempts = attempts
	overallTimeout := timeout
	if config.Type == "ping" {
		overallTimeout *= time.Duration(attempts)
	}
	ctx, cancel := context.WithTimeout(parent, overallTimeout)
	defer cancel()
	var err error
	switch config.Type {
	case "http":
		err = checkHTTP(ctx, config)
	case "tcp":
		err = checkTCP(ctx, config)
	case "ping":
		result.LatencyMS, result.PacketLossPercent, err = checkPing(ctx, config)
	case "tls":
		var tlsResult tlsCheckResult
		tlsResult, err = checkTLS(ctx, config)
		result.TLSExpiresAtUnix = tlsResult.ExpiresAtUnix
		result.TLSFingerprint = tlsResult.Fingerprint
		result.TLSVersion = tlsResult.Version
	}
	result.LatencyMS = serviceCheckLatency(config.Type, result.LatencyMS, time.Since(started))
	if err != nil {
		result.Status = "down"
		result.Message = trimMessage(err.Error())
	} else {
		result.Status = "up"
	}
	return result
}

func serviceCheckLatency(checkType string, measured int64, elapsed time.Duration) int64 {
	if checkType == "ping" {
		return measured
	}
	return elapsed.Milliseconds()
}

func checkHTTP(ctx context.Context, config CheckConfig) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, config.Target, nil)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: time.Duration(config.TimeoutSeconds) * time.Second}
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1024))
	want := config.ExpectedStatus
	if want == 0 {
		want = http.StatusOK
	}
	if response.StatusCode != want {
		return fmt.Errorf("http status %d, expected %d", response.StatusCode, want)
	}
	return nil
}

func checkTCP(ctx context.Context, config CheckConfig) error {
	dialer := net.Dialer{Timeout: time.Duration(config.TimeoutSeconds) * time.Second}
	connection, err := dialer.DialContext(ctx, "tcp", config.Target)
	if err != nil {
		return err
	}
	return connection.Close()
}

func checkPing(ctx context.Context, config CheckConfig) (int64, float64, error) {
	target, err := resolvePingTarget(ctx, config.Target)
	if err != nil {
		return 0, 100, err
	}
	if runtime.GOOS == "windows" && target.To4() == nil {
		return 0, 100, errors.New("IPv6 ping is not supported on this platform")
	}
	network := "udp4"
	listenAddr := "0.0.0.0"
	protocol := 1
	var messageType icmp.Type = ipv4.ICMPTypeEcho
	var replyType icmp.Type = ipv4.ICMPTypeEchoReply
	destination := net.Addr(&net.UDPAddr{IP: target.To4()})
	if target.To4() == nil {
		network = "udp6"
		listenAddr = "[::]"
		protocol = 58
		messageType = ipv6.ICMPTypeEchoRequest
		replyType = ipv6.ICMPTypeEchoReply
		destination = &net.UDPAddr{IP: target}
	}
	connection, err := icmp.ListenPacket(network, listenAddr)
	if err != nil {
		return 0, 100, fmt.Errorf("open ICMP socket: %w", err)
	}
	defer func() { _ = connection.Close() }()

	attempts := config.Attempts
	if attempts <= 0 {
		attempts = 1
	}
	var totalLatency time.Duration
	successes := 0
	identifier := os.Getpid() & 0xffff
	for sequence := 1; sequence <= attempts; sequence++ {
		if err := ctx.Err(); err != nil {
			break
		}
		message := icmp.Message{Type: messageType, Code: 0, Body: &icmp.Echo{ID: identifier, Seq: sequence, Data: []byte("nyasm")}}
		body, err := message.Marshal(nil)
		if err != nil {
			return 0, 100, err
		}
		started := time.Now()
		deadline := time.Now().Add(time.Duration(config.TimeoutSeconds) * time.Second)
		if err := connection.SetReadDeadline(deadline); err != nil {
			return 0, 100, err
		}
		if _, err := connection.WriteTo(body, destination); err != nil {
			continue
		}
		buffer := make([]byte, 1500)
		for {
			read, _, readErr := connection.ReadFrom(buffer)
			if readErr != nil {
				break
			}
			parsed, parseErr := icmp.ParseMessage(protocol, buffer[:read])
			if parseErr != nil || parsed.Type != replyType {
				continue
			}
			echo, ok := parsed.Body.(*icmp.Echo)
			if !ok || echo.ID != identifier || echo.Seq != sequence {
				continue
			}
			totalLatency += time.Since(started)
			successes++
			break
		}
	}
	loss := float64(attempts-successes) / float64(attempts) * 100
	if successes == 0 {
		return 0, loss, errors.New("no ICMP echo reply")
	}
	average := totalLatency / time.Duration(successes)
	if loss > 0 {
		return average.Milliseconds(), loss, fmt.Errorf("packet loss %.1f%% (%d/%d replies)", loss, successes, attempts)
	}
	return average.Milliseconds(), loss, nil
}

func resolvePingTarget(ctx context.Context, target string) (net.IP, error) {
	if ip := net.ParseIP(strings.Trim(target, "[]")); ip != nil {
		return ip, nil
	}
	resolver := net.Resolver{}
	addresses, err := resolver.LookupIP(ctx, "ip", target)
	if err != nil || len(addresses) == 0 {
		if err == nil {
			err = errors.New("no address found")
		}
		return nil, fmt.Errorf("resolve ping target: %w", err)
	}
	for _, address := range addresses {
		if address.To4() != nil {
			return address, nil
		}
	}
	return addresses[0], nil
}

type tlsCheckResult struct {
	ExpiresAtUnix int64
	Fingerprint   string
	Version       string
}

func checkTLS(ctx context.Context, config CheckConfig) (tlsCheckResult, error) {
	host, address, err := tlsTarget(config.Target)
	if err != nil {
		return tlsCheckResult{}, err
	}
	serverName := host
	if net.ParseIP(host) != nil {
		serverName = host
	}
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: time.Duration(config.TimeoutSeconds) * time.Second},
		Config: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			ServerName:         serverName,
			InsecureSkipVerify: true, // inspect expired certificates, then verify below
		},
	}
	connection, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return tlsCheckResult{}, err
	}
	defer func() { _ = connection.Close() }()
	tlsConnection, ok := connection.(*tls.Conn)
	if !ok {
		return tlsCheckResult{}, errors.New("unexpected TLS connection")
	}
	state := tlsConnection.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return tlsCheckResult{}, errors.New("server did not provide a certificate")
	}
	certificate := state.PeerCertificates[0]
	fingerprint := sha256.Sum256(certificate.Raw)
	result := tlsCheckResult{
		ExpiresAtUnix: certificate.NotAfter.Unix(),
		Fingerprint:   hex.EncodeToString(fingerprint[:]),
		Version:       tlsVersionName(state.Version),
	}
	intermediates := x509.NewCertPool()
	for _, intermediate := range state.PeerCertificates[1:] {
		intermediates.AddCert(intermediate)
	}
	if _, err := certificate.Verify(x509.VerifyOptions{DNSName: serverName, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return result, fmt.Errorf("certificate verification failed: %w", err)
	}
	return result, nil
}

func tlsTarget(target string) (string, string, error) {
	target = strings.TrimSpace(target)
	if strings.Contains(target, "://") {
		parsed, err := url.Parse(target)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
			return "", "", errors.New("target must be an https URL or host:port")
		}
		if parsed.Path != "" && parsed.Path != "/" || parsed.RawQuery != "" || parsed.Fragment != "" {
			return "", "", errors.New("tls target must not include a path or query")
		}
		host := parsed.Hostname()
		port := parsed.Port()
		if port == "" {
			port = "443"
		}
		return host, net.JoinHostPort(host, port), nil
	}
	if host, port, err := net.SplitHostPort(target); err == nil {
		if host == "" || port == "" {
			return "", "", errors.New("host and port are required")
		}
		return host, net.JoinHostPort(host, port), nil
	}
	if strings.Contains(target, "/") || target == "" {
		return "", "", errors.New("target must be an https URL or host:port")
	}
	return target, net.JoinHostPort(target, "443"), nil
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	default:
		return fmt.Sprintf("0x%04x", version)
	}
}

func trimMessage(value string) string {
	value = strings.Join(strings.Fields(value), " ")
	if len(value) > 256 {
		return value[:256]
	}
	return value
}
