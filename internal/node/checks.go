package node

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"nyaservermonitor/internal/shared/model"
)

type CheckConfig struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Type           string `json:"type"`
	Target         string `json:"target"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty"`
	ExpectedStatus int    `json:"expected_status,omitempty"`
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
		if err := validateCheck(checks[index]); err != nil {
			return nil, fmt.Errorf("check %d: %w", index, err)
		}
	}
	return checks, nil
}

func validateCheck(check CheckConfig) error {
	if len(check.ID) == 0 || len(check.ID) > 64 || strings.ContainsAny(check.ID, " /\\") {
		return errors.New("invalid id")
	}
	if len(check.Name) == 0 || len(check.Name) > 128 {
		return errors.New("invalid name")
	}
	if check.Type != "http" && check.Type != "tcp" {
		return errors.New("type must be http or tcp")
	}
	if len(check.Target) == 0 || len(check.Target) > 512 {
		return errors.New("invalid target")
	}
	if check.TimeoutSeconds == 0 {
		check.TimeoutSeconds = 5
	}
	if check.TimeoutSeconds < 1 || check.TimeoutSeconds > 30 {
		return errors.New("timeout_seconds must be between 1 and 30")
	}
	if check.Type == "http" {
		parsed, err := url.Parse(check.Target)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
			return errors.New("target must be an http or https URL")
		}
		if check.ExpectedStatus != 0 && (check.ExpectedStatus < 100 || check.ExpectedStatus > 599) {
			return errors.New("invalid expected_status")
		}
	} else if _, _, err := net.SplitHostPort(check.Target); err != nil {
		return errors.New("tcp target must be host:port")
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
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	var err error
	if config.Type == "http" {
		err = checkHTTP(ctx, config)
	} else {
		err = checkTCP(ctx, config)
	}
	result.LatencyMS = time.Since(started).Milliseconds()
	if err != nil {
		result.Status = "down"
		result.Message = trimMessage(err.Error())
	} else {
		result.Status = "up"
	}
	return result
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

func trimMessage(value string) string {
	value = strings.Join(strings.Fields(value), " ")
	if len(value) > 256 {
		return value[:256]
	}
	return value
}
