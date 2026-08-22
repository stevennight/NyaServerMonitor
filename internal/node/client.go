package node

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	sharedcrypto "nyaservermonitor/internal/shared/crypto"
	"nyaservermonitor/internal/shared/model"
)

const reportPath = "/api/agent/v1/report"

type client struct {
	baseURL string
	nodeID  string
	token   string
	http    *http.Client
}

func newClient(cfg Config) *client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: cfg.InsecureSkipVerify}, // explicit development escape hatch
	}
	return &client{
		baseURL: strings.TrimRight(cfg.ControllerURL, "/"),
		nodeID:  cfg.NodeID,
		token:   cfg.NodeToken,
		http: &http.Client{
			Timeout:   cfg.HTTPTimeout,
			Transport: transport,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (c *client) report(ctx context.Context, report model.Report) error {
	body, err := json.Marshal(report)
	if err != nil {
		return err
	}
	// A fresh nonce is required for every request. The controller rejects reuse.
	var nonceBytes [18]byte
	if _, err := rand.Read(nonceBytes[:]); err != nil {
		return err
	}
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes[:])
	signature := sharedcrypto.ReportSignature(sharedcrypto.HashToken(c.token), http.MethodPost, reportPath, timestamp, nonce, body)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+reportPath, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "nyasm-node/"+report.AgentVersion)
	request.Header.Set("X-NyaSM-Node-ID", c.nodeID)
	request.Header.Set("X-NyaSM-Timestamp", timestamp)
	request.Header.Set("X-NyaSM-Nonce", nonce)
	request.Header.Set("X-NyaSM-Signature", signature)
	response, err := c.http.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("controller rejected report: %s", response.Status)
	}
	return nil
}
