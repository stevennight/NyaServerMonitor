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
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"

	sharedcrypto "nyaservermonitor/internal/shared/crypto"
	"nyaservermonitor/internal/shared/model"
	sharedprotocol "nyaservermonitor/internal/shared/protocol"
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

func (c *client) connectWS(ctx context.Context) (*websocket.Conn, error) {
	base, err := validateControllerURL(c.baseURL)
	if err != nil {
		return nil, err
	}
	if base.Scheme == "http" {
		base.Scheme = "ws"
	} else {
		base.Scheme = "wss"
	}
	base.Path = "/api/node/ws"
	base.RawQuery = ""
	base.Fragment = ""
	headers := http.Header{}
	headers.Set("X-NyaSM-Node-ID", c.nodeID)
	headers.Set("X-NyaSM-Node-Token", c.token)
	conn, response, err := websocket.Dial(ctx, base.String(), &websocket.DialOptions{HTTPClient: c.http, HTTPHeader: headers})
	if err != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return nil, err
	}
	return conn, nil
}

func writeControlMessage(ctx context.Context, conn *websocket.Conn, message sharedprotocol.ControlMessage) error {
	return wsjson.Write(ctx, conn, message)
}

func validateControllerURL(raw string) (*url.URL, error) {
	raw = strings.TrimRight(strings.TrimSpace(raw), "/")
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("invalid controller URL")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("controller URL must use http or https")
	}
	if parsed.Scheme == "http" && !isLoopbackHost(parsed.Hostname()) {
		return nil, fmt.Errorf("unencrypted controller HTTP is only allowed on loopback")
	}
	return parsed, nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
