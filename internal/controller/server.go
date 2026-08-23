package controller

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"nyaservermonitor/internal/controller/auth"
	"nyaservermonitor/internal/controller/nodehub"
	"nyaservermonitor/internal/controller/store"
	sharedcrypto "nyaservermonitor/internal/shared/crypto"
	"nyaservermonitor/internal/shared/model"
	"nyaservermonitor/internal/shared/validate"
	sharedversion "nyaservermonitor/internal/shared/version"
)

const (
	sessionCookieName = "nyasm_session"
	reportPath        = "/api/agent/v1/report"
)

//go:embed webdist/*
var webFiles embed.FS

type Server struct {
	cfg             Config
	log             *slog.Logger
	store           *store.Store
	tokenBox        *secretBox
	sessions        *auth.Sessions
	limiter         *auth.LoginLimiter
	alerts          *alertEngine
	geoIP           *geoIPLookup
	mux             *http.ServeMux
	nonces          *nonceCache
	hub             *nodehub.Hub
	telemetry       *telemetryHub
	nodeSocketMu    sync.Mutex
	releaseMu       sync.Mutex
	releaseCache    model.SignedNodeRelease
	releaseCachedAt time.Time
	setupMu         sync.Mutex
	publicMu        sync.Mutex
	publicAt        time.Time
	publicSort      string
	publicBody      []byte
}

type nonceCache struct {
	mu    sync.Mutex
	items map[string]time.Time
	max   int
}

func newNonceCache() *nonceCache {
	return &nonceCache{items: make(map[string]time.Time), max: 100000}
}

func (c *nonceCache) Claim(nodeID, nonce string, now time.Time) bool {
	key := nodeID + "\x00" + nonce
	c.mu.Lock()
	defer c.mu.Unlock()
	for existing, expires := range c.items {
		if !now.Before(expires) {
			delete(c.items, existing)
		}
	}
	if _, exists := c.items[key]; exists {
		return false
	}
	if len(c.items) >= c.max {
		return false
	}
	c.items[key] = now.Add(10 * time.Minute)
	return true
}

func NewServer(cfg Config, st *store.Store) *Server {
	s := &Server{
		cfg:       cfg,
		log:       slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: parseLevel(cfg.LogLevel)})),
		store:     st,
		tokenBox:  newSecretBox(cfg.NodeTokenKey),
		sessions:  auth.NewSessions(cfg.SessionLifetime),
		limiter:   auth.NewLoginLimiter(),
		mux:       http.NewServeMux(),
		nonces:    newNonceCache(),
		hub:       nodehub.New(),
		telemetry: newTelemetryHub(),
		geoIP:     newGeoIPLookup(cfg.GeoIPURL),
	}
	s.alerts = newAlertEngine(st, newSecretBox(cfg.NotificationKey), s.log)
	s.routes()
	return s
}

func Run(ctx context.Context, args []string) error {
	if hasVersionArg(args) {
		fmt.Println("nyasm-controller " + sharedversion.Version)
		return nil
	}
	cfg, err := parseConfig(args)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return err
	}
	st, err := store.Open(ctx, cfg.DBPath)
	if err != nil {
		return err
	}
	defer st.Close()
	s := NewServer(cfg, st)
	go s.maintenanceLoop(ctx)
	httpServer := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           secureHeaders(s.mux),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       20 * time.Second,
		WriteTimeout:      20 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 * 1024,
	}
	errCh := make(chan error, 1)
	go func() {
		s.log.Info("controller listening", "addr", cfg.ListenAddr, "data", cfg.DataDir)
		errCh <- httpServer.ListenAndServe()
	}()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return httpServer.Shutdown(shutdownCtx)
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /api/setup/status", s.handleSetupStatus)
	s.mux.HandleFunc("POST /api/setup", s.handleSetup)
	s.mux.HandleFunc("POST /api/auth/login", s.handleLogin)
	s.mux.HandleFunc("POST /api/auth/logout", s.withAuth(s.handleLogout))
	s.mux.HandleFunc("GET /api/me", s.withAuth(s.handleMe))
	s.mux.HandleFunc("POST /api/settings/totp/setup", s.withAuth(s.handleTOTPSetup))
	s.mux.HandleFunc("POST /api/settings/totp/enable", s.withAuth(s.handleTOTPEnable))
	s.mux.HandleFunc("POST /api/settings/totp/disable", s.withAuth(s.handleTOTPDisable))
	s.mux.HandleFunc("GET /api/public/dashboard", s.handlePublicDashboard)
	s.mux.HandleFunc("GET /api/public/nodes/{id}/metrics", s.handlePublicNodeMetrics)
	s.mux.HandleFunc("GET /api/dashboard", s.withAuth(s.handleDashboard))
	s.mux.HandleFunc("GET /api/telemetry/stream", s.withAuth(s.handleTelemetryStream))
	s.mux.HandleFunc("GET /api/audit", s.withAuth(s.handleAudit))
	s.mux.HandleFunc("GET /api/alerts", s.withAuth(s.handleAlerts))
	s.mux.HandleFunc("GET /api/alerts/events", s.withAuth(s.handleAlertEvents))
	s.mux.HandleFunc("POST /api/alerts/rules", s.withAuth(s.handleCreateAlertRule))
	s.mux.HandleFunc("PUT /api/alerts/rules/{id}", s.withAuth(s.handleUpdateAlertRule))
	s.mux.HandleFunc("DELETE /api/alerts/rules/{id}", s.withAuth(s.handleDeleteAlertRule))
	s.mux.HandleFunc("POST /api/alerts/channels", s.withAuth(s.handleCreateNotificationChannel))
	s.mux.HandleFunc("DELETE /api/alerts/channels/{id}", s.withAuth(s.handleDeleteNotificationChannel))
	s.mux.HandleFunc("GET /api/controller/info", s.withAuth(s.handleControllerInfo))
	s.mux.HandleFunc("GET /api/nodes", s.withAuth(s.handleListNodes))
	s.mux.HandleFunc("POST /api/nodes", s.withAuth(s.handleCreateNode))
	s.mux.HandleFunc("GET /api/nodes/{id}", s.withAuth(s.handleGetNode))
	s.mux.HandleFunc("PUT /api/nodes/{id}", s.withAuth(s.handleUpdateNodeMetadata))
	s.mux.HandleFunc("GET /api/nodes/{id}/metrics", s.withAuth(s.handleNodeMetrics))
	s.mux.HandleFunc("POST /api/nodes/{id}/rotate-token", s.withAuth(s.handleRotateToken))
	s.mux.HandleFunc("POST /api/nodes/{id}/install", s.withAuth(s.handleNodeInstall))
	s.mux.HandleFunc("POST /api/nodes/{id}/update", s.withAuth(s.handleUpdateNode))
	s.mux.HandleFunc("POST /api/nodes/update", s.withAuth(s.handleUpdateAllNodes))
	s.mux.HandleFunc("POST /api/nodes/{id}/revoke", s.withAuth(s.handleRevokeNode))
	s.mux.HandleFunc("POST /api/nodes/{id}/restore", s.withAuth(s.handleRestoreNode))
	s.mux.HandleFunc("GET /install.sh", s.handleInstallScript)
	s.mux.HandleFunc("GET /downloads/nyasm-node", s.handleDownloadNodeBinary)
	s.mux.HandleFunc("GET /downloads/nyasm-node/manifest", s.handleDownloadNodeReleaseManifest)
	s.mux.HandleFunc("GET /downloads/nyasm-node/signature", s.handleDownloadNodeBinarySignature)
	s.mux.HandleFunc("GET /api/node/ws", s.withNode(s.handleNodeWS))
	// Reports remain a signed, durable data endpoint. The node WebSocket carries
	// heartbeats, live telemetry, and the fixed signed update message.
	s.mux.HandleFunc("POST "+reportPath, s.handleAgentReport)
	s.mux.HandleFunc("/", s.handleSPA)
}

func (s *Server) maintenanceLoop(ctx context.Context) {
	ticker := time.NewTicker(s.cfg.CleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			if err := s.store.MarkOffline(ctx, now.Add(-s.cfg.OfflineAfter)); err != nil {
				s.log.Warn("mark offline failed", "error", err)
			}
			if err := s.alerts.evaluateAll(ctx); err != nil {
				s.log.Warn("evaluate offline alerts failed", "error", err)
			}
			if err := s.store.PruneMetrics(ctx, now.Add(-s.cfg.MetricsRetention)); err != nil {
				s.log.Warn("prune metrics failed", "error", err)
			}
		}
	}
}

func (s *Server) handleSetupStatus(w http.ResponseWriter, r *http.Request) {
	count, err := s.store.UserCount(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "setup status unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"needs_setup": count == 0})
}

type setupRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	s.setupMu.Lock()
	defer s.setupMu.Unlock()
	count, err := s.store.UserCount(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "setup unavailable")
		return
	}
	if count != 0 {
		writeError(w, http.StatusConflict, "setup has already been completed")
		return
	}
	var input setupRequest
	if err := decodeJSON(w, r, 4096, &input); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := validateAdminCredentials(input.Username, input.Password); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	hash, err := auth.HashPassword(input.Password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "password hashing failed")
		return
	}
	user, err := s.store.CreateUser(r.Context(), strings.TrimSpace(input.Username), hash)
	if err != nil {
		writeError(w, http.StatusConflict, "unable to create administrator")
		return
	}
	session, err := s.sessions.Create(user.ID, user.Username)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "session creation failed")
		return
	}
	s.setSessionCookie(w, session)
	_ = s.store.AddAudit(r.Context(), user.Username, "setup_completed", "controller", nil)
	writeJSON(w, http.StatusCreated, map[string]any{"username": user.Username})
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	TOTPCode string `json:"totp_code,omitempty"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	key := remoteIP(r)
	if !s.limiter.Allow(key) {
		writeError(w, http.StatusTooManyRequests, "too many login attempts")
		return
	}
	var input loginRequest
	if err := decodeJSON(w, r, 8192, &input); err != nil {
		s.limiter.Fail(key)
		writeError(w, http.StatusBadRequest, "invalid login request")
		return
	}
	user, err := s.store.FindUserByUsername(r.Context(), strings.TrimSpace(input.Username))
	if err != nil || !auth.VerifyPassword(user.PasswordHash, input.Password) {
		s.limiter.Fail(key)
		writeError(w, http.StatusUnauthorized, "invalid username or password")
		return
	}
	if user.TOTPEnabled && !auth.VerifyTOTP(user.TOTPSecret, input.TOTPCode, time.Now()) {
		s.limiter.Fail(key)
		writeError(w, http.StatusUnauthorized, "two-factor code required")
		return
	}
	s.limiter.Success(key)
	session, err := s.sessions.Create(user.ID, user.Username)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "session creation failed")
		return
	}
	s.setSessionCookie(w, session)
	_ = s.store.AddAudit(r.Context(), user.Username, "login", "auth", nil)
	writeJSON(w, http.StatusOK, map[string]any{"username": user.Username})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request, session auth.Session) {
	s.sessions.Delete(session.ID)
	http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: s.cfg.CookieSecure, SameSite: http.SameSiteStrictMode})
	_ = s.store.AddAudit(r.Context(), session.Username, "logout", "auth", nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request, session auth.Session) {
	user, err := s.store.FindUserByUsername(r.Context(), session.Username)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "session user not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"username": session.Username, "totp_enabled": user.TOTPEnabled})
}

func (s *Server) handleTOTPSetup(w http.ResponseWriter, r *http.Request, session auth.Session) {
	secret, err := auth.GenerateTOTPSecret()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to generate two-factor secret")
		return
	}
	if err := s.store.SetTOTP(r.Context(), session.UserID, secret, false); err != nil {
		writeError(w, http.StatusInternalServerError, "unable to save two-factor secret")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"secret": secret, "otpauth_url": auth.TOTPURL("NyaServerMonitor", session.Username, secret)})
}

type totpRequest struct {
	Code string `json:"code"`
}

func (s *Server) handleTOTPEnable(w http.ResponseWriter, r *http.Request, session auth.Session) {
	var input totpRequest
	if err := decodeJSON(w, r, 2048, &input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid code")
		return
	}
	user, err := s.store.FindUserByUsername(r.Context(), session.Username)
	if err != nil || user.TOTPSecret == "" || !auth.VerifyTOTP(user.TOTPSecret, input.Code, time.Now()) {
		writeError(w, http.StatusBadRequest, "invalid code")
		return
	}
	if err := s.store.SetTOTP(r.Context(), session.UserID, user.TOTPSecret, true); err != nil {
		writeError(w, http.StatusInternalServerError, "unable to enable two-factor authentication")
		return
	}
	_ = s.store.AddAudit(r.Context(), session.Username, "totp_enabled", "auth", nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleTOTPDisable(w http.ResponseWriter, r *http.Request, session auth.Session) {
	var input totpRequest
	if err := decodeJSON(w, r, 2048, &input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid code")
		return
	}
	user, err := s.store.FindUserByUsername(r.Context(), session.Username)
	if err != nil || !user.TOTPEnabled || !auth.VerifyTOTP(user.TOTPSecret, input.Code, time.Now()) {
		writeError(w, http.StatusBadRequest, "invalid code")
		return
	}
	if err := s.store.SetTOTP(r.Context(), session.UserID, "", false); err != nil {
		writeError(w, http.StatusInternalServerError, "unable to disable two-factor authentication")
		return
	}
	_ = s.store.AddAudit(r.Context(), session.Username, "totp_disabled", "auth", nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) withAuth(next func(http.ResponseWriter, *http.Request, auth.Session)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(sessionCookieName)
		if err != nil || cookie.Value == "" {
			writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		session, ok := s.sessions.Get(cookie.Value)
		if !ok {
			writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Header.Get("Origin") != "" && !sameOrigin(r) {
			writeError(w, http.StatusForbidden, "cross-origin request rejected")
			return
		}
		next(w, r, session)
	}
}

func sameOrigin(r *http.Request) bool {
	origin, err := url.Parse(r.Header.Get("Origin"))
	if err != nil || origin.Host == "" || r.Host == "" {
		return false
	}
	return origin.Host == r.Host
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request, session auth.Session) {
	_ = s.store.MarkOffline(r.Context(), time.Now().UTC().Add(-s.cfg.OfflineAfter))
	nodes, err := s.store.ListNodes(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to load nodes")
		return
	}
	events, err := s.store.ListAudit(r.Context(), 10)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to load events")
		return
	}
	alertEvents, err := s.store.ListAlertEvents(r.Context(), 10)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to load alert events")
		return
	}
	activeAlerts, err := s.store.CountActiveAlerts(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to load alert state")
		return
	}
	dashboard := model.Dashboard{Nodes: nodes, RecentEvents: events, RecentAlerts: alertEvents, ActiveAlerts: activeAlerts, GeneratedAtUnix: time.Now().Unix()}
	for _, node := range nodes {
		switch node.Status {
		case model.NodeOnline:
			dashboard.OnlineNodes++
		case model.NodeOffline:
			dashboard.OfflineNodes++
		case model.NodeRevoked:
			dashboard.RevokedNodes++
		}
		for _, check := range node.Checks {
			if check.Status != "up" {
				dashboard.DegradedChecks++
			}
		}
	}
	dashboard.TotalNodes = len(nodes)
	writeJSON(w, http.StatusOK, dashboard)
}

const publicDashboardCacheTTL = 5 * time.Second

func (s *Server) handlePublicDashboard(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	sortMode := publicNodeSort(r.URL.Query().Get("sort"))
	s.publicMu.Lock()
	if len(s.publicBody) > 0 && s.publicSort == sortMode && now.Sub(s.publicAt) < publicDashboardCacheTTL {
		body := append([]byte(nil), s.publicBody...)
		s.publicMu.Unlock()
		writePublicDashboard(w, body)
		return
	}
	s.publicMu.Unlock()

	_ = s.store.MarkOffline(r.Context(), now.UTC().Add(-s.cfg.OfflineAfter))
	nodes, err := s.store.ListNodes(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "public dashboard unavailable")
		return
	}
	sortPublicNodes(nodes, sortMode)
	body, err := json.Marshal(buildPublicDashboard(nodes, now.Unix()))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "public dashboard unavailable")
		return
	}
	s.publicMu.Lock()
	s.publicAt = now
	s.publicSort = sortMode
	s.publicBody = append(s.publicBody[:0], body...)
	s.publicMu.Unlock()
	writePublicDashboard(w, body)
}

func publicNodeSort(value string) string {
	if strings.EqualFold(strings.TrimSpace(value), "created") {
		return "created"
	}
	return "name"
}

func sortPublicNodes(nodes []model.Node, mode string) {
	sort.SliceStable(nodes, func(left, right int) bool {
		if mode == "created" && !nodes[left].CreatedAt.Equal(nodes[right].CreatedAt) {
			return nodes[left].CreatedAt.Before(nodes[right].CreatedAt)
		}
		nameOrder := strings.Compare(strings.ToLower(nodes[left].Name), strings.ToLower(nodes[right].Name))
		if nameOrder != 0 {
			return nameOrder < 0
		}
		return nodes[left].ID < nodes[right].ID
	})
}

func (s *Server) handlePublicNodeMetrics(w http.ResponseWriter, r *http.Request) {
	nodes, err := s.store.ListNodes(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "public metrics unavailable")
		return
	}
	var node model.Node
	for _, candidate := range nodes {
		if candidate.Status != model.NodeRevoked && publicNodeID(candidate.ID) == r.PathValue("id") {
			node = candidate
			break
		}
	}
	if node.ID == "" {
		writeError(w, http.StatusNotFound, "node not found")
		return
	}
	hours := queryInt(r, "hours", 24, 1, 24*30)
	limit := queryInt(r, "limit", 120, 1, 500)
	samples, err := s.store.ListMetrics(r.Context(), node.ID, time.Now().UTC().Add(-time.Duration(hours)*time.Hour), limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "public metrics unavailable")
		return
	}
	publicSamples := make([]model.PublicMetricSample, 0, len(samples))
	for _, sample := range samples {
		memoryPercent := percentOf(sample.Metrics.MemoryUsedBytes, sample.Metrics.MemoryTotalBytes)
		networkIn, networkOut := uint64(0), uint64(0)
		for _, network := range sample.Metrics.Networks {
			networkIn += network.BytesIn
			networkOut += network.BytesOut
		}
		publicSamples = append(publicSamples, model.PublicMetricSample{
			ObservedAt:      sample.ObservedAt,
			CPUPercent:      sample.Metrics.CPUPercent,
			MemoryPercent:   float64(memoryPercent),
			DiskPercent:     float64(publicDiskPercent(sample.Metrics.Disks)),
			Load1:           sample.Metrics.Load1,
			NetworkInBytes:  networkIn,
			NetworkOutBytes: networkOut,
		})
	}
	w.Header().Set("Cache-Control", "public, max-age=5, stale-while-revalidate=15")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow")
	writeJSON(w, http.StatusOK, map[string]any{"node_id": publicNodeID(node.ID), "samples": publicSamples})
}

func publicNodeID(nodeID string) string {
	digest := sha256.Sum256([]byte(nodeID))
	return fmt.Sprintf("node_%x", digest[:8])
}

func buildPublicDashboard(nodes []model.Node, generatedAtUnix int64) model.PublicDashboard {
	dashboard := model.PublicDashboard{GeneratedAtUnix: generatedAtUnix, Nodes: make([]model.PublicNode, 0, len(nodes))}
	for _, node := range nodes {
		if node.Status == model.NodeRevoked {
			continue
		}
		country := node.Country
		if strings.TrimSpace(node.CountryOverride) != "" {
			country = node.CountryOverride
		}
		publicNode := model.PublicNode{
			ID:            publicNodeID(node.ID),
			Name:          node.Name,
			Group:         node.Group,
			Tags:          append([]string(nil), node.Tags...),
			Status:        node.Status,
			AgentVersion:  node.AgentVersion,
			OS:            node.System.OS,
			Arch:          node.System.Arch,
			Country:       country,
			CountryCode:   node.CountryCode,
			UptimeSeconds: node.Metrics.UptimeSeconds,
			CPUPercent:    coarsePercent(node.Metrics.CPUPercent),
			MemoryPercent: percentOf(node.Metrics.MemoryUsedBytes, node.Metrics.MemoryTotalBytes),
			DiskPercent:   publicDiskPercent(node.Metrics.Disks),
		}
		for _, check := range node.Checks {
			publicNode.ChecksTotal++
			if check.Status == "up" {
				publicNode.ChecksUp++
			}
		}
		dashboard.Nodes = append(dashboard.Nodes, publicNode)
		dashboard.TotalNodes++
		switch node.Status {
		case model.NodeOnline:
			dashboard.OnlineNodes++
		case model.NodeOffline:
			dashboard.OfflineNodes++
		case model.NodePending:
			dashboard.PendingNodes++
		}
		if publicNode.ChecksTotal > publicNode.ChecksUp {
			dashboard.DegradedNodes++
		}
	}
	return dashboard
}

func writePublicDashboard(w http.ResponseWriter, body []byte) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=5, stale-while-revalidate=15")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func coarsePercent(value float64) int {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return 0
	}
	return clampPercent(int(math.Round(value)))
}

func percentOf(used, total uint64) int {
	if total == 0 {
		return 0
	}
	return clampPercent(int(math.Round(float64(used) / float64(total) * 100)))
}

func publicDiskPercent(disks []model.DiskMetric) int {
	var used, total uint64
	for _, disk := range disks {
		if ^uint64(0)-used < disk.UsedBytes {
			used = ^uint64(0)
		} else {
			used += disk.UsedBytes
		}
		if ^uint64(0)-total < disk.TotalBytes {
			total = ^uint64(0)
		} else {
			total += disk.TotalBytes
		}
	}
	if total == 0 {
		return 0
	}
	return percentOf(used, total)
}

func clampPercent(value int) int {
	if value < 0 {
		return 0
	}
	if value > 100 {
		return 100
	}
	return value
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request, session auth.Session) {
	limit := queryInt(r, "limit", 100, 1, 500)
	events, err := s.store.ListAudit(r.Context(), limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to load audit events")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": events})
}

func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request, session auth.Session) {
	rules, err := s.store.ListAlertRules(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to load alert rules")
		return
	}
	channels, err := s.store.ListNotificationChannels(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to load notification channels")
		return
	}
	events, err := s.store.ListAlertEvents(r.Context(), queryInt(r, "limit", 50, 1, 500))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to load alert events")
		return
	}
	active, err := s.store.CountActiveAlerts(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to load alert state")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"rules": rules, "channels": channels, "events": events, "active_alerts": active, "notification_ready": s.alerts.box != nil})
}

func (s *Server) handleAlertEvents(w http.ResponseWriter, r *http.Request, session auth.Session) {
	events, err := s.store.ListAlertEvents(r.Context(), queryInt(r, "limit", 100, 1, 500))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to load alert events")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": events})
}

type alertRuleRequest struct {
	Name            string   `json:"name"`
	Type            string   `json:"type"`
	Enabled         *bool    `json:"enabled"`
	Threshold       float64  `json:"threshold"`
	DurationSeconds int      `json:"duration_seconds"`
	CooldownSeconds int      `json:"cooldown_seconds"`
	ChannelIDs      []string `json:"channel_ids,omitempty"`
}

func (s *Server) handleCreateAlertRule(w http.ResponseWriter, r *http.Request, session auth.Session) {
	var input alertRuleRequest
	if err := decodeJSON(w, r, 8192, &input); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	rule, err := normalizeAlertRuleRequest(input, "")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	rule.ID, err = newOpaqueID("rule", 12)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to generate alert rule id")
		return
	}
	if err := s.store.CreateAlertRule(r.Context(), rule); err != nil {
		writeError(w, http.StatusConflict, "unable to create alert rule")
		return
	}
	_ = s.store.AddAudit(r.Context(), session.Username, "alert_rule_created", rule.ID, map[string]any{"type": rule.Type})
	writeJSON(w, http.StatusCreated, rule)
}

func (s *Server) handleUpdateAlertRule(w http.ResponseWriter, r *http.Request, session auth.Session) {
	var input alertRuleRequest
	if err := decodeJSON(w, r, 8192, &input); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	rule, err := normalizeAlertRuleRequest(input, r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.store.UpdateAlertRule(r.Context(), rule); errors.Is(err, store.ErrAlertRuleNotFound) {
		writeError(w, http.StatusNotFound, "alert rule not found")
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to update alert rule")
		return
	}
	_ = s.store.AddAudit(r.Context(), session.Username, "alert_rule_updated", rule.ID, map[string]any{"type": rule.Type})
	writeJSON(w, http.StatusOK, rule)
}

func (s *Server) handleDeleteAlertRule(w http.ResponseWriter, r *http.Request, session auth.Session) {
	id := r.PathValue("id")
	if !validate.Identifier(id) {
		writeError(w, http.StatusBadRequest, "invalid alert rule id")
		return
	}
	if err := s.store.DeleteAlertRule(r.Context(), id); errors.Is(err, store.ErrAlertRuleNotFound) {
		writeError(w, http.StatusNotFound, "alert rule not found")
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to delete alert rule")
		return
	}
	_ = s.store.AddAudit(r.Context(), session.Username, "alert_rule_deleted", id, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleCreateNotificationChannel(w http.ResponseWriter, r *http.Request, session auth.Session) {
	if s.alerts.box == nil {
		writeError(w, http.StatusServiceUnavailable, "set NYASM_NOTIFICATION_KEY before creating notification channels")
		return
	}
	var input struct {
		Name   string `json:"name"`
		Type   string `json:"type"`
		Target string `json:"target"`
		Secret string `json:"secret"`
	}
	if err := decodeJSON(w, r, 8192, &input); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	input.Name = strings.TrimSpace(input.Name)
	input.Type = strings.TrimSpace(strings.ToLower(input.Type))
	input.Target = strings.TrimSpace(input.Target)
	if input.Name == "" || len(input.Name) > 128 {
		writeError(w, http.StatusBadRequest, "invalid notification channel name")
		return
	}
	if err := validateNotificationTarget(input.Type, input.Target, input.Secret); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	target, err := s.alerts.box.seal(input.Target)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to encrypt notification target")
		return
	}
	secret := ""
	if input.Secret != "" {
		secret, err = s.alerts.box.seal(input.Secret)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "unable to encrypt notification secret")
			return
		}
	}
	id, err := newOpaqueID("channel", 12)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to generate notification channel id")
		return
	}
	channel := model.NotificationChannel{ID: id, Name: input.Name, Type: input.Type, Enabled: true, Target: "已配置的" + input.Type + "渠道"}
	if err := s.store.CreateNotificationChannel(r.Context(), store.NotificationChannelRecord{Channel: channel, TargetCiphertext: target, SecretCiphertext: secret}); err != nil {
		writeError(w, http.StatusConflict, "unable to create notification channel")
		return
	}
	_ = s.store.AddAudit(r.Context(), session.Username, "notification_channel_created", id, map[string]any{"type": input.Type})
	writeJSON(w, http.StatusCreated, channel)
}

func (s *Server) handleDeleteNotificationChannel(w http.ResponseWriter, r *http.Request, session auth.Session) {
	id := r.PathValue("id")
	if !validate.Identifier(id) {
		writeError(w, http.StatusBadRequest, "invalid notification channel id")
		return
	}
	if err := s.store.DeleteNotificationChannel(r.Context(), id); errors.Is(err, store.ErrNotificationChannelNotFound) {
		writeError(w, http.StatusNotFound, "notification channel not found")
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to delete notification channel")
		return
	}
	_ = s.store.AddAudit(r.Context(), session.Username, "notification_channel_deleted", id, nil)
	w.WriteHeader(http.StatusNoContent)
}

func normalizeAlertRuleRequest(input alertRuleRequest, id string) (model.AlertRule, error) {
	input.Name = strings.TrimSpace(input.Name)
	input.Type = strings.TrimSpace(strings.ToLower(input.Type))
	if input.Name == "" || len(input.Name) > 128 {
		return model.AlertRule{}, errors.New("alert rule name must be 1-128 characters")
	}
	if !validateAlertRuleType(input.Type) {
		return model.AlertRule{}, errors.New("unsupported alert rule type")
	}
	if input.DurationSeconds < 0 || input.DurationSeconds > 7*24*60*60 || input.CooldownSeconds < 0 || input.CooldownSeconds > 30*24*60*60 {
		return model.AlertRule{}, errors.New("invalid alert duration or cooldown")
	}
	if math.IsNaN(input.Threshold) || math.IsInf(input.Threshold, 0) {
		return model.AlertRule{}, errors.New("invalid alert threshold")
	}
	switch input.Type {
	case model.AlertCPUHigh, model.AlertMemoryHigh, model.AlertDiskHigh:
		if input.Threshold <= 0 || input.Threshold > 100 {
			return model.AlertRule{}, errors.New("resource threshold must be between 0 and 100")
		}
	case model.AlertLatencyHigh:
		if input.Threshold <= 0 || input.Threshold > 24*60*60*1000 {
			return model.AlertRule{}, errors.New("latency threshold is out of range")
		}
	case model.AlertPacketLossHigh:
		if input.Threshold <= 0 || input.Threshold > 100 {
			return model.AlertRule{}, errors.New("packet loss threshold must be between 0 and 100")
		}
	case model.AlertTLSExpiring:
		if input.Threshold < time.Hour.Seconds() || input.Threshold > (365*24*time.Hour).Seconds() {
			return model.AlertRule{}, errors.New("TLS expiration threshold is out of range")
		}
	default:
		input.Threshold = 0
	}
	if len(input.ChannelIDs) > 16 {
		return model.AlertRule{}, errors.New("too many notification channels")
	}
	seen := make(map[string]struct{}, len(input.ChannelIDs))
	for _, channelID := range input.ChannelIDs {
		if !validate.Identifier(channelID) {
			return model.AlertRule{}, errors.New("invalid notification channel id")
		}
		if _, ok := seen[channelID]; ok {
			return model.AlertRule{}, errors.New("duplicate notification channel id")
		}
		seen[channelID] = struct{}{}
	}
	enabled := true
	if input.Enabled != nil {
		enabled = *input.Enabled
	}
	return model.AlertRule{ID: id, Name: input.Name, Type: input.Type, Enabled: enabled, Threshold: input.Threshold, DurationSeconds: input.DurationSeconds, CooldownSeconds: input.CooldownSeconds, ChannelIDs: input.ChannelIDs}, nil
}

func validateAlertRuleType(value string) bool {
	switch value {
	case model.AlertNodeOffline, model.AlertServiceDown, model.AlertCPUHigh, model.AlertMemoryHigh, model.AlertDiskHigh, model.AlertLatencyHigh, model.AlertPacketLossHigh, model.AlertTLSExpiring, model.AlertTLSChanged, model.AlertTLSInvalid:
		return true
	default:
		return false
	}
}

func (s *Server) handleControllerInfo(w http.ResponseWriter, r *http.Request, session auth.Session) {
	release := s.nodeRelease()
	writeJSON(w, http.StatusOK, map[string]any{
		"version":              sharedversion.Version,
		"public_url":           s.cfg.PublicURL,
		"report_path":          reportPath,
		"node_control_channel": "websocket",
		"node_update_enabled":  release.UpdateEnabled,
		"node_update_version":  release.Manifest.Version,
	})
}

type nodeMetadataRequest struct {
	Name            string   `json:"name"`
	Group           string   `json:"group,omitempty"`
	Tags            []string `json:"tags,omitempty"`
	IPOverride      *string  `json:"ip_override"`
	CountryOverride *string  `json:"country_override"`
	IP              *string  `json:"ip"`
	Country         *string  `json:"country"`
}

func normalizeNodeMetadata(input *nodeMetadataRequest) error {
	input.Name = strings.TrimSpace(input.Name)
	input.Group = strings.TrimSpace(input.Group)
	if input.Name == "" || len(input.Name) > 128 || len(input.Group) > 64 || len(input.Tags) > 16 {
		return errors.New("invalid node metadata")
	}
	for index, tag := range input.Tags {
		input.Tags[index] = strings.TrimSpace(tag)
		if input.Tags[index] == "" || len(input.Tags[index]) > 32 || strings.ContainsAny(input.Tags[index], "\r\n") {
			return errors.New("invalid node tag")
		}
	}
	return nil
}

func normalizeNodeOverrides(input *nodeMetadataRequest) (string, string, error) {
	ipValue := input.IPOverride
	if ipValue == nil {
		ipValue = input.IP
	}
	countryValue := input.CountryOverride
	if countryValue == nil {
		countryValue = input.Country
	}
	ipOverride := ""
	if ipValue != nil {
		ipOverride = strings.TrimSpace(*ipValue)
		if len(ipOverride) > 64 || strings.ContainsAny(ipOverride, "\r\n\x00") {
			return "", "", errors.New("invalid IP override")
		}
		if ipOverride != "" && net.ParseIP(strings.Trim(ipOverride, "[]")) == nil {
			return "", "", errors.New("invalid IP override")
		}
		if parsed := net.ParseIP(strings.Trim(ipOverride, "[]")); parsed != nil {
			if ipv4 := parsed.To4(); ipv4 != nil {
				ipOverride = ipv4.String()
			} else {
				ipOverride = parsed.String()
			}
		}
	}
	countryOverride := ""
	if countryValue != nil {
		countryOverride = strings.TrimSpace(*countryValue)
		if len(countryOverride) > 128 || strings.ContainsAny(countryOverride, "\r\n\x00") {
			return "", "", errors.New("invalid country override")
		}
	}
	return ipOverride, countryOverride, nil
}

func (s *Server) handleCreateNode(w http.ResponseWriter, r *http.Request, session auth.Session) {
	var input nodeMetadataRequest
	if err := decodeJSON(w, r, 8192, &input); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := normalizeNodeMetadata(&input); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	ipOverride, countryOverride, err := normalizeNodeOverrides(&input)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	id, err := newOpaqueID("node", 16)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to generate node id")
		return
	}
	token, err := newToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to generate node token")
		return
	}
	tokenCiphertext, err := s.sealNodeToken(token)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to protect node token")
		return
	}
	node := model.Node{ID: id, Name: input.Name, Group: input.Group, Tags: input.Tags, Status: model.NodePending, IPOverride: ipOverride, CountryOverride: countryOverride}
	if err := s.store.CreateNode(r.Context(), node, sharedcrypto.HashToken(token), tokenCiphertext); err != nil {
		writeError(w, http.StatusInternalServerError, "unable to create node")
		return
	}
	_ = s.store.AddAudit(r.Context(), session.Username, "node_created", id, map[string]any{"name": input.Name})
	writeJSON(w, http.StatusCreated, nodeCredentialResponse(s.cfg, node, token))
}

func (s *Server) handleUpdateNodeMetadata(w http.ResponseWriter, r *http.Request, session auth.Session) {
	var input nodeMetadataRequest
	if err := decodeJSON(w, r, 8192, &input); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := normalizeNodeMetadata(&input); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	current, err := s.store.GetNode(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNodeNotFound) {
		writeError(w, http.StatusNotFound, "node not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to load node metadata")
		return
	}
	ipOverride, countryOverride, err := normalizeNodeOverrides(&input)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if input.IPOverride == nil && input.IP == nil {
		ipOverride = current.IPOverride
	}
	if input.CountryOverride == nil && input.Country == nil {
		countryOverride = current.CountryOverride
	}
	node, err := s.store.UpdateNodeMetadataWithOverrides(r.Context(), r.PathValue("id"), input.Name, input.Group, input.Tags, ipOverride, countryOverride)
	if errors.Is(err, store.ErrNodeNotFound) {
		writeError(w, http.StatusNotFound, "node not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to update node metadata")
		return
	}
	_ = s.store.AddAudit(r.Context(), session.Username, "node_metadata_updated", node.ID, map[string]any{
		"name":             node.Name,
		"group":            node.Group,
		"tags":             node.Tags,
		"ip_override":      node.IPOverride,
		"country_override": node.CountryOverride,
	})
	shouldLookupCountry := current.IPOverride != node.IPOverride
	if current.CountryOverride != "" && node.CountryOverride == "" && node.Country == "" {
		if err := s.store.ResetCountryLookup(r.Context(), node.ID); err != nil && !errors.Is(err, store.ErrNodeNotFound) {
			s.log.Warn("reset node country lookup failed", "node_id", node.ID, "error", err)
		}
		shouldLookupCountry = true
	}
	if shouldLookupCountry {
		if err := s.queueNodeCountryLookup(r.Context(), node.ID, displayNodeIP(node)); err != nil {
			s.log.Warn("queue node country lookup after IP metadata change failed", "node_id", node.ID, "error", err)
		}
	}
	writeJSON(w, http.StatusOK, node)
}

func (s *Server) handleListNodes(w http.ResponseWriter, r *http.Request, session auth.Session) {
	_ = s.store.MarkOffline(r.Context(), time.Now().UTC().Add(-s.cfg.OfflineAfter))
	nodes, err := s.store.ListNodes(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to load nodes")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"nodes": nodes, "offline_after_seconds": int(s.cfg.OfflineAfter.Seconds())})
}

func (s *Server) handleGetNode(w http.ResponseWriter, r *http.Request, session auth.Session) {
	node, err := s.store.GetNode(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNodeNotFound) {
		writeError(w, http.StatusNotFound, "node not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to load node")
		return
	}
	writeJSON(w, http.StatusOK, node)
}

func (s *Server) handleNodeMetrics(w http.ResponseWriter, r *http.Request, session auth.Session) {
	id := r.PathValue("id")
	if _, err := s.store.GetNode(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNodeNotFound) {
			writeError(w, http.StatusNotFound, "node not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to load node")
		return
	}
	hours := queryInt(r, "hours", 24, 1, 24*30)
	limit := queryInt(r, "limit", 500, 1, 2000)
	samples, err := s.store.ListMetrics(r.Context(), id, time.Now().UTC().Add(-time.Duration(hours)*time.Hour), limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to load metrics")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"node_id": id, "samples": samples})
}

func (s *Server) handleRotateToken(w http.ResponseWriter, r *http.Request, session auth.Session) {
	id := r.PathValue("id")
	node, err := s.store.GetNode(r.Context(), id)
	if errors.Is(err, store.ErrNodeNotFound) {
		writeError(w, http.StatusNotFound, "node not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to load node")
		return
	}
	token, err := newToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to generate node token")
		return
	}
	tokenCiphertext, err := s.sealNodeToken(token)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to protect node token")
		return
	}
	if err := s.store.SetNodeTokenHash(r.Context(), id, sharedcrypto.HashToken(token), tokenCiphertext); err != nil {
		writeError(w, http.StatusInternalServerError, "unable to rotate node token")
		return
	}
	_ = s.store.AddAudit(r.Context(), session.Username, "node_token_rotated", id, nil)
	writeJSON(w, http.StatusOK, nodeCredentialResponse(s.cfg, node, token))
}

func (s *Server) handleNodeInstall(w http.ResponseWriter, r *http.Request, session auth.Session) {
	id := r.PathValue("id")
	node, err := s.store.GetNode(r.Context(), id)
	if errors.Is(err, store.ErrNodeNotFound) {
		writeError(w, http.StatusNotFound, "node not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to load node")
		return
	}
	credential, err := s.store.GetNodeCredential(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to load node credential")
		return
	}
	if credential.TokenCiphertext == "" || s.tokenBox == nil {
		writeError(w, http.StatusConflict, "node token is not recoverable; configure NYASM_NODE_TOKEN_KEY and rotate this node token once")
		return
	}
	token, err := s.tokenBox.open(credential.TokenCiphertext)
	if err != nil || !constantTimeEqual(sharedcrypto.HashToken(token), credential.TokenHash) {
		writeError(w, http.StatusConflict, "node token cannot be recovered; rotate this node token once")
		return
	}
	_ = s.store.AddAudit(r.Context(), session.Username, "node_install_command_viewed", id, nil)
	writeJSON(w, http.StatusOK, nodeCredentialResponse(s.cfg, node, token))
}

func (s *Server) sealNodeToken(token string) (string, error) {
	if s.tokenBox == nil {
		return "", nil
	}
	return s.tokenBox.seal(token)
}

func (s *Server) handleRevokeNode(w http.ResponseWriter, r *http.Request, session auth.Session) {
	s.changeNodeRevocation(w, r, session, true)
}

func (s *Server) handleRestoreNode(w http.ResponseWriter, r *http.Request, session auth.Session) {
	s.changeNodeRevocation(w, r, session, false)
}

func (s *Server) changeNodeRevocation(w http.ResponseWriter, r *http.Request, session auth.Session, revoked bool) {
	id := r.PathValue("id")
	if err := s.store.SetNodeRevoked(r.Context(), id, revoked); errors.Is(err, store.ErrNodeNotFound) {
		writeError(w, http.StatusNotFound, "node not found")
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to update node")
		return
	}
	action := "node_restored"
	if revoked {
		action = "node_revoked"
	}
	_ = s.store.AddAudit(r.Context(), session.Username, action, id, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleAgentReport(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Content-Type") == "" || !strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "application/json") {
		writeError(w, http.StatusUnsupportedMediaType, "application/json required")
		return
	}
	nodeID := strings.TrimSpace(r.Header.Get("X-NyaSM-Node-ID"))
	timestamp := strings.TrimSpace(r.Header.Get("X-NyaSM-Timestamp"))
	nonce := strings.TrimSpace(r.Header.Get("X-NyaSM-Nonce"))
	signature := strings.TrimSpace(r.Header.Get("X-NyaSM-Signature"))
	if !validate.Identifier(nodeID) || len(timestamp) > 32 || len(nonce) < 16 || len(nonce) > 128 || len(signature) != 64 {
		writeError(w, http.StatusUnauthorized, "invalid node authentication")
		return
	}
	if _, err := base64.RawURLEncoding.DecodeString(nonce); err != nil {
		writeError(w, http.StatusUnauthorized, "invalid node authentication")
		return
	}
	sentTimestamp, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil || absInt64(time.Now().Unix()-sentTimestamp) > 5*60 {
		writeError(w, http.StatusUnauthorized, "stale node request")
		return
	}
	credential, err := s.store.GetNodeCredential(r.Context(), nodeID)
	if errors.Is(err, store.ErrNodeNotFound) || credential.Revoked {
		writeError(w, http.StatusUnauthorized, "node is not authorized")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "node authentication unavailable")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 128*1024))
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "report is too large")
		return
	}
	if !sharedcrypto.VerifyReportSignature(credential.TokenHash, http.MethodPost, reportPath, timestamp, nonce, body, signature) {
		writeError(w, http.StatusUnauthorized, "invalid node authentication")
		return
	}
	if !s.nonces.Claim(nodeID, nonce, time.Now()) {
		writeError(w, http.StatusUnauthorized, "replayed node request")
		return
	}
	var report model.Report
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&report); err != nil {
		writeError(w, http.StatusBadRequest, "invalid report")
		return
	}
	if err := ensureJSONEOF(decoder); err != nil || report.NodeID != nodeID {
		writeError(w, http.StatusBadRequest, "invalid report")
		return
	}
	if err := validate.Report(report, time.Now()); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	observedIP := remoteIP(r)
	if err := s.store.UpdateReport(r.Context(), report, observedIP); errors.Is(err, store.ErrNodeRevoked) || errors.Is(err, store.ErrNodeNotFound) {
		writeError(w, http.StatusUnauthorized, "node is not authorized")
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to save report")
		return
	}
	lookupIP := observedIP
	if node, err := s.store.GetNode(r.Context(), report.NodeID); err != nil {
		s.log.Warn("load node IP for country lookup failed", "node_id", report.NodeID, "error", err)
	} else if node.IPOverride != "" {
		lookupIP = node.IPOverride
	}
	if err := s.queueNodeCountryLookup(r.Context(), report.NodeID, lookupIP); err != nil {
		s.log.Warn("queue node country lookup failed", "node_id", report.NodeID, "error", err)
	}
	go func(nodeID string) {
		if err := s.alerts.evaluateNode(context.Background(), nodeID); err != nil {
			s.log.Warn("evaluate node alerts failed", "node_id", nodeID, "error", err)
		}
	}(report.NodeID)
	// Deliberately return no configuration, command, URL, or shell content to the node.
	writeJSON(w, http.StatusAccepted, map[string]any{"accepted": true, "server_time_unix": time.Now().Unix()})
}

func displayNodeIP(node model.Node) string {
	if strings.TrimSpace(node.IPOverride) != "" {
		return node.IPOverride
	}
	return node.LastIP
}

func (s *Server) queueNodeCountryLookup(ctx context.Context, nodeID, ip string) error {
	if s.geoIP == nil || strings.TrimSpace(ip) == "" {
		return nil
	}
	claimed, err := s.store.ClaimCountryLookup(ctx, nodeID, ip)
	if err != nil || !claimed {
		return err
	}
	if !eligibleGeoIP(net.ParseIP(strings.Trim(ip, "[]"))) {
		return nil
	}
	go func() {
		country, countryCode, err := s.geoIP.lookup(context.Background(), ip)
		if err != nil {
			s.log.Warn("node country lookup failed", "node_id", nodeID, "ip", ip, "error", err)
			return
		}
		if err := s.store.SaveNodeCountry(context.Background(), nodeID, ip, country, countryCode); err != nil && !errors.Is(err, store.ErrNodeNotFound) {
			s.log.Warn("save node country failed", "node_id", nodeID, "ip", ip, "error", err)
		}
	}()
	return nil
}

func (s *Server) handleSPA(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	data, err := webFiles.ReadFile("webdist/index.html")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "web interface unavailable")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(data)
}

type nodeCredential struct {
	Node             model.Node `json:"node"`
	Token            string     `json:"token"`
	ControllerURL    string     `json:"controller_url"`
	UpdateSigningKey string     `json:"update_signing_key,omitempty"`
	Env              string     `json:"env"`
	InstallCommand   string     `json:"install_command,omitempty"`
	InstallScriptURL string     `json:"install_script_url,omitempty"`
	BinaryURL        string     `json:"binary_url,omitempty"`
	ChecksExample    string     `json:"checks_example"`
}

func nodeCredentialResponse(cfg Config, node model.Node, token string) nodeCredential {
	controllerURL := strings.TrimRight(cfg.PublicURL, "/")
	envText := fmt.Sprintf("NYASM_CONTROLLER=%s\nNYASM_NODE_ID=%s\nNYASM_NODE_TOKEN=%s\nNYASM_DATA=/var/lib/nyasm\nNYASM_CHECKS=/etc/nyasm/checks.json\n", controllerURL, node.ID, token)
	updateSigningKey := installUpdateSigningKey(controllerURL)
	return nodeCredential{
		Node:             node,
		Token:            token,
		ControllerURL:    controllerURL,
		UpdateSigningKey: updateSigningKey,
		Env:              envText,
		InstallCommand:   installCommand(controllerURL, node.ID, token, updateSigningKey),
		InstallScriptURL: installScriptURL(controllerURL),
		BinaryURL:        nodeBinaryURL(controllerURL),
		ChecksExample:    `[{"id":"homepage","name":"Homepage","type":"http","target":"https://example.com","timeout_seconds":5,"expected_status":200},{"id":"gateway-ping","name":"Gateway ping","type":"ping","target":"1.1.1.1","timeout_seconds":2,"attempts":3},{"id":"certificate","name":"Public certificate","type":"tls","target":"https://example.com","timeout_seconds":5}]`,
	}
}

func (s *Server) setSessionCookie(w http.ResponseWriter, session auth.Session) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: session.ID, Path: "/", MaxAge: int(time.Until(session.ExpiresAt).Seconds()), HttpOnly: true, Secure: s.cfg.CookieSecure, SameSite: http.SameSiteStrictMode})
}

func secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, limit int64, destination any) error {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return errors.New("invalid JSON request")
	}
	return ensureJSONEOF(decoder)
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("trailing JSON data")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func queryInt(r *http.Request, key string, fallback, min, max int) int {
	value, err := strconv.Atoi(r.URL.Query().Get(key))
	if err != nil || value < min {
		return fallback
	}
	if value > max {
		return max
	}
	return value
}

func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return strings.TrimSpace(r.RemoteAddr)
}

func validateAdminCredentials(username, password string) error {
	username = strings.TrimSpace(username)
	if len(username) < 3 || len(username) > 64 || strings.ContainsAny(username, "\r\n/\\") {
		return errors.New("username must be 3-64 characters")
	}
	if len(password) < 12 || len(password) > 256 {
		return errors.New("password must be 12-256 characters")
	}
	return nil
}

func newOpaqueID(prefix string, bytesCount int) (string, error) {
	raw := make([]byte, bytesCount)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return prefix + "_" + base64.RawURLEncoding.EncodeToString(raw), nil
}

func newToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func constantTimeEqual(left, right string) bool {
	return subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

func absInt64(value int64) int64 {
	if value < 0 {
		return -value
	}
	return value
}

func hasVersionArg(args []string) bool {
	for _, arg := range args {
		if arg == "--version" || arg == "-version" {
			return true
		}
	}
	return false
}

func parseLevel(value string) slog.Level {
	switch value {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
