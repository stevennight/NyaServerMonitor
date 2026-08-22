package controller

import (
	"bytes"
	"context"
	"crypto/rand"
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
	"strconv"
	"strings"
	"sync"
	"time"

	"nyaservermonitor/internal/controller/auth"
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
	cfg        Config
	log        *slog.Logger
	store      *store.Store
	sessions   *auth.Sessions
	limiter    *auth.LoginLimiter
	mux        *http.ServeMux
	nonces     *nonceCache
	setupMu    sync.Mutex
	publicMu   sync.Mutex
	publicAt   time.Time
	publicBody []byte
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
		cfg:      cfg,
		log:      slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: parseLevel(cfg.LogLevel)})),
		store:    st,
		sessions: auth.NewSessions(cfg.SessionLifetime),
		limiter:  auth.NewLoginLimiter(),
		mux:      http.NewServeMux(),
		nonces:   newNonceCache(),
	}
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
	s.mux.HandleFunc("GET /api/dashboard", s.withAuth(s.handleDashboard))
	s.mux.HandleFunc("GET /api/audit", s.withAuth(s.handleAudit))
	s.mux.HandleFunc("GET /api/controller/info", s.withAuth(s.handleControllerInfo))
	s.mux.HandleFunc("GET /api/nodes", s.withAuth(s.handleListNodes))
	s.mux.HandleFunc("POST /api/nodes", s.withAuth(s.handleCreateNode))
	s.mux.HandleFunc("GET /api/nodes/{id}", s.withAuth(s.handleGetNode))
	s.mux.HandleFunc("GET /api/nodes/{id}/metrics", s.withAuth(s.handleNodeMetrics))
	s.mux.HandleFunc("POST /api/nodes/{id}/rotate-token", s.withAuth(s.handleRotateToken))
	s.mux.HandleFunc("POST /api/nodes/{id}/revoke", s.withAuth(s.handleRevokeNode))
	s.mux.HandleFunc("POST /api/nodes/{id}/restore", s.withAuth(s.handleRestoreNode))
	s.mux.HandleFunc("GET /install.sh", s.handleInstallScript)
	s.mux.HandleFunc("GET /downloads/nyasm-node", s.handleDownloadNodeBinary)
	// This is the only public node endpoint. It accepts reports and has no response data channel.
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
	dashboard := model.Dashboard{Nodes: nodes, RecentEvents: events, GeneratedAtUnix: time.Now().Unix()}
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
	s.publicMu.Lock()
	if len(s.publicBody) > 0 && now.Sub(s.publicAt) < publicDashboardCacheTTL {
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
	body, err := json.Marshal(buildPublicDashboard(nodes, now.Unix()))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "public dashboard unavailable")
		return
	}
	s.publicMu.Lock()
	s.publicAt = now
	s.publicBody = append(s.publicBody[:0], body...)
	s.publicMu.Unlock()
	writePublicDashboard(w, body)
}

func buildPublicDashboard(nodes []model.Node, generatedAtUnix int64) model.PublicDashboard {
	dashboard := model.PublicDashboard{GeneratedAtUnix: generatedAtUnix, Nodes: make([]model.PublicNode, 0, len(nodes))}
	for _, node := range nodes {
		if node.Status == model.NodeRevoked {
			continue
		}
		publicNode := model.PublicNode{
			Name:          node.Name,
			Status:        node.Status,
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
	if len(disks) == 0 {
		return 0
	}
	return percentOf(disks[0].UsedBytes, disks[0].TotalBytes)
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

func (s *Server) handleControllerInfo(w http.ResponseWriter, r *http.Request, session auth.Session) {
	writeJSON(w, http.StatusOK, map[string]any{"version": sharedversion.Version, "public_url": s.cfg.PublicURL, "report_path": reportPath, "node_control_channel": false})
}

type createNodeRequest struct {
	Name  string   `json:"name"`
	Group string   `json:"group,omitempty"`
	Tags  []string `json:"tags,omitempty"`
}

func (s *Server) handleCreateNode(w http.ResponseWriter, r *http.Request, session auth.Session) {
	var input createNodeRequest
	if err := decodeJSON(w, r, 8192, &input); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	input.Name = strings.TrimSpace(input.Name)
	input.Group = strings.TrimSpace(input.Group)
	if input.Name == "" || len(input.Name) > 128 || len(input.Group) > 64 || len(input.Tags) > 16 {
		writeError(w, http.StatusBadRequest, "invalid node metadata")
		return
	}
	for _, tag := range input.Tags {
		if len(tag) == 0 || len(tag) > 32 || strings.ContainsAny(tag, "\r\n") {
			writeError(w, http.StatusBadRequest, "invalid node tag")
			return
		}
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
	node := model.Node{ID: id, Name: input.Name, Group: input.Group, Tags: input.Tags, Status: model.NodePending}
	if err := s.store.CreateNode(r.Context(), node, sharedcrypto.HashToken(token)); err != nil {
		writeError(w, http.StatusInternalServerError, "unable to create node")
		return
	}
	_ = s.store.AddAudit(r.Context(), session.Username, "node_created", id, map[string]any{"name": input.Name})
	writeJSON(w, http.StatusCreated, nodeCredentialResponse(s.cfg, node, token))
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
	if err := s.store.SetNodeTokenHash(r.Context(), id, sharedcrypto.HashToken(token)); err != nil {
		writeError(w, http.StatusInternalServerError, "unable to rotate node token")
		return
	}
	_ = s.store.AddAudit(r.Context(), session.Username, "node_token_rotated", id, nil)
	writeJSON(w, http.StatusOK, nodeCredentialResponse(s.cfg, node, token))
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
	if err := s.store.UpdateReport(r.Context(), report, remoteIP(r)); errors.Is(err, store.ErrNodeRevoked) || errors.Is(err, store.ErrNodeNotFound) {
		writeError(w, http.StatusUnauthorized, "node is not authorized")
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to save report")
		return
	}
	// Deliberately return no configuration, command, URL, or shell content to the node.
	writeJSON(w, http.StatusAccepted, map[string]any{"accepted": true, "server_time_unix": time.Now().Unix()})
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
	Env              string     `json:"env"`
	InstallCommand   string     `json:"install_command,omitempty"`
	InstallScriptURL string     `json:"install_script_url,omitempty"`
	BinaryURL        string     `json:"binary_url,omitempty"`
	ChecksExample    string     `json:"checks_example"`
}

func nodeCredentialResponse(cfg Config, node model.Node, token string) nodeCredential {
	controllerURL := strings.TrimRight(cfg.PublicURL, "/")
	envText := fmt.Sprintf("NYASM_CONTROLLER=%s\nNYASM_NODE_ID=%s\nNYASM_NODE_TOKEN=%s\nNYASM_DATA=/var/lib/nyasm\nNYASM_CHECKS=/etc/nyasm/checks.json\n", controllerURL, node.ID, token)
	return nodeCredential{
		Node:             node,
		Token:            token,
		ControllerURL:    controllerURL,
		Env:              envText,
		InstallCommand:   installCommand(controllerURL, node.ID, token),
		InstallScriptURL: installScriptURL(controllerURL),
		BinaryURL:        nodeBinaryURL(controllerURL),
		ChecksExample:    `[{"id":"homepage","name":"Homepage","type":"http","target":"https://example.com","timeout_seconds":5,"expected_status":200}]`,
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
