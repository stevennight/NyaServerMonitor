package controller

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"

	"nyaservermonitor/internal/controller/auth"
	"nyaservermonitor/internal/controller/nodehub"
	"nyaservermonitor/internal/controller/store"
	sharedcrypto "nyaservermonitor/internal/shared/crypto"
	"nyaservermonitor/internal/shared/model"
	sharedprotocol "nyaservermonitor/internal/shared/protocol"
	sharedversion "nyaservermonitor/internal/shared/version"
)

const (
	controlWebSocketReadLimit  int64 = 256 * 1024
	controlWebSocketHelloLimit       = 10 * time.Second
	controlWebSocketIdleLimit        = 90 * time.Second
	maxNodeVersionBytes              = 128
	maxNodeMetadataBytes             = 256
	maxNodeUpdateErrorBytes          = 2048
)

func (s *Server) withNode(next func(http.ResponseWriter, *http.Request, model.Node)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		nodeID := strings.TrimSpace(r.Header.Get("X-NyaSM-Node-ID"))
		token := strings.TrimSpace(r.Header.Get("X-NyaSM-Node-Token"))
		if !validateIdentifier(nodeID) || len(token) < 32 || len(token) > 256 {
			writeError(w, http.StatusUnauthorized, "node is not authorized")
			return
		}
		credential, err := s.store.GetNodeCredential(r.Context(), nodeID)
		if errors.Is(err, store.ErrNodeNotFound) || credential.Revoked || !constantTimeEqual(sharedcrypto.HashToken(token), credential.TokenHash) {
			writeError(w, http.StatusUnauthorized, "node is not authorized")
			return
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, "node authentication unavailable")
			return
		}
		next(w, r, credential.Node)
	}
}

func (s *Server) handleUpdateNode(w http.ResponseWriter, r *http.Request, session auth.Session) {
	nodeID := r.PathValue("id")
	release := s.nodeRelease()
	if !release.UpdateEnabled {
		writeError(w, http.StatusConflict, "node release is unavailable; publish a signed node release first")
		return
	}
	node, err := s.requestNodeUpdate(r.Context(), nodeID)
	if errors.Is(err, store.ErrNodeNotFound) {
		writeError(w, http.StatusNotFound, "node not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	_ = s.store.AddAudit(r.Context(), session.Username, "node_update_requested", nodeID, map[string]any{"version": release.Manifest.Version})
	if err := s.pushNodeUpdate(r.Context(), nodeID); err != nil && !errors.Is(err, nodehub.ErrNotConnected) {
		s.log.Warn("push node update failed", "node_id", nodeID, "error", err)
	}
	writeJSON(w, http.StatusOK, node)
}

func (s *Server) handleUpdateAllNodes(w http.ResponseWriter, r *http.Request, session auth.Session) {
	release := s.nodeRelease()
	if !release.UpdateEnabled {
		writeError(w, http.StatusConflict, "node release is unavailable; publish a signed node release first")
		return
	}
	nodes, err := s.store.ListNodes(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to load nodes")
		return
	}
	requested := 0
	for _, node := range nodes {
		if node.Status == model.NodeRevoked || !sharedversion.NeedsUpdate(node.AgentVersion, release.Manifest.Version) {
			continue
		}
		if _, err := s.requestNodeUpdate(r.Context(), node.ID); err != nil {
			continue
		}
		requested++
		if err := s.pushNodeUpdate(r.Context(), node.ID); err != nil && !errors.Is(err, nodehub.ErrNotConnected) {
			s.log.Warn("push node update failed", "node_id", node.ID, "error", err)
		}
	}
	_ = s.store.AddAudit(r.Context(), session.Username, "node_updates_requested", "nodes", map[string]any{"version": release.Manifest.Version, "count": requested})
	writeJSON(w, http.StatusOK, map[string]any{"version": release.Manifest.Version, "requested": requested})
}

func (s *Server) requestNodeUpdate(ctx context.Context, nodeID string) (model.Node, error) {
	release := s.nodeRelease()
	if !release.UpdateEnabled {
		return model.Node{}, fmt.Errorf("node release is unavailable")
	}
	node, err := s.store.GetNode(ctx, nodeID)
	if err != nil {
		return model.Node{}, err
	}
	if node.Status == model.NodeRevoked {
		return model.Node{}, store.ErrNodeNotFound
	}
	if !sharedversion.NeedsUpdate(node.AgentVersion, release.Manifest.Version) {
		return node, nil
	}
	return s.store.RequestNodeUpdate(ctx, node.ID, release.Manifest.Version)
}

func (s *Server) pushNodeUpdate(ctx context.Context, nodeID string) error {
	node, err := s.store.GetNode(ctx, nodeID)
	if err != nil {
		return err
	}
	if node.DesiredVersion == "" || !sharedversion.NeedsUpdate(node.AgentVersion, node.DesiredVersion) {
		return nil
	}
	release := s.nodeRelease()
	if !release.UpdateEnabled {
		return errors.New("node release is unavailable")
	}
	if release.Manifest.Version != node.DesiredVersion {
		return errors.New("requested node release is no longer available")
	}
	return s.hub.SendContext(ctx, nodeID, sharedprotocol.ControlMessage{
		Type:   "update",
		NodeID: nodeID,
		Update: &model.NodeUpdateCommand{
			Version:      release.Manifest.Version,
			Manifest:     release.Manifest,
			Signature:    release.Signature,
			SigningKeyID: release.SigningKeyID,
		},
	})
}

func (s *Server) handleNodeWS(w http.ResponseWriter, r *http.Request, node model.Node) {
	conn, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	defer func() { _ = conn.Close(websocket.StatusNormalClosure, "bye") }()
	conn.SetReadLimit(controlWebSocketReadLimit)

	var hello sharedprotocol.ControlMessage
	helloCtx, cancelHello := context.WithTimeout(r.Context(), controlWebSocketHelloLimit)
	err = wsjson.Read(helloCtx, conn, &hello)
	cancelHello()
	if err != nil || hello.Type != "hello" || validateNodeHello(node.ID, hello) != nil {
		return
	}
	current, err := s.store.GetNode(r.Context(), node.ID)
	if err != nil || current.Status == model.NodeRevoked {
		return
	}
	if err := s.store.MarkNodeSeen(r.Context(), node.ID, hello.System, hello.Version); err != nil {
		return
	}
	s.nodeSocketMu.Lock()
	s.hub.RegisterSocket(node.ID, conn)
	s.nodeSocketMu.Unlock()
	defer func() { _ = s.hub.UnregisterSocket(node.ID, conn) }()

	if err := s.pushNodeUpdate(r.Context(), node.ID); err != nil && !errors.Is(err, nodehub.ErrNotConnected) {
		s.log.Warn("send node update failed", "node_id", node.ID, "error", err)
	}

	for {
		var message sharedprotocol.ControlMessage
		readCtx, cancelRead := context.WithTimeout(r.Context(), controlWebSocketIdleLimit)
		err := wsjson.Read(readCtx, conn, &message)
		cancelRead()
		if err != nil {
			logNodeControlReadFailure(s.log, r.Context(), err, node.ID)
			return
		}
		if err := validateNodeControlMessage(node.ID, message); err != nil {
			s.log.Warn("node websocket message rejected", "node_id", node.ID, "error", err)
			return
		}
		switch message.Type {
		case "heartbeat":
			if err := s.store.MarkNodeSeen(r.Context(), node.ID, message.System, message.Version); err != nil {
				return
			}
			if message.UpdateReport != nil {
				if err := s.store.UpdateNodeReport(r.Context(), node.ID, *message.UpdateReport); err != nil {
					s.log.Warn("save node update report failed", "node_id", node.ID, "error", err)
				}
			}
		case "update_status":
			if err := s.store.UpdateNodeReport(r.Context(), node.ID, *message.UpdateReport); err != nil {
				s.log.Warn("save node update report failed", "node_id", node.ID, "error", err)
			}
		}
	}
}

func validateNodeHello(expectedID string, hello sharedprotocol.ControlMessage) error {
	if hello.NodeID != expectedID {
		return errors.New("node id does not match websocket credential")
	}
	return validateNodeHeartbeat(hello.Version, hello.System)
}

func validateNodeControlMessage(expectedID string, message sharedprotocol.ControlMessage) error {
	if message.NodeID != expectedID {
		return errors.New("node id does not match websocket credential")
	}
	switch message.Type {
	case "heartbeat":
		if err := validateNodeHeartbeat(message.Version, message.System); err != nil {
			return err
		}
		if message.UpdateReport != nil {
			return validateNodeUpdateReport(*message.UpdateReport)
		}
	case "update_status":
		if message.UpdateReport == nil {
			return errors.New("update status is required")
		}
		return validateNodeUpdateReport(*message.UpdateReport)
	default:
		return fmt.Errorf("unsupported node websocket message type %q", message.Type)
	}
	return nil
}

func validateNodeHeartbeat(version string, system model.SystemInfo) error {
	if err := validateNodeText("node version", version, maxNodeVersionBytes, false); err != nil {
		return err
	}
	for field, value := range map[string]string{
		"hostname": system.Hostname,
		"os":       system.OS,
		"arch":     system.Arch,
		"kernel":   system.Kernel,
		"ip":       system.IP,
	} {
		if err := validateNodeText("node "+field, value, maxNodeMetadataBytes, true); err != nil {
			return err
		}
	}
	if system.IP != "" && net.ParseIP(strings.Trim(system.IP, "[]")) == nil {
		return errors.New("node IP is invalid")
	}
	return nil
}

func validateNodeUpdateReport(report model.NodeUpdateReport) error {
	switch report.Status {
	case model.NodeUpdateIdle, model.NodeUpdateRequested, model.NodeUpdateRunning, model.NodeUpdateSucceeded, model.NodeUpdateFailed:
	default:
		return fmt.Errorf("unsupported node update status %q", report.Status)
	}
	if report.Version != "" {
		if err := validateNodeText("update version", report.Version, maxNodeVersionBytes, true); err != nil {
			return err
		}
	}
	return validateNodeText("update error", report.Error, maxNodeUpdateErrorBytes, true)
}

func validateNodeText(field, value string, maxBytes int, emptyAllowed bool) error {
	if !emptyAllowed && value == "" {
		return fmt.Errorf("%s is required", field)
	}
	if len(value) > maxBytes || strings.ContainsAny(value, "\r\n\x00") {
		return fmt.Errorf("%s is invalid", field)
	}
	return nil
}

func validateIdentifier(value string) bool {
	if value == "" || len(value) > 128 || strings.ContainsAny(value, "/\\\r\n\x00") {
		return false
	}
	return true
}

func logNodeControlReadFailure(log *slog.Logger, ctx context.Context, err error, nodeID string) {
	status := websocket.CloseStatus(err)
	if ctx.Err() != nil || status == websocket.StatusNormalClosure || status == websocket.StatusGoingAway {
		log.Debug("node websocket closed", "node_id", nodeID, "error", err)
		return
	}
	log.Warn("node websocket read failed", "node_id", nodeID, "error", err)
}
