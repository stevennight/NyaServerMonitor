package nodehub

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
)

var ErrNotConnected = errors.New("node is not connected")

type Hub struct {
	mu      sync.Mutex
	sockets map[string]*socketConn
}

func New() *Hub {
	return &Hub{sockets: make(map[string]*socketConn)}
}

func (h *Hub) RegisterSocket(nodeID string, conn *websocket.Conn) {
	h.mu.Lock()
	old := h.sockets[nodeID]
	h.sockets[nodeID] = &socketConn{conn: conn}
	h.mu.Unlock()
	if old != nil {
		_ = old.Close(websocket.StatusNormalClosure, "replaced")
	}
}

func (h *Hub) UnregisterSocket(nodeID string, conn *websocket.Conn) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	current, ok := h.sockets[nodeID]
	if ok && current.conn == conn {
		delete(h.sockets, nodeID)
		return true
	}
	return false
}

func (h *Hub) NodeIDs() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	ids := make([]string, 0, len(h.sockets))
	for id := range h.sockets {
		ids = append(ids, id)
	}
	return ids
}

func (h *Hub) SendContext(ctx context.Context, nodeID string, value any) error {
	h.mu.Lock()
	socket := h.sockets[nodeID]
	h.mu.Unlock()
	if socket == nil {
		return ErrNotConnected
	}
	return socket.Send(ctx, value)
}

func (h *Hub) Close(nodeID string, code websocket.StatusCode, reason string) bool {
	h.mu.Lock()
	socket := h.sockets[nodeID]
	h.mu.Unlock()
	if socket == nil {
		return false
	}
	_ = socket.Close(code, reason)
	return true
}

type socketConn struct {
	conn *websocket.Conn
	mu   sync.Mutex
}

func (s *socketConn) Send(ctx context.Context, value any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	writeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return wsjson.Write(writeCtx, s.conn, value)
}

func (s *socketConn) Close(code websocket.StatusCode, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conn.Close(code, reason)
}
