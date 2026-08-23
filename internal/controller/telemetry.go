package controller

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"nyaservermonitor/internal/controller/auth"
	"nyaservermonitor/internal/shared/model"
)

type telemetryHub struct {
	mu          sync.Mutex
	nextID      uint64
	subscribers map[uint64]chan []byte
}

func newTelemetryHub() *telemetryHub {
	return &telemetryHub{subscribers: make(map[uint64]chan []byte)}
}

func (h *telemetryHub) Subscribe() (uint64, <-chan []byte, func()) {
	h.mu.Lock()
	h.nextID++
	id := h.nextID
	channel := make(chan []byte, 1)
	h.subscribers[id] = channel
	h.mu.Unlock()

	var once sync.Once
	unsubscribe := func() {
		once.Do(func() {
			h.mu.Lock()
			if current, ok := h.subscribers[id]; ok {
				delete(h.subscribers, id)
				close(current)
			}
			h.mu.Unlock()
		})
	}
	return id, channel, unsubscribe
}

func (h *telemetryHub) Publish(telemetry model.LiveTelemetry) {
	data, err := json.Marshal(telemetry)
	if err != nil {
		return
	}
	event := make([]byte, 0, len(data)+32)
	event = append(event, "event: telemetry\ndata: "...)
	event = append(event, data...)
	event = append(event, '\n', '\n')

	h.mu.Lock()
	defer h.mu.Unlock()
	for _, channel := range h.subscribers {
		select {
		case channel <- event:
		default:
			// Replace a queued sample so a slow browser receives the newest state.
			select {
			case <-channel:
			default:
			}
			select {
			case channel <- event:
			default:
			}
		}
	}
}

func (s *Server) handleTelemetryStream(w http.ResponseWriter, r *http.Request, session auth.Session) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming is unavailable")
		return
	}
	// The regular HTTP server has a finite write timeout for request handlers;
	// this endpoint keeps its deadline open and uses keepalives to detect peers.
	_ = http.NewResponseController(w).SetWriteDeadline(time.Time{})
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	_, events, unsubscribe := s.telemetry.Subscribe()
	defer unsubscribe()
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte(": connected\n\n")); err != nil {
		return
	}
	flusher.Flush()

	keepalive := time.NewTicker(15 * time.Second)
	defer keepalive.Stop()
	sessionCheck := time.NewTicker(30 * time.Second)
	defer sessionCheck.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case event, open := <-events:
			if !open {
				return
			}
			if _, err := w.Write(event); err != nil {
				return
			}
			flusher.Flush()
		case <-keepalive.C:
			if _, err := w.Write([]byte(": keepalive\n\n")); err != nil {
				return
			}
			flusher.Flush()
		case <-sessionCheck.C:
			if _, ok := s.sessions.Get(session.ID); !ok {
				return
			}
		}
	}
}
