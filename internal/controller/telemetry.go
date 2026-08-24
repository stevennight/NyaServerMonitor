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
	subscribers map[uint64]telemetrySubscriber
}

type telemetrySubscriber struct {
	public  bool
	channel chan []byte
}

func newTelemetryHub() *telemetryHub {
	return &telemetryHub{subscribers: make(map[uint64]telemetrySubscriber)}
}

func (h *telemetryHub) Subscribe(public bool) (uint64, <-chan []byte, func()) {
	h.mu.Lock()
	h.nextID++
	id := h.nextID
	channel := make(chan []byte, 1)
	h.subscribers[id] = telemetrySubscriber{public: public, channel: channel}
	h.mu.Unlock()

	var once sync.Once
	unsubscribe := func() {
		once.Do(func() {
			h.mu.Lock()
			if current, ok := h.subscribers[id]; ok {
				delete(h.subscribers, id)
				close(current.channel)
			}
			h.mu.Unlock()
		})
	}
	return id, channel, unsubscribe
}

func (h *telemetryHub) Publish(telemetry model.LiveTelemetry) {
	adminData, err := json.Marshal(telemetry)
	if err != nil {
		return
	}
	publicData, err := json.Marshal(sanitizePublicLiveTelemetry(telemetry))
	if err != nil {
		return
	}
	adminEvent := telemetrySSEEvent(adminData)
	publicEvent := telemetrySSEEvent(publicData)

	h.mu.Lock()
	defer h.mu.Unlock()
	for _, subscriber := range h.subscribers {
		event := adminEvent
		if subscriber.public {
			event = publicEvent
		}
		select {
		case subscriber.channel <- event:
		default:
			// Replace a queued sample so a slow browser receives the newest state.
			select {
			case <-subscriber.channel:
			default:
			}
			select {
			case subscriber.channel <- event:
			default:
			}
		}
	}
}

func telemetrySSEEvent(data []byte) []byte {
	event := make([]byte, 0, len(data)+32)
	event = append(event, "event: telemetry\ndata: "...)
	event = append(event, data...)
	event = append(event, '\n', '\n')
	return event
}

type publicLiveTelemetry struct {
	NodeID              string                    `json:"node_id"`
	Sequence            uint64                    `json:"sequence"`
	ObservedAtUnixMilli int64                     `json:"observed_at_unix_milli"`
	MetricsAvailable    bool                      `json:"metrics_available"`
	CPUPercent          int                       `json:"cpu_percent,omitempty"`
	MemoryPercent       int                       `json:"memory_percent,omitempty"`
	DiskPercent         int                       `json:"disk_percent,omitempty"`
	Load1               float64                   `json:"load1,omitempty"`
	UptimeSeconds       uint64                    `json:"uptime_seconds,omitempty"`
	NetworkInBytes      uint64                    `json:"network_in_bytes,omitempty"`
	NetworkOutBytes     uint64                    `json:"network_out_bytes,omitempty"`
	Networks            []publicLiveNetworkMetric `json:"networks,omitempty"`
}

type publicLiveNetworkMetric struct {
	BytesInPerSecond  uint64 `json:"bytes_in_per_second"`
	BytesOutPerSecond uint64 `json:"bytes_out_per_second"`
}

func sanitizePublicLiveTelemetry(telemetry model.LiveTelemetry) publicLiveTelemetry {
	public := publicLiveTelemetry{
		NodeID:              publicNodeID(telemetry.NodeID),
		Sequence:            telemetry.Sequence,
		ObservedAtUnixMilli: telemetry.ObservedAtUnixMilli,
		MetricsAvailable:    telemetry.MetricsAvailable,
	}
	var networkIn, networkOut uint64
	for _, network := range telemetry.Networks {
		networkIn += network.BytesInPerSecond
		networkOut += network.BytesOutPerSecond
	}
	if len(telemetry.Networks) > 0 {
		public.Networks = []publicLiveNetworkMetric{{BytesInPerSecond: networkIn, BytesOutPerSecond: networkOut}}
	}
	if telemetry.MetricsAvailable {
		public.CPUPercent = coarsePercent(telemetry.Metrics.CPUPercent)
		public.MemoryPercent = percentOf(telemetry.Metrics.MemoryUsedBytes, telemetry.Metrics.MemoryTotalBytes)
		public.DiskPercent = publicDiskPercent(telemetry.Metrics.Disks)
		public.Load1 = telemetry.Metrics.Load1
		public.UptimeSeconds = telemetry.Metrics.UptimeSeconds
		for _, network := range telemetry.Metrics.Networks {
			public.NetworkInBytes += network.BytesIn
			public.NetworkOutBytes += network.BytesOut
		}
	}
	return public
}

func (s *Server) handleTelemetryStream(w http.ResponseWriter, r *http.Request, session auth.Session) {
	s.serveTelemetryStream(w, r, false, session)
}

func (s *Server) handlePublicTelemetryStream(w http.ResponseWriter, r *http.Request) {
	s.serveTelemetryStream(w, r, true, auth.Session{})
}

func (s *Server) serveTelemetryStream(w http.ResponseWriter, r *http.Request, public bool, session auth.Session) {
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
	_, events, unsubscribe := s.telemetry.Subscribe(public)
	defer unsubscribe()
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte(": connected\n\n")); err != nil {
		return
	}
	flusher.Flush()

	keepalive := time.NewTicker(15 * time.Second)
	defer keepalive.Stop()
	var sessionCheck *time.Ticker
	if !public {
		sessionCheck = time.NewTicker(30 * time.Second)
		defer sessionCheck.Stop()
	}
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
		case <-sessionCheckChannel(sessionCheck):
			if !public {
				if _, ok := s.sessions.Get(session.ID); !ok {
					return
				}
			}
		}
	}
}

func sessionCheckChannel(ticker *time.Ticker) <-chan time.Time {
	if ticker == nil {
		return nil
	}
	return ticker.C
}
