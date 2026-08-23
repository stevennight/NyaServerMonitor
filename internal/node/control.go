package node

import (
	"context"
	"log/slog"
	"os/exec"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"

	"nyaservermonitor/internal/node/metrics"
	"nyaservermonitor/internal/shared/model"
	sharedprotocol "nyaservermonitor/internal/shared/protocol"
	sharedversion "nyaservermonitor/internal/shared/version"
)

const (
	controlWebSocketReadLimit    int64 = 256 * 1024
	controlWebSocketHelloTimeout       = 10 * time.Second
	controlWebSocketIdleTimeout        = 90 * time.Second
	controlHeartbeatInterval           = 20 * time.Second
	controlWriteTimeout                = 10 * time.Second
	controlPingTimeout                 = 10 * time.Second
)

func controlLoop(ctx context.Context, client *client, cfg Config, log *slog.Logger) {
	backoff := time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		conn, err := client.connectWS(ctx)
		if err != nil {
			logControlFailure(log, ctx, "control websocket connect failed", err)
			if !sleepContext(ctx, backoff) {
				return
			}
			if backoff < 30*time.Second {
				backoff *= 2
			}
			continue
		}
		backoff = time.Second
		conn.SetReadLimit(controlWebSocketReadLimit)
		connCtx, cancel := context.WithCancel(ctx)
		var writeMu sync.Mutex
		write := func(message sharedprotocol.ControlMessage) error {
			writeMu.Lock()
			defer writeMu.Unlock()
			writeCtx, cancelWrite := context.WithTimeout(connCtx, controlWriteTimeout)
			defer cancelWrite()
			return wsjson.Write(writeCtx, conn, message)
		}

		hello := sharedprotocol.ControlMessage{Type: "hello", NodeID: cfg.NodeID, Version: sharedversion.Version, System: nodeSystem()}
		helloCtx, cancelHello := context.WithTimeout(connCtx, controlWebSocketHelloTimeout)
		err = writeWithContext(helloCtx, conn, &writeMu, hello)
		cancelHello()
		if err != nil {
			logControlFailure(log, connCtx, "control websocket hello failed", err)
			cancel()
			_ = conn.CloseNow()
			continue
		}
		reportUpdateStatus(ctx, cfg, write, log)

		heartbeatDone := make(chan struct{})
		go controlHeartbeat(connCtx, conn, cfg, write, log, heartbeatDone)
		telemetryDone := make(chan struct{})
		go controlTelemetry(connCtx, conn, cfg, write, log, telemetryDone)

		for {
			var message sharedprotocol.ControlMessage
			readCtx, cancelRead := context.WithTimeout(connCtx, controlWebSocketIdleTimeout)
			err := wsjson.Read(readCtx, conn, &message)
			cancelRead()
			if err != nil {
				logControlReadFailure(log, connCtx, err)
				break
			}
			switch message.Type {
			case "update":
				if message.Update == nil {
					log.Warn("controller sent empty update command")
					continue
				}
				if err := handleUpdateCommand(cfg, *message.Update); err != nil {
					log.Warn("signed node update rejected", "error", err)
					_ = write(sharedprotocol.ControlMessage{Type: "update_status", NodeID: cfg.NodeID, UpdateReport: &model.NodeUpdateReport{Status: model.NodeUpdateFailed, Version: message.Update.Version, Error: err.Error()}})
					continue
				}
				_ = write(sharedprotocol.ControlMessage{Type: "update_status", NodeID: cfg.NodeID, UpdateReport: &model.NodeUpdateReport{Status: model.NodeUpdateRequested, Version: message.Update.Version}})
			case "error":
				if message.Error != "" {
					log.Warn("controller rejected control request", "error", message.Error)
				}
			default:
				log.Warn("controller sent unsupported control message", "type", message.Type)
			}
		}
		cancel()
		_ = conn.CloseNow()
		<-heartbeatDone
		<-telemetryDone
		if !sleepContext(ctx, backoff) {
			return
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

func controlHeartbeat(ctx context.Context, conn *websocket.Conn, cfg Config, write func(sharedprotocol.ControlMessage) error, log *slog.Logger, done chan<- struct{}) {
	defer close(done)
	ticker := time.NewTicker(controlHeartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			message := sharedprotocol.ControlMessage{Type: "heartbeat", NodeID: cfg.NodeID, Version: sharedversion.Version, System: nodeSystem()}
			if report, err := loadUpdateStatus(cfg.UpdateStatusPath); err == nil {
				message.UpdateReport = &report
			}
			if err := write(message); err != nil {
				logControlFailure(log, ctx, "control websocket heartbeat failed", err)
				return
			}
			pingCtx, cancel := context.WithTimeout(ctx, controlPingTimeout)
			if err := conn.Ping(pingCtx); err != nil {
				cancel()
				logControlFailure(log, ctx, "control websocket ping failed", err)
				return
			}
			cancel()
		}
	}
}

func controlTelemetry(ctx context.Context, conn *websocket.Conn, cfg Config, write func(sharedprotocol.ControlMessage) error, log *slog.Logger, done chan<- struct{}) {
	defer close(done)
	interval := cfg.LiveInterval
	if interval <= 0 {
		interval = defaultLiveInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	collector := metrics.New()
	var sequence uint64
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			telemetry, err := collector.CollectLive()
			if err != nil {
				logControlFailure(log, ctx, "live telemetry collection failed", err)
				continue
			}
			sequence++
			telemetry.NodeID = cfg.NodeID
			telemetry.Sequence = sequence
			telemetry.ObservedAtUnixMilli = time.Now().UnixMilli()
			telemetry.AgentVersion = sharedversion.Version
			telemetry.System = nodeSystem()
			telemetry.MetricsAvailable = true
			message := sharedprotocol.ControlMessage{Type: "telemetry", NodeID: cfg.NodeID, Telemetry: &telemetry}
			if err := write(message); err != nil {
				logControlFailure(log, ctx, "live telemetry write failed", err)
				return
			}
		}
	}
}

func reportUpdateStatus(ctx context.Context, cfg Config, write func(sharedprotocol.ControlMessage) error, log *slog.Logger) {
	report, err := loadUpdateStatus(cfg.UpdateStatusPath)
	if err != nil {
		return
	}
	if err := write(sharedprotocol.ControlMessage{Type: "update_status", NodeID: cfg.NodeID, UpdateReport: &report}); err != nil {
		logControlFailure(log, ctx, "update status report failed", err)
	}
}

func writeWithContext(ctx context.Context, conn *websocket.Conn, mu *sync.Mutex, message sharedprotocol.ControlMessage) error {
	mu.Lock()
	defer mu.Unlock()
	return wsjson.Write(ctx, conn, message)
}

func nodeSystem() model.SystemInfo {
	return metrics.SystemInfo()
}

func restartNodeService() error {
	return exec.Command("systemctl", "restart", "nyasm-node").Run()
}

func sleepContext(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func logControlFailure(log *slog.Logger, ctx context.Context, message string, err error) {
	if ctx.Err() != nil {
		log.Debug(message, "error", err)
		return
	}
	log.Warn(message, "error", err)
}

func logControlReadFailure(log *slog.Logger, ctx context.Context, err error) {
	status := websocket.CloseStatus(err)
	if ctx.Err() != nil || status == websocket.StatusNormalClosure || status == websocket.StatusGoingAway {
		log.Debug("control websocket read failed", "error", err)
		return
	}
	logControlFailure(log, ctx, "control websocket read failed", err)
}
