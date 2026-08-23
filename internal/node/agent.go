package node

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"nyaservermonitor/internal/node/metrics"
	"nyaservermonitor/internal/shared/model"
	sharedversion "nyaservermonitor/internal/shared/version"
)

type Agent struct {
	cfg       Config
	log       *slog.Logger
	client    *client
	collector *metrics.Collector
	checks    []CheckConfig
	sequence  atomic.Uint64
}

func Run(ctx context.Context, args []string) error {
	if len(args) > 0 && args[0] == "update" {
		cfg, err := parseConfig(args[1:])
		if err != nil {
			return err
		}
		if err := runUpdate(ctx, cfg); err != nil {
			return err
		}
		if os.Getenv("NYASM_SKIP_RESTART") == "1" {
			return nil
		}
		return restartNodeService()
	}
	cfg, err := parseConfig(args)
	if err != nil {
		return err
	}
	checks, err := loadChecks(cfg.ChecksPath)
	if err != nil {
		return fmt.Errorf("load checks: %w", err)
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return err
	}
	agent := &Agent{
		cfg:       cfg,
		log:       slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: parseLevel(cfg.LogLevel)})),
		client:    newClient(cfg),
		collector: metrics.New(),
		checks:    checks,
	}
	agent.log.Info("node agent started", "node_id", cfg.NodeID, "controller", cfg.ControllerURL, "interval", cfg.Interval)
	if err := agent.send(ctx); err != nil {
		agent.log.Warn("initial report failed", "error", err)
	}
	go controlLoop(ctx, agent.client, cfg, agent.log)
	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := agent.send(ctx); err != nil {
				agent.log.Warn("report failed", "error", err)
			}
		}
	}
}

func (a *Agent) send(ctx context.Context) error {
	snapshot, err := a.collector.Collect()
	if err != nil {
		return err
	}
	report := model.Report{
		ProtocolVersion: model.ProtocolVersion,
		NodeID:          a.cfg.NodeID,
		SentAtUnix:      time.Now().Unix(),
		Sequence:        a.sequence.Add(1),
		AgentVersion:    sharedversion.Version,
		System:          metrics.SystemInfo(),
		Metrics:         snapshot,
		Checks:          runChecks(ctx, a.checks),
	}
	return a.client.report(ctx, report)
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

func writeExampleChecks(path string) error {
	data, err := json.MarshalIndent([]CheckConfig{{ID: "homepage", Name: "Homepage", Type: "http", Target: "https://example.com", TimeoutSeconds: 5, ExpectedStatus: 200}}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o600)
}
