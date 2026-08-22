package node

import (
	"errors"
	"flag"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Config struct {
	ControllerURL      string
	NodeID             string
	NodeToken          string
	ChecksPath         string
	DataDir            string
	LogLevel           string
	Interval           time.Duration
	HTTPTimeout        time.Duration
	InsecureSkipVerify bool
}

func parseConfig(args []string) (Config, error) {
	cfg := Config{
		ControllerURL: env("NYASM_CONTROLLER", "http://127.0.0.1:8080"),
		NodeID:        env("NYASM_NODE_ID", ""),
		NodeToken:     env("NYASM_NODE_TOKEN", ""),
		ChecksPath:    env("NYASM_CHECKS", ""),
		DataDir:       env("NYASM_DATA", "./node-data"),
		LogLevel:      env("NYASM_LOG_LEVEL", "info"),
		Interval:      15 * time.Second,
		HTTPTimeout:   20 * time.Second,
	}
	flags := flag.NewFlagSet("nyasm-node", flag.ContinueOnError)
	flags.StringVar(&cfg.ControllerURL, "controller", cfg.ControllerURL, "controller URL")
	flags.StringVar(&cfg.NodeID, "id", cfg.NodeID, "node id")
	flags.StringVar(&cfg.NodeToken, "token", cfg.NodeToken, "node token")
	flags.StringVar(&cfg.ChecksPath, "checks", cfg.ChecksPath, "local service check JSON path")
	flags.StringVar(&cfg.DataDir, "data", cfg.DataDir, "node data directory")
	flags.StringVar(&cfg.LogLevel, "log-level", cfg.LogLevel, "log level")
	flags.DurationVar(&cfg.Interval, "interval", cfg.Interval, "report interval")
	flags.DurationVar(&cfg.HTTPTimeout, "http-timeout", cfg.HTTPTimeout, "report HTTP timeout")
	flags.BoolVar(&cfg.InsecureSkipVerify, "insecure-skip-verify", false, "disable TLS certificate verification; development only")
	if err := flags.Parse(args); err != nil {
		return Config{}, err
	}
	if err := cfg.validate(); err != nil {
		return Config{}, err
	}
	cfg.DataDir = filepath.Clean(cfg.DataDir)
	return cfg, nil
}

func (c Config) validate() error {
	parsed, err := url.Parse(strings.TrimRight(strings.TrimSpace(c.ControllerURL), "/"))
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return errors.New("controller must be an http or https URL")
	}
	if len(c.NodeID) == 0 || len(c.NodeID) > 64 || strings.ContainsAny(c.NodeID, "/\\") {
		return errors.New("node id is required and must not contain a path separator")
	}
	if len(c.NodeToken) < 32 || len(c.NodeToken) > 256 {
		return errors.New("node token must be at least 32 characters")
	}
	if c.Interval < 5*time.Second || c.Interval > 24*time.Hour {
		return errors.New("interval must be between 5s and 24h")
	}
	if c.HTTPTimeout < time.Second || c.HTTPTimeout > 2*time.Minute {
		return errors.New("http-timeout must be between 1s and 2m")
	}
	// The flag is intentionally explicit and never enabled through the default environment.
	return nil
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
