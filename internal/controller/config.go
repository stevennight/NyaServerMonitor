package controller

import (
	"errors"
	"flag"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

type Config struct {
	ListenAddr       string
	DataDir          string
	DBPath           string
	PublicURL        string
	LogLevel         string
	SessionLifetime  time.Duration
	OfflineAfter     time.Duration
	MetricsRetention time.Duration
	CleanupInterval  time.Duration
	CookieSecure     bool
}

func parseConfig(args []string) (Config, error) {
	cfg := Config{
		ListenAddr:       env("NYASM_LISTEN", ":8080"),
		DataDir:          env("NYASM_DATA", "./data"),
		PublicURL:        env("NYASM_PUBLIC_URL", "http://127.0.0.1:8080"),
		LogLevel:         env("NYASM_LOG_LEVEL", "info"),
		SessionLifetime:  24 * time.Hour,
		OfflineAfter:     90 * time.Second,
		MetricsRetention: 30 * 24 * time.Hour,
		CleanupInterval:  5 * time.Minute,
	}
	flags := flag.NewFlagSet("nyasm-controller", flag.ContinueOnError)
	flags.StringVar(&cfg.ListenAddr, "listen", cfg.ListenAddr, "HTTP listen address")
	flags.StringVar(&cfg.DataDir, "data", cfg.DataDir, "data directory")
	flags.StringVar(&cfg.PublicURL, "public-url", cfg.PublicURL, "URL used in node configuration")
	flags.StringVar(&cfg.LogLevel, "log-level", cfg.LogLevel, "log level")
	flags.DurationVar(&cfg.SessionLifetime, "session-lifetime", cfg.SessionLifetime, "admin session lifetime")
	flags.DurationVar(&cfg.OfflineAfter, "offline-after", cfg.OfflineAfter, "time without a report before a node is offline")
	flags.DurationVar(&cfg.MetricsRetention, "metrics-retention", cfg.MetricsRetention, "metric history retention")
	flags.DurationVar(&cfg.CleanupInterval, "cleanup-interval", cfg.CleanupInterval, "maintenance interval")
	flags.BoolVar(&cfg.CookieSecure, "secure-cookies", false, "mark admin cookies Secure")
	if err := flags.Parse(args); err != nil {
		return Config{}, err
	}
	cfg.DataDir = filepath.Clean(cfg.DataDir)
	cfg.DBPath = filepath.Join(cfg.DataDir, "nyasm.db")
	if cfg.SessionLifetime < 15*time.Minute || cfg.SessionLifetime > 30*24*time.Hour {
		return Config{}, errors.New("session-lifetime must be between 15m and 30d")
	}
	if cfg.OfflineAfter < 15*time.Second || cfg.OfflineAfter > 24*time.Hour {
		return Config{}, errors.New("offline-after must be between 15s and 24h")
	}
	if cfg.MetricsRetention < time.Hour || cfg.MetricsRetention > 365*24*time.Hour {
		return Config{}, errors.New("metrics-retention must be between 1h and 365d")
	}
	if cfg.CleanupInterval < time.Minute || cfg.CleanupInterval > 24*time.Hour {
		return Config{}, errors.New("cleanup-interval must be between 1m and 24h")
	}
	parsed, err := url.Parse(cfg.PublicURL)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return Config{}, errors.New("public-url must be an http or https URL")
	}
	if !cfg.CookieSecure && parsed.Scheme == "https" {
		cfg.CookieSecure = true
	}
	return cfg, nil
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
