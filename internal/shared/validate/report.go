package validate

import (
	"fmt"
	"math"
	"regexp"
	"strings"
	"time"

	"nyaservermonitor/internal/shared/model"
)

var identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$`)

func Identifier(value string) bool {
	return identifierPattern.MatchString(strings.TrimSpace(value))
}

func Report(report model.Report, now time.Time) error {
	if report.ProtocolVersion != model.ProtocolVersion {
		return fmt.Errorf("unsupported protocol version %d", report.ProtocolVersion)
	}
	if !Identifier(report.NodeID) {
		return fmt.Errorf("invalid node id")
	}
	if report.AgentVersion == "" || len(report.AgentVersion) > 64 {
		return fmt.Errorf("invalid agent version")
	}
	if report.SentAtUnix <= 0 {
		return fmt.Errorf("sent_at_unix is required")
	}
	sentAt := time.Unix(report.SentAtUnix, 0)
	if sentAt.Before(now.Add(-25*time.Hour)) || sentAt.After(now.Add(10*time.Minute)) {
		return fmt.Errorf("report timestamp is outside the accepted window")
	}
	if err := system(report.System); err != nil {
		return err
	}
	if err := metrics(report.Metrics); err != nil {
		return err
	}
	if len(report.Checks) > 50 {
		return fmt.Errorf("too many service checks")
	}
	seenChecks := make(map[string]struct{}, len(report.Checks))
	for index, check := range report.Checks {
		if !Identifier(check.ID) || len(check.Name) == 0 || len(check.Name) > 128 {
			return fmt.Errorf("invalid service check %d", index)
		}
		if _, exists := seenChecks[check.ID]; exists {
			return fmt.Errorf("duplicate service check id %q", check.ID)
		}
		seenChecks[check.ID] = struct{}{}
		if check.Type != "http" && check.Type != "tcp" && check.Type != "ping" && check.Type != "tls" {
			return fmt.Errorf("unsupported service check type %q", check.Type)
		}
		if len(check.Target) == 0 || len(check.Target) > 512 {
			return fmt.Errorf("invalid service check target")
		}
		if check.Status != "up" && check.Status != "down" && check.Status != "unknown" {
			return fmt.Errorf("invalid service check status %q", check.Status)
		}
		if check.LatencyMS < 0 || check.LatencyMS > 24*60*60*1000 {
			return fmt.Errorf("invalid service check latency")
		}
		if check.PacketLossPercent < 0 || math.IsNaN(check.PacketLossPercent) || math.IsInf(check.PacketLossPercent, 0) || check.PacketLossPercent > 100 {
			return fmt.Errorf("invalid service check packet loss")
		}
		if check.Attempts < 0 || check.Attempts > 10 {
			return fmt.Errorf("invalid service check attempts")
		}
		if len(check.TLSFingerprint) > 64 || len(check.TLSVersion) > 32 {
			return fmt.Errorf("invalid TLS metadata")
		}
		if check.TLSExpiresAtUnix < 0 {
			return fmt.Errorf("invalid TLS expiration")
		}
		if check.Message != "" && len(check.Message) > 256 {
			return fmt.Errorf("service check message is too long")
		}
		if check.CheckedAtUnix <= 0 || check.CheckedAtUnix < now.Add(-25*time.Hour).Unix() || check.CheckedAtUnix > now.Add(10*time.Minute).Unix() {
			return fmt.Errorf("invalid service check timestamp")
		}
	}
	return nil
}

func system(value model.SystemInfo) error {
	if len(value.Hostname) > 253 || len(value.OS) > 64 || len(value.Arch) > 32 || len(value.Kernel) > 128 || len(value.IP) > 64 {
		return fmt.Errorf("system information is too long")
	}
	if value.CPUCount < 0 || value.CPUCount > 4096 {
		return fmt.Errorf("invalid cpu count")
	}
	return nil
}

func metrics(value model.MetricsSnapshot) error {
	for name, number := range map[string]float64{
		"cpu_percent": value.CPUPercent,
		"load1":       value.Load1,
		"load5":       value.Load5,
		"load15":      value.Load15,
	} {
		if math.IsNaN(number) || math.IsInf(number, 0) || number < 0 || number > 100000 {
			return fmt.Errorf("invalid %s", name)
		}
	}
	if value.CPUPercent > 100 {
		return fmt.Errorf("cpu_percent must be between 0 and 100")
	}
	if value.MemoryUsedBytes > value.MemoryTotalBytes || value.SwapUsedBytes > value.SwapTotalBytes {
		return fmt.Errorf("memory usage cannot exceed total memory")
	}
	if len(value.Disks) > 64 || len(value.Networks) > 256 {
		return fmt.Errorf("too many disk or network metrics")
	}
	for _, disk := range value.Disks {
		if len(disk.Mount) == 0 || len(disk.Mount) > 256 || disk.UsedBytes > disk.TotalBytes || disk.AvailableBytes > disk.TotalBytes {
			return fmt.Errorf("invalid disk metric")
		}
	}
	for _, network := range value.Networks {
		if len(network.Name) == 0 || len(network.Name) > 128 {
			return fmt.Errorf("invalid network metric")
		}
	}
	return nil
}
