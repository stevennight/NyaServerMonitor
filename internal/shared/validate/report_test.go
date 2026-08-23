package validate

import (
	"testing"
	"time"

	"nyaservermonitor/internal/shared/model"
)

func validReport() model.Report {
	return model.Report{
		ProtocolVersion: model.ProtocolVersion,
		NodeID:          "node_test-1",
		SentAtUnix:      time.Now().Unix(),
		AgentVersion:    "dev",
		System:          model.SystemInfo{Hostname: "host", OS: "linux", Arch: "amd64", CPUCount: 2},
		Metrics:         model.MetricsSnapshot{CPUPercent: 30, MemoryTotalBytes: 100, MemoryUsedBytes: 50},
	}
}

func TestReportRejectsUnsafeValues(t *testing.T) {
	if err := Report(validReport(), time.Now()); err != nil {
		t.Fatalf("valid report rejected: %v", err)
	}
	bad := validReport()
	bad.NodeID = "../shell"
	if err := Report(bad, time.Now()); err == nil {
		t.Fatal("path-like node id should be rejected")
	}
	bad = validReport()
	bad.Metrics.CPUPercent = 101
	if err := Report(bad, time.Now()); err == nil {
		t.Fatal("cpu over 100 should be rejected")
	}
}

func TestReportAcceptsPhysicalDiskMetric(t *testing.T) {
	report := validReport()
	report.Metrics.Disks = []model.DiskMetric{{Device: "vda", TotalBytes: 100, UsedBytes: 40, AvailableBytes: 60}}
	if err := Report(report, time.Now()); err != nil {
		t.Fatalf("physical disk metric rejected: %v", err)
	}

	invalid := validReport()
	invalid.Metrics.Disks = []model.DiskMetric{{TotalBytes: 100, UsedBytes: 40, AvailableBytes: 60}}
	if err := Report(invalid, time.Now()); err == nil {
		t.Fatal("disk metric without device or mount should be rejected")
	}
}
