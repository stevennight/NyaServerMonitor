//go:build linux

package metrics

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPhysicalDiskNamesCollapsePartitions(t *testing.T) {
	sysRoot := t.TempDir()
	sysBlockPath := filepath.Join(sysRoot, "class", "block")
	physicalPath := filepath.Join(sysRoot, "devices", "vda")
	if err := os.MkdirAll(filepath.Join(sysBlockPath, "vda"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(physicalPath, "vda1"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sysBlockPath, "vda", "size"), []byte("2097152\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	partitionPath := filepath.Join(sysBlockPath, "vda1")
	if err := os.Symlink(filepath.Join(physicalPath, "vda1"), partitionPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(physicalPath, "vda1", "partition"), []byte("1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	names := physicalDiskNames("/dev/vda1", sysBlockPath)
	if len(names) != 1 || names[0] != "vda" {
		t.Fatalf("expected vda for vda1, got %#v", names)
	}
	if got := blockDeviceSize(sysBlockPath, "vda"); got != 1<<30 {
		t.Fatalf("expected 1 GiB disk size, got %d", got)
	}
}

func TestDecodeMountInfoPath(t *testing.T) {
	if got := decodeMountInfoPath(`/srv/data\040with\011tabs`); got != "/srv/data with\ttabs" {
		t.Fatalf("unexpected decoded mount path: %q", got)
	}
}

func TestBytesPerSecond(t *testing.T) {
	if got := bytesPerSecond(4096, 2*time.Second); got != 2048 {
		t.Fatalf("expected 2048 bytes per second, got %d", got)
	}
	if got := bytesPerSecond(4096, 0); got != 0 {
		t.Fatalf("expected zero rate for zero elapsed time, got %d", got)
	}
}
