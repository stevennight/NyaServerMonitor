//go:build linux

package metrics

import (
	"bufio"
	"math"
	"os"
	"strconv"
	"strings"
	"syscall"

	"nyaservermonitor/internal/shared/model"
)

type platformState struct {
	previousTotal uint64
	previousIdle  uint64
}

func platformKernel() string {
	data, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func collectPlatform(state *platformState) (model.MetricsSnapshot, error) {
	snapshot := model.MetricsSnapshot{}
	readCPU(&snapshot, state)
	readLoad(&snapshot)
	readMemory(&snapshot)
	readUptime(&snapshot)
	readNetwork(&snapshot)
	readDisks(&snapshot)
	snapshot.ProcessCount = processCount()
	return snapshot, nil
}

func readCPU(snapshot *model.MetricsSnapshot, state *platformState) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 || fields[0] != "cpu" {
			continue
		}
		var values []uint64
		for _, field := range fields[1:] {
			value, err := strconv.ParseUint(field, 10, 64)
			if err != nil {
				return
			}
			values = append(values, value)
		}
		var total, idle uint64
		for _, value := range values {
			total += value
		}
		idle = values[3]
		if len(values) > 4 {
			idle += values[4]
		}
		if state.previousTotal > 0 && total > state.previousTotal && idle >= state.previousIdle {
			totalDelta := total - state.previousTotal
			idleDelta := idle - state.previousIdle
			snapshot.CPUPercent = math.Min(100, math.Max(0, (1-float64(idleDelta)/float64(totalDelta))*100))
		}
		state.previousTotal = total
		state.previousIdle = idle
		return
	}
}

func readLoad(snapshot *model.MetricsSnapshot) {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return
	}
	fields := strings.Fields(string(data))
	if len(fields) < 3 {
		return
	}
	snapshot.Load1, _ = strconv.ParseFloat(fields[0], 64)
	snapshot.Load5, _ = strconv.ParseFloat(fields[1], 64)
	snapshot.Load15, _ = strconv.ParseFloat(fields[2], 64)
}

func readMemory(snapshot *model.MetricsSnapshot) {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return
	}
	defer file.Close()
	values := map[string]uint64{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		value, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}
		if len(fields) > 2 && fields[2] == "kB" {
			value *= 1024
		}
		values[strings.TrimSuffix(fields[0], ":")] = value
	}
	snapshot.MemoryTotalBytes = values["MemTotal"]
	available := values["MemAvailable"]
	if available == 0 {
		available = values["MemFree"] + values["Buffers"] + values["Cached"]
	}
	if snapshot.MemoryTotalBytes >= available {
		snapshot.MemoryUsedBytes = snapshot.MemoryTotalBytes - available
	}
	snapshot.SwapTotalBytes = values["SwapTotal"]
	if snapshot.SwapTotalBytes >= values["SwapFree"] {
		snapshot.SwapUsedBytes = snapshot.SwapTotalBytes - values["SwapFree"]
	}
}

func readUptime(snapshot *model.MetricsSnapshot) {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return
	}
	seconds, err := strconv.ParseFloat(fields[0], 64)
	if err == nil && seconds >= 0 {
		snapshot.UptimeSeconds = uint64(seconds)
	}
}

func readNetwork(snapshot *model.MetricsSnapshot) {
	file, err := os.Open("/proc/net/dev")
	if err != nil {
		return
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		separator := strings.IndexByte(line, ':')
		if separator < 0 {
			continue
		}
		name := strings.TrimSpace(line[:separator])
		if name == "lo" {
			continue
		}
		fields := strings.Fields(line[separator+1:])
		if len(fields) < 10 {
			continue
		}
		inBytes, errIn := strconv.ParseUint(fields[0], 10, 64)
		inPackets, errInPackets := strconv.ParseUint(fields[1], 10, 64)
		outBytes, errOut := strconv.ParseUint(fields[8], 10, 64)
		outPackets, errOutPackets := strconv.ParseUint(fields[9], 10, 64)
		if errIn != nil || errInPackets != nil || errOut != nil || errOutPackets != nil {
			continue
		}
		snapshot.Networks = append(snapshot.Networks, model.NetworkMetric{Name: name, BytesIn: inBytes, BytesOut: outBytes, PacketsIn: inPackets, PacketsOut: outPackets})
	}
}

func readDisks(snapshot *model.MetricsSnapshot) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs("/", &stat); err != nil {
		return
	}
	total := uint64(stat.Blocks) * uint64(stat.Bsize)
	available := uint64(stat.Bavail) * uint64(stat.Bsize)
	used := uint64(0)
	if total >= available {
		used = total - available
	}
	snapshot.Disks = append(snapshot.Disks, model.DiskMetric{Mount: "/", TotalBytes: total, UsedBytes: used, AvailableBytes: available})
}

func processCount() int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}
	count := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if _, err := strconv.Atoi(entry.Name()); err == nil {
			count++
		}
	}
	return count
}
