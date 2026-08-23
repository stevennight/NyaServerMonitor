//go:build linux

package metrics

import (
	"bufio"
	"math"
	"math/bits"
	"os"
	"path/filepath"
	"sort"
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
	snapshot.Disks = append(snapshot.Disks, collectPhysicalDisks("/proc/self/mountinfo", "/sys/class/block")...)
}

type mountedFilesystem struct {
	mountPoint string
	source     string
	deviceID   string
}

type physicalDiskAggregate struct {
	total     uint64
	used      uint64
	available uint64
}

func collectPhysicalDisks(mountInfoPath, sysBlockPath string) []model.DiskMetric {
	mounts, err := readMountInfo(mountInfoPath)
	if err != nil {
		return nil
	}

	aggregates := make(map[string]*physicalDiskAggregate)
	seenFilesystems := make(map[string]struct{})
	for _, mount := range mounts {
		source := resolveDeviceSource(mount.source)
		if source == "" {
			source = resolveDeviceID(mount.deviceID, sysBlockPath)
		}
		if source == "" {
			continue
		}
		if _, seen := seenFilesystems[source]; seen {
			continue
		}
		seenFilesystems[source] = struct{}{}

		usage, ok := filesystemUsage(mount.mountPoint)
		if !ok {
			continue
		}

		physicalNames := physicalDiskNames(source, sysBlockPath)
		if len(physicalNames) == 0 {
			continue
		}
		var physicalTotal uint64
		availableNames := make([]string, 0, len(physicalNames))
		for _, name := range physicalNames {
			total := blockDeviceSize(sysBlockPath, name)
			if total == 0 {
				continue
			}
			if _, exists := aggregates[name]; !exists {
				aggregates[name] = &physicalDiskAggregate{total: total}
			}
			physicalTotal = saturatingAdd(physicalTotal, total)
			availableNames = append(availableNames, name)
		}
		if physicalTotal == 0 {
			continue
		}

		for _, name := range availableNames {
			aggregate := aggregates[name]
			share := aggregate.total
			aggregate.used = saturatingAdd(aggregate.used, proportionalBytes(usage.used, share, physicalTotal))
			aggregate.available = saturatingAdd(aggregate.available, proportionalBytes(usage.available, share, physicalTotal))
		}
	}

	names := make([]string, 0, len(aggregates))
	for name := range aggregates {
		names = append(names, name)
	}
	sort.Strings(names)
	disks := make([]model.DiskMetric, 0, len(names))
	for _, name := range names {
		aggregate := aggregates[name]
		used := aggregate.used
		available := aggregate.available
		if used > aggregate.total {
			used = aggregate.total
		}
		if available > aggregate.total {
			available = aggregate.total
		}
		disks = append(disks, model.DiskMetric{
			Device:         name,
			TotalBytes:     aggregate.total,
			UsedBytes:      used,
			AvailableBytes: available,
		})
	}
	return disks
}

func readMountInfo(path string) ([]mountedFilesystem, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var mounts []mountedFilesystem
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		separator := -1
		for index, field := range fields {
			if field == "-" {
				separator = index
				break
			}
		}
		if separator < 6 || len(fields) <= separator+2 {
			continue
		}
		mounts = append(mounts, mountedFilesystem{
			mountPoint: decodeMountInfoPath(fields[4]),
			source:     decodeMountInfoPath(fields[separator+2]),
			deviceID:   fields[2],
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return mounts, nil
}

func decodeMountInfoPath(value string) string {
	return strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`).Replace(value)
}

func resolveDeviceSource(source string) string {
	if !strings.HasPrefix(source, "/dev/") {
		return ""
	}
	if resolved, err := filepath.EvalSymlinks(source); err == nil {
		source = resolved
	}
	name := filepath.Base(source)
	if name == "." || name == string(filepath.Separator) || name == "" {
		return ""
	}
	return source
}

func resolveDeviceID(deviceID, sysBlockPath string) string {
	if !strings.Contains(deviceID, ":") {
		return ""
	}
	sysRoot := filepath.Dir(filepath.Dir(sysBlockPath))
	path := filepath.Join(sysRoot, "dev", "block", deviceID)
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return ""
	}
	return resolved
}

func filesystemUsage(mountPoint string) (physicalDiskAggregate, bool) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(mountPoint, &stat); err != nil || stat.Bsize <= 0 {
		return physicalDiskAggregate{}, false
	}
	total, ok := blockBytes(uint64(stat.Blocks), uint64(stat.Bsize))
	if !ok {
		return physicalDiskAggregate{}, false
	}
	available := uint64(0)
	if stat.Bavail > 0 {
		available, ok = blockBytes(uint64(stat.Bavail), uint64(stat.Bsize))
		if !ok {
			return physicalDiskAggregate{}, false
		}
	}
	used := uint64(0)
	if total >= available {
		used = total - available
	}
	return physicalDiskAggregate{total: total, used: used, available: available}, true
}

func physicalDiskNames(source, sysBlockPath string) []string {
	name := filepath.Base(source)
	if name == "" || name == "." || name == string(filepath.Separator) {
		return nil
	}
	names := make(map[string]struct{})
	visited := make(map[string]struct{})
	collectPhysicalDiskNames(name, sysBlockPath, visited, names)
	result := make([]string, 0, len(names))
	for name := range names {
		result = append(result, name)
	}
	sort.Strings(result)
	return result
}

func collectPhysicalDiskNames(name, sysBlockPath string, visited, names map[string]struct{}) {
	if name == "" {
		return
	}
	if _, seen := visited[name]; seen {
		return
	}
	visited[name] = struct{}{}

	blockPath := filepath.Join(sysBlockPath, name)
	if _, err := os.Stat(blockPath); err != nil {
		return
	}
	if entries, err := os.ReadDir(filepath.Join(blockPath, "slaves")); err == nil && len(entries) > 0 {
		for _, entry := range entries {
			collectPhysicalDiskNames(entry.Name(), sysBlockPath, visited, names)
		}
		return
	}
	if _, err := os.Stat(filepath.Join(blockPath, "partition")); err == nil {
		if resolved, err := filepath.EvalSymlinks(blockPath); err == nil {
			parent := filepath.Base(filepath.Dir(resolved))
			if parent != "" && parent != "block" && parent != name {
				collectPhysicalDiskNames(parent, sysBlockPath, visited, names)
				return
			}
		}
	}
	if !isPhysicalDisk(sysBlockPath, name) {
		return
	}
	names[name] = struct{}{}
}

func isPhysicalDisk(sysBlockPath, name string) bool {
	resolved, err := filepath.EvalSymlinks(filepath.Join(sysBlockPath, name))
	if err == nil && strings.Contains(resolved, string(filepath.Separator)+"virtual"+string(filepath.Separator)) {
		return false
	}
	if _, err := os.Stat(filepath.Join(sysBlockPath, name, "device")); err == nil {
		return true
	}
	for _, prefix := range []string{"sd", "vd", "xvd", "hd", "nvme", "mmcblk", "dasd"} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

func blockDeviceSize(sysBlockPath, name string) uint64 {
	data, err := os.ReadFile(filepath.Join(sysBlockPath, name, "size"))
	if err != nil {
		return 0
	}
	sectors, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0
	}
	size, ok := blockBytes(sectors, 512)
	if !ok {
		return 0
	}
	return size
}

func blockBytes(blocks, blockSize uint64) (uint64, bool) {
	if blockSize == 0 || blocks > ^uint64(0)/blockSize {
		return 0, false
	}
	return blocks * blockSize, true
}

func proportionalBytes(value, numerator, denominator uint64) uint64 {
	if value == 0 || numerator == 0 || denominator == 0 {
		return 0
	}
	high, low := bits.Mul64(value, numerator)
	if high >= denominator {
		return ^uint64(0)
	}
	quotient, _ := bits.Div64(high, low, denominator)
	return quotient
}

func saturatingAdd(left, right uint64) uint64 {
	if ^uint64(0)-left < right {
		return ^uint64(0)
	}
	return left + right
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
