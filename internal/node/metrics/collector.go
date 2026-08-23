package metrics

import (
	"net"
	"os"
	"runtime"
	"strings"

	"nyaservermonitor/internal/shared/model"
)

type Collector struct {
	state platformState
}

func New() *Collector { return &Collector{} }

func (c *Collector) Collect() (model.MetricsSnapshot, error) {
	return collectPlatform(&c.state)
}

func (c *Collector) CollectLive() (model.LiveTelemetry, error) {
	return collectLivePlatform(&c.state)
}

func SystemInfo() model.SystemInfo {
	hostname, _ := os.Hostname()
	return model.SystemInfo{
		Hostname: strings.TrimSpace(hostname),
		OS:       runtime.GOOS,
		Arch:     runtime.GOARCH,
		Kernel:   platformKernel(),
		IP:       firstNonLoopbackIP(),
		CPUCount: runtime.NumCPU(),
	}
}

func firstNonLoopbackIP() string {
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	var fallback string
	for _, address := range addresses {
		var ip net.IP
		switch value := address.(type) {
		case *net.IPNet:
			ip = value.IP
		case *net.IPAddr:
			ip = value.IP
		}
		if ip == nil || ip.IsLoopback() || ip.IsMulticast() || ip.IsUnspecified() {
			continue
		}
		if ip4 := ip.To4(); ip4 != nil {
			return ip4.String()
		}
		if fallback == "" {
			fallback = ip.String()
		}
	}
	return fallback
}
