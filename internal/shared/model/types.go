package model

import "time"

const ProtocolVersion = 1

type NodeStatus string

const (
	NodePending NodeStatus = "pending"
	NodeOnline  NodeStatus = "online"
	NodeOffline NodeStatus = "offline"
	NodeRevoked NodeStatus = "revoked"
)

type Node struct {
	ID           string          `json:"id"`
	Name         string          `json:"name"`
	Group        string          `json:"group,omitempty"`
	Tags         []string        `json:"tags,omitempty"`
	Status       NodeStatus      `json:"status"`
	AgentVersion string          `json:"agent_version,omitempty"`
	LastIP       string          `json:"last_ip,omitempty"`
	LastSeen     time.Time       `json:"last_seen,omitempty"`
	FirstSeen    time.Time       `json:"first_seen,omitempty"`
	CreatedAt    time.Time       `json:"created_at"`
	UpdatedAt    time.Time       `json:"updated_at"`
	Sequence     uint64          `json:"sequence,omitempty"`
	System       SystemInfo      `json:"system,omitempty"`
	Metrics      MetricsSnapshot `json:"metrics,omitempty"`
	Checks       []ServiceCheck  `json:"checks,omitempty"`
}

type SystemInfo struct {
	Hostname string `json:"hostname,omitempty"`
	OS       string `json:"os,omitempty"`
	Arch     string `json:"arch,omitempty"`
	Kernel   string `json:"kernel,omitempty"`
	IP       string `json:"ip,omitempty"`
	CPUCount int    `json:"cpu_count,omitempty"`
}

type MetricsSnapshot struct {
	CPUPercent       float64         `json:"cpu_percent"`
	Load1            float64         `json:"load1"`
	Load5            float64         `json:"load5"`
	Load15           float64         `json:"load15"`
	MemoryTotalBytes uint64          `json:"memory_total_bytes"`
	MemoryUsedBytes  uint64          `json:"memory_used_bytes"`
	SwapTotalBytes   uint64          `json:"swap_total_bytes"`
	SwapUsedBytes    uint64          `json:"swap_used_bytes"`
	UptimeSeconds    uint64          `json:"uptime_seconds"`
	ProcessCount     int             `json:"process_count"`
	Disks            []DiskMetric    `json:"disks,omitempty"`
	Networks         []NetworkMetric `json:"networks,omitempty"`
}

type DiskMetric struct {
	Mount          string `json:"mount"`
	TotalBytes     uint64 `json:"total_bytes"`
	UsedBytes      uint64 `json:"used_bytes"`
	AvailableBytes uint64 `json:"available_bytes"`
}

type NetworkMetric struct {
	Name       string `json:"name"`
	BytesIn    uint64 `json:"bytes_in"`
	BytesOut   uint64 `json:"bytes_out"`
	PacketsIn  uint64 `json:"packets_in"`
	PacketsOut uint64 `json:"packets_out"`
}

type ServiceCheck struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Type          string `json:"type"`
	Target        string `json:"target"`
	Status        string `json:"status"`
	LatencyMS     int64  `json:"latency_ms,omitempty"`
	Message       string `json:"message,omitempty"`
	CheckedAtUnix int64  `json:"checked_at_unix"`
}

type Report struct {
	ProtocolVersion int             `json:"protocol_version"`
	NodeID          string          `json:"node_id"`
	SentAtUnix      int64           `json:"sent_at_unix"`
	Sequence        uint64          `json:"sequence"`
	AgentVersion    string          `json:"agent_version"`
	System          SystemInfo      `json:"system"`
	Metrics         MetricsSnapshot `json:"metrics"`
	Checks          []ServiceCheck  `json:"checks,omitempty"`
}

type MetricSample struct {
	ObservedAt time.Time       `json:"observed_at"`
	Sequence   uint64          `json:"sequence"`
	Metrics    MetricsSnapshot `json:"metrics"`
	Checks     []ServiceCheck  `json:"checks,omitempty"`
}

type AuditEvent struct {
	ID        int64          `json:"id"`
	Actor     string         `json:"actor"`
	Action    string         `json:"action"`
	Target    string         `json:"target"`
	Detail    map[string]any `json:"detail,omitempty"`
	CreatedAt time.Time      `json:"created_at"`
}

type Dashboard struct {
	TotalNodes      int          `json:"total_nodes"`
	OnlineNodes     int          `json:"online_nodes"`
	OfflineNodes    int          `json:"offline_nodes"`
	RevokedNodes    int          `json:"revoked_nodes"`
	DegradedChecks  int          `json:"degraded_checks"`
	Nodes           []Node       `json:"nodes"`
	RecentEvents    []AuditEvent `json:"recent_events"`
	GeneratedAtUnix int64        `json:"generated_at_unix"`
}
