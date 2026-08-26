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
	ID                string           `json:"id"`
	Name              string           `json:"name"`
	Group             string           `json:"group,omitempty"`
	Tags              []string         `json:"tags,omitempty"`
	Status            NodeStatus       `json:"status"`
	AgentVersion      string           `json:"agent_version,omitempty"`
	LastIP            string           `json:"-"`
	PublicIPv4        string           `json:"public_ipv4,omitempty"`
	PublicIPv6        string           `json:"public_ipv6,omitempty"`
	IPOverride        string           `json:"ip_override,omitempty"`
	Country           string           `json:"country,omitempty"`
	CountryCode       string           `json:"country_code,omitempty"`
	CountryOverride   string           `json:"country_override,omitempty"`
	LastSeen          time.Time        `json:"last_seen,omitempty"`
	FirstSeen         time.Time        `json:"first_seen,omitempty"`
	CreatedAt         time.Time        `json:"created_at"`
	UpdatedAt         time.Time        `json:"updated_at"`
	Sequence          uint64           `json:"sequence,omitempty"`
	System            SystemInfo       `json:"system,omitempty"`
	Metrics           MetricsSnapshot  `json:"metrics,omitempty"`
	Checks            []ServiceCheck   `json:"checks,omitempty"`
	DesiredVersion    string           `json:"desired_version,omitempty"`
	UpdateStatus      NodeUpdateStatus `json:"update_status,omitempty"`
	UpdateError       string           `json:"update_error,omitempty"`
	UpdateRequestedAt time.Time        `json:"update_requested_at,omitempty"`
	UpdateFinishedAt  time.Time        `json:"update_finished_at,omitempty"`
}

type NodeUpdateStatus string

const (
	NodeUpdateIdle      NodeUpdateStatus = ""
	NodeUpdateRequested NodeUpdateStatus = "requested"
	NodeUpdateRunning   NodeUpdateStatus = "running"
	NodeUpdateSucceeded NodeUpdateStatus = "succeeded"
	NodeUpdateFailed    NodeUpdateStatus = "failed"
)

type NodeReleaseManifest struct {
	Version   string                `json:"version"`
	Commit    string                `json:"commit,omitempty"`
	BuildDate string                `json:"build_date,omitempty"`
	Artifacts []NodeReleaseArtifact `json:"artifacts"`
}

type NodeReleaseArtifact struct {
	OS     string `json:"os"`
	Arch   string `json:"arch"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type SignedNodeRelease struct {
	Manifest       NodeReleaseManifest `json:"manifest"`
	Signature      string              `json:"signature,omitempty"`
	SigningKeyID   string              `json:"signing_key_id,omitempty"`
	UpdateEnabled  bool                `json:"update_enabled"`
	DisabledReason string              `json:"disabled_reason,omitempty"`
}

type NodeUpdateCommand struct {
	Version      string              `json:"version"`
	Manifest     NodeReleaseManifest `json:"manifest"`
	Signature    string              `json:"signature"`
	SigningKeyID string              `json:"signing_key_id"`
}

type NodeUpdateReport struct {
	Status      NodeUpdateStatus `json:"status"`
	Version     string           `json:"version,omitempty"`
	Error       string           `json:"error,omitempty"`
	CompletedAt time.Time        `json:"completed_at,omitempty"`
}

type NodeUpdateRequest struct {
	ControllerURL string    `json:"controller_url"`
	NodeID        string    `json:"node_id"`
	NodeToken     string    `json:"node_token"`
	TargetVersion string    `json:"target_version"`
	OS            string    `json:"os"`
	Arch          string    `json:"arch"`
	SHA256        string    `json:"sha256"`
	RequestedAt   time.Time `json:"requested_at"`
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
	Device         string `json:"device,omitempty"`
	Mount          string `json:"mount,omitempty"`
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

type LiveNetworkMetric struct {
	Name              string `json:"name"`
	BytesInPerSecond  uint64 `json:"bytes_in_per_second"`
	BytesOutPerSecond uint64 `json:"bytes_out_per_second"`
}

type LiveTelemetry struct {
	NodeID              string              `json:"node_id"`
	Sequence            uint64              `json:"sequence"`
	ObservedAtUnixMilli int64               `json:"observed_at_unix_milli"`
	AgentVersion        string              `json:"agent_version,omitempty"`
	System              SystemInfo          `json:"system,omitempty"`
	Metrics             MetricsSnapshot     `json:"metrics,omitempty"`
	MetricsAvailable    bool                `json:"metrics_available,omitempty"`
	Networks            []LiveNetworkMetric `json:"networks,omitempty"`
}

type ServiceCheck struct {
	ID                string  `json:"id"`
	Name              string  `json:"name"`
	Type              string  `json:"type"`
	Target            string  `json:"target"`
	Status            string  `json:"status"`
	LatencyMS         int64   `json:"latency_ms,omitempty"`
	PacketLossPercent float64 `json:"packet_loss_percent,omitempty"`
	Attempts          int     `json:"attempts,omitempty"`
	TLSExpiresAtUnix  int64   `json:"tls_expires_at_unix,omitempty"`
	TLSFingerprint    string  `json:"tls_fingerprint,omitempty"`
	TLSVersion        string  `json:"tls_version,omitempty"`
	Message           string  `json:"message,omitempty"`
	CheckedAtUnix     int64   `json:"checked_at_unix"`
}

type PublicIP struct {
	IPv4 string `json:"ipv4,omitempty"`
	IPv6 string `json:"ipv6,omitempty"`
}

type Report struct {
	ProtocolVersion int             `json:"protocol_version"`
	NodeID          string          `json:"node_id"`
	SentAtUnix      int64           `json:"sent_at_unix"`
	Sequence        uint64          `json:"sequence"`
	AgentVersion    string          `json:"agent_version"`
	System          SystemInfo      `json:"system"`
	Metrics         MetricsSnapshot `json:"metrics"`
	PublicIP        *PublicIP       `json:"public_ip,omitempty"`
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
	ActiveAlerts    int          `json:"active_alerts"`
	SiteName        string       `json:"site_name"`
	MapEnabled      bool         `json:"map_enabled"`
	Nodes           []Node       `json:"nodes"`
	RecentEvents    []AuditEvent `json:"recent_events"`
	RecentAlerts    []AlertEvent `json:"recent_alerts"`
	GeneratedAtUnix int64        `json:"generated_at_unix"`
}

const (
	AlertNodeOffline    = "node_offline"
	AlertServiceDown    = "service_down"
	AlertCPUHigh        = "cpu_high"
	AlertMemoryHigh     = "memory_high"
	AlertDiskHigh       = "disk_high"
	AlertLatencyHigh    = "latency_high"
	AlertPacketLossHigh = "packet_loss_high"
	AlertTLSExpiring    = "tls_expiring"
	AlertTLSChanged     = "tls_changed"
	AlertTLSInvalid     = "tls_invalid"
)

type AlertRule struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	Type            string    `json:"type"`
	Enabled         bool      `json:"enabled"`
	Threshold       float64   `json:"threshold"`
	DurationSeconds int       `json:"duration_seconds"`
	CooldownSeconds int       `json:"cooldown_seconds"`
	ChannelIDs      []string  `json:"channel_ids,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

type NotificationChannel struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Type      string    `json:"type"`
	Enabled   bool      `json:"enabled"`
	Target    string    `json:"target"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type AlertState struct {
	RuleID           string    `json:"rule_id"`
	NodeID           string    `json:"node_id"`
	Status           string    `json:"status"`
	Value            float64   `json:"value,omitempty"`
	Message          string    `json:"message,omitempty"`
	Fingerprint      string    `json:"-"`
	FirstTriggeredAt time.Time `json:"first_triggered_at,omitempty"`
	LastEvaluatedAt  time.Time `json:"last_evaluated_at"`
	LastNotifiedAt   time.Time `json:"last_notified_at,omitempty"`
}

type AlertEvent struct {
	ID        int64     `json:"id"`
	RuleID    string    `json:"rule_id"`
	RuleName  string    `json:"rule_name"`
	NodeID    string    `json:"node_id"`
	NodeName  string    `json:"node_name"`
	Kind      string    `json:"kind"`
	Value     float64   `json:"value,omitempty"`
	Message   string    `json:"message"`
	CreatedAt time.Time `json:"created_at"`
	Notified  bool      `json:"notified"`
}

// PublicDashboard deliberately contains only explicitly allowlisted, non-address
// node data. Keep this separate from Dashboard so private fields cannot leak by accident.
type PublicDashboard struct {
	TotalNodes      int          `json:"total_nodes"`
	OnlineNodes     int          `json:"online_nodes"`
	OfflineNodes    int          `json:"offline_nodes"`
	PendingNodes    int          `json:"pending_nodes"`
	DegradedNodes   int          `json:"degraded_nodes"`
	SiteName        string       `json:"site_name"`
	MapEnabled      bool         `json:"map_enabled"`
	Nodes           []PublicNode `json:"nodes"`
	GeneratedAtUnix int64        `json:"generated_at_unix"`
}

type PublicNode struct {
	ID              string     `json:"id"`
	Name            string     `json:"name"`
	Group           string     `json:"group,omitempty"`
	Tags            []string   `json:"tags,omitempty"`
	Status          NodeStatus `json:"status"`
	OS              string     `json:"os,omitempty"`
	Arch            string     `json:"arch,omitempty"`
	Country         string     `json:"country,omitempty"`
	CountryCode     string     `json:"country_code,omitempty"`
	UptimeSeconds   uint64     `json:"uptime_seconds,omitempty"`
	NetworkInBytes  uint64     `json:"network_in_bytes,omitempty"`
	NetworkOutBytes uint64     `json:"network_out_bytes,omitempty"`
	Load1           float64    `json:"load1"`
	CPUPercent      int        `json:"cpu_percent"`
	MemoryPercent   int        `json:"memory_percent"`
	DiskPercent     int        `json:"disk_percent"`
	ChecksUp        int        `json:"checks_up"`
	ChecksTotal     int        `json:"checks_total"`
}

type PublicMetricSample struct {
	ObservedAt      time.Time `json:"observed_at"`
	CPUPercent      float64   `json:"cpu_percent"`
	MemoryPercent   float64   `json:"memory_percent"`
	DiskPercent     float64   `json:"disk_percent"`
	Load1           float64   `json:"load1"`
	NetworkInBytes  uint64    `json:"network_in_bytes"`
	NetworkOutBytes uint64    `json:"network_out_bytes"`
}
