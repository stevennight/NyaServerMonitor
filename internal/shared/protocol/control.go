package protocol

import "nyaservermonitor/internal/shared/model"

// ControlMessage intentionally contains only the small, fixed control surface
// needed for heartbeats, live telemetry, and signed node updates. It has no
// shell, script, configuration, arbitrary URL, or filesystem-path fields.
type ControlMessage struct {
	Type         string                   `json:"type"`
	NodeID       string                   `json:"node_id,omitempty"`
	Version      string                   `json:"version,omitempty"`
	System       model.SystemInfo         `json:"system,omitempty"`
	Telemetry    *model.LiveTelemetry     `json:"telemetry,omitempty"`
	Update       *model.NodeUpdateCommand `json:"update,omitempty"`
	UpdateReport *model.NodeUpdateReport  `json:"update_report,omitempty"`
	Error        string                   `json:"error,omitempty"`
}
