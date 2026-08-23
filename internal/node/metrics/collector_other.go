//go:build !linux

package metrics

import "nyaservermonitor/internal/shared/model"

type platformState struct{}

func platformKernel() string { return "" }

func collectPlatform(state *platformState) (model.MetricsSnapshot, error) {
	return model.MetricsSnapshot{}, nil
}

func collectLivePlatform(state *platformState) (model.LiveTelemetry, error) {
	return model.LiveTelemetry{}, nil
}
