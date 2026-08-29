package controller

import (
	"strings"
	"testing"
)

func TestAdminServiceCheckHistoryUIIsEmbedded(t *testing.T) {
	data, err := webFiles.ReadFile("webdist/index.html")
	if err != nil {
		t.Fatal(err)
	}
	page := string(data)
	for _, required := range []string{
		"serviceCheckHistoryChart",
		"service-check-chart-host",
		"service-chart-readout",
		"data-service-check-id",
		"packet_loss_percent",
		"service-check-target",
		"showsPacketLoss = selected.length === 1 && selected[0].type === 'ping'",
		"HTTP/TCP 失败点标红",
		"最多同时比较 6 个服务检查",
	} {
		if !strings.Contains(page, required) {
			t.Fatalf("admin service-check history UI is missing %q", required)
		}
	}
}

func TestNodeDetailChartsAndRefreshUIAreEmbedded(t *testing.T) {
	data, err := webFiles.ReadFile("webdist/index.html")
	if err != nil {
		t.Fatal(err)
	}
	page := string(data)
	for _, required := range []string{
		"chart-readout",
		"可见时间刻度数值",
		"detailRefreshIntervalMillis = 15000",
		"refreshAdminDetail",
		"service-check-current-host",
		"service-history-host",
		"modal modal-wide",
		"position:sticky;top:0",
		"node-detail-modal-body",
	} {
		if !strings.Contains(page, required) {
			t.Fatalf("node detail chart/refresh UI is missing %q", required)
		}
	}
}
