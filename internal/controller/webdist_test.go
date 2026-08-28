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
		"data-service-check-id",
		"packet_loss_percent",
		"service-check-target",
		"最多同时比较 6 个服务检查",
	} {
		if !strings.Contains(page, required) {
			t.Fatalf("admin service-check history UI is missing %q", required)
		}
	}
}
