package model

import "testing"

func TestCountryCodeNormalization(t *testing.T) {
	tests := []struct {
		value string
		code  string
		name  string
	}{
		{value: "cn", code: "CN", name: "中国"},
		{value: "TW", code: "CN", name: "中国"},
		{value: "台湾", code: "CN", name: "中国"},
		{value: "中国台湾", code: "CN", name: "中国"},
		{value: "Japan", code: "JP", name: "日本"},
		{value: "EX", code: "EX", name: "EX"},
	}
	for _, test := range tests {
		if got := CountryCodeFromValue(test.value); got != test.code {
			t.Errorf("CountryCodeFromValue(%q) = %q, want %q", test.value, got, test.code)
		}
		if got := CountryName(test.code); got != test.name {
			t.Errorf("CountryName(%q) = %q, want %q", test.code, got, test.name)
		}
	}
}

func TestNormalizeNodeCountryUsesCodeAsSource(t *testing.T) {
	node := Node{Country: "Taiwan", CountryCode: "TW", CountryOverride: "Japan"}
	NormalizeNodeCountry(&node)
	if node.CountryCode != "CN" || node.Country != "中国" || node.CountryOverride != "JP" {
		t.Fatalf("normalized node country = %#v", node)
	}
}
