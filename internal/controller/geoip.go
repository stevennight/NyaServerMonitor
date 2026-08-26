package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"nyaservermonitor/internal/shared/model"
)

const (
	defaultGeoIPURL = "https://ipwho.is/{ip}"
	geoIPMaxBody    = 64 << 10
)

type geoIPLookup struct {
	endpoint string
	client   *http.Client
}

type geoIPResponse struct {
	Success     *bool   `json:"success"`
	Error       bool    `json:"error"`
	Message     string  `json:"message"`
	Country     string  `json:"country"`
	CountryName string  `json:"country_name"`
	CountryCode string  `json:"country_code"`
	CountryAlt  string  `json:"countryCode"`
	Region      string  `json:"region"`
	RegionCode  string  `json:"region_code"`
	City        string  `json:"city"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
}

func newGeoIPLookup(endpoint string) *geoIPLookup {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return nil
	}
	return &geoIPLookup{
		endpoint: endpoint,
		client:   &http.Client{Timeout: 5 * time.Second},
	}
}

func (g *geoIPLookup) lookup(ctx context.Context, ip string) (model.GeoLocation, error) {
	if g == nil {
		return model.GeoLocation{}, errors.New("geoip lookup is disabled")
	}
	parsedIP := net.ParseIP(strings.Trim(ip, "[]"))
	if !eligibleGeoIP(parsedIP) {
		return model.GeoLocation{}, errors.New("IP is not eligible for geoip lookup")
	}
	if !strings.Contains(g.endpoint, "{ip}") {
		return model.GeoLocation{}, errors.New("geoip URL must contain {ip}")
	}
	endpoint := strings.ReplaceAll(g.endpoint, "{ip}", url.PathEscape(parsedIP.String()))
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return model.GeoLocation{}, fmt.Errorf("create geoip request: %w", err)
	}
	response, err := g.client.Do(request)
	if err != nil {
		return model.GeoLocation{}, fmt.Errorf("geoip request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return model.GeoLocation{}, fmt.Errorf("geoip returned HTTP %d", response.StatusCode)
	}
	var payload geoIPResponse
	decoder := json.NewDecoder(io.LimitReader(response.Body, geoIPMaxBody))
	if err := decoder.Decode(&payload); err != nil {
		return model.GeoLocation{}, fmt.Errorf("decode geoip response: %w", err)
	}
	if payload.Success != nil && !*payload.Success || payload.Error {
		if strings.TrimSpace(payload.Message) == "" {
			return model.GeoLocation{}, errors.New("geoip lookup failed")
		}
		return model.GeoLocation{}, errors.New(strings.TrimSpace(payload.Message))
	}
	countryCode := strings.TrimSpace(payload.CountryCode)
	if countryCode == "" {
		countryCode = strings.TrimSpace(payload.CountryAlt)
	}
	countryCode = model.NormalizeCountryCode(countryCode)
	if countryCode == "" {
		return model.GeoLocation{}, errors.New("geoip response did not contain a valid country_code")
	}
	location := model.GeoLocation{
		Country:     model.CountryName(countryCode),
		CountryCode: countryCode,
		Region:      payload.Region,
		RegionCode:  payload.RegionCode,
		City:        payload.City,
		Latitude:    payload.Latitude,
		Longitude:   payload.Longitude,
	}
	model.NormalizeGeoLocation(&location)
	return location, nil
}

func eligibleGeoIP(ip net.IP) bool {
	return ip != nil && !ip.IsLoopback() && !ip.IsPrivate() && !ip.IsLinkLocalUnicast() && !ip.IsMulticast() && !ip.IsUnspecified()
}
