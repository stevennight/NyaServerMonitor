package model

import (
	"math"
	"strings"
)

func NormalizeGeoLocation(location *GeoLocation) {
	if location == nil {
		return
	}
	location.CountryCode = NormalizeCountryCode(location.CountryCode)
	if location.CountryCode != "" {
		location.Country = CountryName(location.CountryCode)
	}
	location.Region = normalizeGeoText(location.Region)
	location.RegionCode = strings.ToUpper(normalizeGeoText(location.RegionCode))
	location.City = normalizeGeoText(location.City)
	if !validGeoCoordinates(location.Latitude, location.Longitude) {
		location.Latitude = 0
		location.Longitude = 0
	}
}

func NormalizeNodeGeo(node *Node) {
	if node == nil {
		return
	}
	location := GeoLocation{
		Country:     node.Country,
		CountryCode: node.CountryCode,
		Region:      node.Region,
		RegionCode:  node.RegionCode,
		City:        node.City,
		Latitude:    node.Latitude,
		Longitude:   node.Longitude,
	}
	NormalizeGeoLocation(&location)
	node.Region = location.Region
	node.RegionCode = location.RegionCode
	node.City = location.City
	node.Latitude = location.Latitude
	node.Longitude = location.Longitude
}

func validGeoCoordinates(latitude, longitude float64) bool {
	return !math.IsNaN(latitude) && !math.IsInf(latitude, 0) && latitude >= -90 && latitude <= 90 &&
		!math.IsNaN(longitude) && !math.IsInf(longitude, 0) && longitude >= -180 && longitude <= 180
}

func normalizeGeoText(value string) string {
	return strings.Join(strings.Fields(strings.TrimSpace(value)), " ")
}
