package version

import (
	"strconv"
	"strings"
)

var (
	Version         = "0.1.0-dev"
	Commit          = "unknown"
	BuildDate       = "unknown"
	UpdatePublicKey = ""
)

func NeedsUpdate(currentVersion, desiredVersion string) bool {
	if desiredVersion == "" {
		return false
	}
	if currentVersion == "" {
		return true
	}
	return Compare(currentVersion, desiredVersion) < 0
}

func Compare(left, right string) int {
	leftParts := versionParts(left)
	rightParts := versionParts(right)
	for index := 0; index < len(leftParts) || index < len(rightParts); index++ {
		var leftValue, rightValue int
		if index < len(leftParts) {
			leftValue = leftParts[index]
		}
		if index < len(rightParts) {
			rightValue = rightParts[index]
		}
		if leftValue < rightValue {
			return -1
		}
		if leftValue > rightValue {
			return 1
		}
	}
	return 0
}

func versionParts(value string) []int {
	value = strings.TrimPrefix(strings.TrimSpace(value), "v")
	if index := strings.IndexAny(value, "+-"); index >= 0 {
		value = value[:index]
	}
	parts := strings.Split(value, ".")
	values := make([]int, 0, len(parts))
	for _, part := range parts {
		value, _ := strconv.Atoi(part)
		values = append(values, value)
	}
	return values
}
