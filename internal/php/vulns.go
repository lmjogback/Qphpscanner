package php

import (
	"strconv"
	"strings"
)

// parseVersion extracts major.minor.patch from a version string, tolerating
// suffixes such as "-dev", "RC1" or "p1". Missing components default to 0.
func parseVersion(v string) (maj, min, pat int, ok bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, 0, 0, false
	}
	fields := strings.SplitN(v, ".", 4)
	nums := make([]int, 3)
	for i := 0; i < 3 && i < len(fields); i++ {
		nums[i] = leadingInt(fields[i])
	}
	if _, err := strconv.Atoi(trimToDigits(fields[0])); err != nil {
		return 0, 0, 0, false
	}
	return nums[0], nums[1], nums[2], true
}

func leadingInt(s string) int {
	n := 0
	started := false
	for _, r := range s {
		if r < '0' || r > '9' {
			if started {
				break
			}
			continue
		}
		started = true
		n = n*10 + int(r-'0')
	}
	return n
}

func trimToDigits(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		} else if b.Len() > 0 {
			break
		}
	}
	if b.Len() == 0 {
		return "x"
	}
	return b.String()
}

// CorrelateVulns correlates PHP-core leads against the built-in catalogue.
// It is a convenience wrapper over DefaultCatalog().CorrelatePHP.
func CorrelateVulns(variant, version string) []Vulnerability {
	return DefaultCatalog().CorrelatePHP(variant, version)
}

// evaluateEOL reports branch end-of-life using the built-in catalogue.
func evaluateEOL(variant, version string) (bool, string) {
	return DefaultCatalog().EOL(variant, version)
}
