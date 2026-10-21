package php

import (
	"fmt"
	"strconv"
	"strings"
	"time"
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
	if len(fields) == 0 {
		return 0, 0, 0, false
	}
	// Require at least a parseable major.minor.
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

// CorrelateVulns returns the catalogue entries whose version predicate matches.
// It only correlates for the native PHP variant; HHVM and others use their own
// version numbering and are skipped.
func CorrelateVulns(variant, version string) []Vulnerability {
	if version == "" {
		return nil
	}
	if variant != "" && variant != "PHP" && variant != "Zend Server" {
		return nil
	}
	maj, min, pat, ok := parseVersion(version)
	if !ok {
		return nil
	}

	var out []Vulnerability
	for _, e := range vulnDB {
		if e.match == nil || !e.match(maj, min, pat) {
			continue
		}
		basis := "version-correlation"
		if e.Note != "" {
			basis += "; applies to: " + e.Note
		}
		out = append(out, Vulnerability{
			ID:               e.ID,
			Severity:         e.Severity,
			Title:            e.Title,
			AffectedVersions: e.Affected,
			Description:      e.Description,
			Reference:        e.Reference,
			MatchBasis:       basis,
		})
	}
	return out
}

// evaluateEOL reports whether the detected version's release branch has
// reached end of security support, relative to the current date.
func evaluateEOL(variant, version string) (bool, string) {
	if variant != "" && variant != "PHP" && variant != "Zend Server" {
		return false, ""
	}
	maj, min, _, ok := parseVersion(version)
	if !ok {
		return false, ""
	}
	branch := fmt.Sprintf("%d.%d", maj, min)

	// Anything older than the oldest tracked 5.4 branch is certainly EOL.
	if maj < 5 || (maj == 5 && min < 4) {
		return true, fmt.Sprintf("PHP %s is long past end of life", branch)
	}

	info, known := eolTable[branch]
	if !known {
		// Unknown (e.g. a future branch); treat as supported.
		return false, ""
	}
	end, err := time.Parse("2006-01-02", info.securityEnd)
	if err != nil {
		return false, ""
	}
	if time.Now().After(end) {
		return true, fmt.Sprintf("PHP %s reached end of security support on %s", branch, info.securityEnd)
	}
	return false, fmt.Sprintf("PHP %s receives security support until %s", branch, info.securityEnd)
}
