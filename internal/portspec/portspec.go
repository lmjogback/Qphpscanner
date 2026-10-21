// Package portspec parses port specifications such as "80", "80,443,8080" and
// "8000-8100", including mixtures like "80,443,8000-8010".
package portspec

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// DefaultWebPorts is the port set used when the user does not specify any.
// It covers the common HTTP/HTTPS and alternate web-service ports where a
// PHP application is most likely to be reachable.
var DefaultWebPorts = []int{80, 443, 8000, 8008, 8080, 8443, 8888, 3000, 5000, 9000}

// Parse turns a port spec string into a sorted, de-duplicated list of ports.
func Parse(spec string) ([]int, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, fmt.Errorf("empty port specification")
	}

	seen := map[int]struct{}{}
	for _, tok := range strings.Split(spec, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		if strings.Contains(tok, "-") {
			lo, hi, err := parseRange(tok)
			if err != nil {
				return nil, err
			}
			for p := lo; p <= hi; p++ {
				seen[p] = struct{}{}
			}
			continue
		}
		p, err := parsePort(tok)
		if err != nil {
			return nil, err
		}
		seen[p] = struct{}{}
	}

	if len(seen) == 0 {
		return nil, fmt.Errorf("port specification %q yielded no ports", spec)
	}

	out := make([]int, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Ints(out)
	return out, nil
}

func parseRange(tok string) (int, int, error) {
	parts := strings.SplitN(tok, "-", 2)
	lo, err := parsePort(strings.TrimSpace(parts[0]))
	if err != nil {
		return 0, 0, err
	}
	hi, err := parsePort(strings.TrimSpace(parts[1]))
	if err != nil {
		return 0, 0, err
	}
	if lo > hi {
		return 0, 0, fmt.Errorf("port range %q is reversed", tok)
	}
	return lo, hi, nil
}

func parsePort(tok string) (int, error) {
	p, err := strconv.Atoi(tok)
	if err != nil {
		return 0, fmt.Errorf("invalid port %q", tok)
	}
	if p < 1 || p > 65535 {
		return 0, fmt.Errorf("port %d out of range (1-65535)", p)
	}
	return p, nil
}
