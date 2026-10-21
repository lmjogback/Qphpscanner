// Package target parses and expands user-supplied scan targets into a concrete
// list of endpoints. It understands single URLs, IPv4/IPv6 literals, hostnames,
// CIDR blocks, dashed ranges (1.2.3.4-9 or 1.2.3.4-1.2.3.9) and per-octet
// wildcards (1.2.3.* / 10.0.*.*).
package target

import (
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// DefaultMaxHosts bounds how many hosts a single spec may expand to, guarding
// against an accidental "0.0.0.0/0". Callers may override via ExpandOptions.
const DefaultMaxHosts = 65536

// Endpoint is one host (plus optional URL-derived hints) to be scanned.
type Endpoint struct {
	// Input is the original spec token this endpoint was derived from.
	Input string
	// Host is an IP literal or a DNS hostname.
	Host string
	// Scheme is a hint ("http"/"https") taken from a URL target, else "".
	Scheme string
	// Ports are explicit ports from a URL target. When nil the scanner's
	// global port selection is used instead.
	Ports []int
	// Path is the request path from a URL target, default "/".
	Path string
}

// ExpandOptions tunes expansion.
type ExpandOptions struct {
	MaxHosts int
}

func (o ExpandOptions) maxHosts() int {
	if o.MaxHosts > 0 {
		return o.MaxHosts
	}
	return DefaultMaxHosts
}

// Expand turns a single target spec into one or more endpoints.
func Expand(spec string, opts ExpandOptions) ([]Endpoint, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, nil
	}

	if strings.Contains(spec, "://") {
		return expandURL(spec)
	}

	hosts, err := expandHostSpec(spec, opts.maxHosts())
	if err != nil {
		return nil, err
	}
	eps := make([]Endpoint, 0, len(hosts))
	for _, h := range hosts {
		eps = append(eps, Endpoint{Input: spec, Host: h, Path: "/"})
	}
	return eps, nil
}

// ExpandAll expands every spec and concatenates the results.
func ExpandAll(specs []string, opts ExpandOptions) ([]Endpoint, error) {
	var out []Endpoint
	for _, s := range specs {
		eps, err := Expand(s, opts)
		if err != nil {
			return nil, fmt.Errorf("target %q: %w", s, err)
		}
		out = append(out, eps...)
	}
	return out, nil
}

func expandURL(spec string) ([]Endpoint, error) {
	u, err := url.Parse(spec)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("URL %q has no host", spec)
	}
	host := u.Hostname()
	ep := Endpoint{
		Input:  spec,
		Host:   host,
		Scheme: strings.ToLower(u.Scheme),
		Path:   u.EscapedPath(),
	}
	if ep.Path == "" {
		ep.Path = "/"
	}
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("URL %q has invalid port %q", spec, p)
		}
		ep.Ports = []int{n}
	}
	return []Endpoint{ep}, nil
}

// expandHostSpec handles everything that is not a URL.
func expandHostSpec(spec string, max int) ([]string, error) {
	// Strip IPv6 brackets ([::1] -> ::1).
	if strings.HasPrefix(spec, "[") && strings.HasSuffix(spec, "]") {
		spec = spec[1 : len(spec)-1]
	}

	// CIDR block.
	if strings.Contains(spec, "/") {
		return expandCIDR(spec, max)
	}

	// IPv6 literal (no wildcard/range support beyond CIDR and single).
	if isIPv6(spec) {
		addr, err := netip.ParseAddr(spec)
		if err != nil {
			return nil, fmt.Errorf("invalid IPv6 address %q: %w", spec, err)
		}
		return []string{addr.String()}, nil
	}

	// Full dashed IPv4 range: a.b.c.d-e.f.g.h
	if i := strings.IndexByte(spec, '-'); i >= 0 && strings.Count(spec, ".") >= 4 {
		left, right := spec[:i], spec[i+1:]
		if strings.Count(left, ".") == 3 && strings.Count(right, ".") == 3 {
			return expandIPv4FullRange(left, right, max)
		}
	}

	// Per-octet wildcard / dashed-octet IPv4 (1.2.3.*, 10.0.*.*, 1.2.3.4-9).
	if looksLikeIPv4Pattern(spec) {
		return expandIPv4Pattern(spec, max)
	}

	// Plain IPv4 literal.
	if addr, err := netip.ParseAddr(spec); err == nil {
		return []string{addr.String()}, nil
	}

	// Fall back to a DNS hostname; validate it has no spaces.
	if strings.ContainsAny(spec, " \t") {
		return nil, fmt.Errorf("invalid target %q", spec)
	}
	return []string{spec}, nil
}

func isIPv6(s string) bool {
	if !strings.Contains(s, ":") {
		return false
	}
	addr, err := netip.ParseAddr(s)
	return err == nil && addr.Is6() && !addr.Is4In6()
}

func looksLikeIPv4Pattern(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if p == "*" {
			continue
		}
		if strings.Contains(p, "-") {
			continue
		}
		if _, err := strconv.Atoi(p); err != nil {
			return false
		}
	}
	return true
}

func expandCIDR(spec string, max int) ([]string, error) {
	prefix, err := netip.ParsePrefix(spec)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR %q: %w", spec, err)
	}
	prefix = prefix.Masked()
	var out []string
	for addr := prefix.Addr(); prefix.Contains(addr); addr = addr.Next() {
		if !addr.IsValid() {
			break
		}
		out = append(out, addr.String())
		if len(out) > max {
			return nil, fmt.Errorf("CIDR %q expands to more than %d hosts; narrow the range or raise the limit", spec, max)
		}
	}
	return out, nil
}

func expandIPv4FullRange(left, right string, max int) ([]string, error) {
	lo, err := parseIPv4(left)
	if err != nil {
		return nil, err
	}
	hi, err := parseIPv4(right)
	if err != nil {
		return nil, err
	}
	if hi < lo {
		return nil, fmt.Errorf("range start %s is greater than end %s", left, right)
	}
	if hi-lo+1 > uint64(max) {
		return nil, fmt.Errorf("range %s-%s expands to more than %d hosts", left, right, max)
	}
	var out []string
	for v := lo; v <= hi; v++ {
		out = append(out, u32ToIPv4(uint32(v)))
		if v == hi {
			break
		}
	}
	return out, nil
}

func expandIPv4Pattern(spec string, max int) ([]string, error) {
	parts := strings.Split(spec, ".")
	ranges := make([][]int, 4)
	for i, p := range parts {
		switch {
		case p == "*":
			r := make([]int, 256)
			for v := 0; v < 256; v++ {
				r[v] = v
			}
			ranges[i] = r
		case strings.Contains(p, "-"):
			ab := strings.SplitN(p, "-", 2)
			a, err1 := strconv.Atoi(ab[0])
			b, err2 := strconv.Atoi(ab[1])
			if err1 != nil || err2 != nil || a < 0 || b > 255 || a > b {
				return nil, fmt.Errorf("invalid octet range %q", p)
			}
			r := make([]int, 0, b-a+1)
			for v := a; v <= b; v++ {
				r = append(r, v)
			}
			ranges[i] = r
		default:
			v, err := strconv.Atoi(p)
			if err != nil || v < 0 || v > 255 {
				return nil, fmt.Errorf("invalid octet %q", p)
			}
			ranges[i] = []int{v}
		}
	}

	total := len(ranges[0]) * len(ranges[1]) * len(ranges[2]) * len(ranges[3])
	if total > max {
		return nil, fmt.Errorf("pattern %q expands to %d hosts (limit %d)", spec, total, max)
	}

	out := make([]string, 0, total)
	for _, a := range ranges[0] {
		for _, b := range ranges[1] {
			for _, c := range ranges[2] {
				for _, d := range ranges[3] {
					out = append(out, fmt.Sprintf("%d.%d.%d.%d", a, b, c, d))
				}
			}
		}
	}
	return out, nil
}

func parseIPv4(s string) (uint64, error) {
	addr, err := netip.ParseAddr(s)
	if err != nil || !addr.Is4() {
		return 0, fmt.Errorf("invalid IPv4 address %q", s)
	}
	b := addr.As4()
	return uint64(b[0])<<24 | uint64(b[1])<<16 | uint64(b[2])<<8 | uint64(b[3]), nil
}

func u32ToIPv4(v uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}
