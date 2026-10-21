package target

import "testing"

func hostsOf(t *testing.T, spec string) []string {
	t.Helper()
	eps, err := Expand(spec, ExpandOptions{})
	if err != nil {
		t.Fatalf("Expand(%q) error: %v", spec, err)
	}
	hs := make([]string, len(eps))
	for i, e := range eps {
		hs[i] = e.Host
	}
	return hs
}

func TestExpandURL(t *testing.T) {
	eps, err := Expand("https://example.com:8443/app.php", ExpandOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(eps) != 1 {
		t.Fatalf("want 1 endpoint, got %d", len(eps))
	}
	e := eps[0]
	if e.Host != "example.com" || e.Scheme != "https" || e.Path != "/app.php" {
		t.Fatalf("unexpected endpoint: %+v", e)
	}
	if len(e.Ports) != 1 || e.Ports[0] != 8443 {
		t.Fatalf("want port 8443, got %v", e.Ports)
	}
}

func TestExpandCIDR(t *testing.T) {
	hs := hostsOf(t, "10.0.0.0/30")
	want := []string{"10.0.0.0", "10.0.0.1", "10.0.0.2", "10.0.0.3"}
	if len(hs) != len(want) {
		t.Fatalf("want %d hosts, got %d (%v)", len(want), len(hs), hs)
	}
	for i := range want {
		if hs[i] != want[i] {
			t.Fatalf("host %d: want %s got %s", i, want[i], hs[i])
		}
	}
}

func TestExpandDashLastOctet(t *testing.T) {
	hs := hostsOf(t, "192.168.1.1-3")
	if len(hs) != 3 || hs[0] != "192.168.1.1" || hs[2] != "192.168.1.3" {
		t.Fatalf("unexpected: %v", hs)
	}
}

func TestExpandFullRange(t *testing.T) {
	hs := hostsOf(t, "10.0.0.250-10.0.1.2")
	want := []string{"10.0.0.250", "10.0.0.251", "10.0.0.252", "10.0.0.253", "10.0.0.254", "10.0.0.255", "10.0.1.0", "10.0.1.1", "10.0.1.2"}
	if len(hs) != len(want) {
		t.Fatalf("want %d got %d: %v", len(want), len(hs), hs)
	}
}

func TestExpandWildcard(t *testing.T) {
	hs := hostsOf(t, "192.168.5.*")
	if len(hs) != 256 || hs[0] != "192.168.5.0" || hs[255] != "192.168.5.255" {
		t.Fatalf("unexpected wildcard expansion: %d hosts", len(hs))
	}
}

func TestExpandIPv6(t *testing.T) {
	hs := hostsOf(t, "2001:db8::1")
	if len(hs) != 1 || hs[0] != "2001:db8::1" {
		t.Fatalf("unexpected: %v", hs)
	}
}

func TestExpandHostname(t *testing.T) {
	hs := hostsOf(t, "example.com")
	if len(hs) != 1 || hs[0] != "example.com" {
		t.Fatalf("unexpected: %v", hs)
	}
}

func TestExpandCapExceeded(t *testing.T) {
	if _, err := Expand("10.0.0.0/8", ExpandOptions{MaxHosts: 1000}); err == nil {
		t.Fatal("expected error for oversized CIDR")
	}
}
