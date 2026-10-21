package target

import "testing"

func TestIsDNSWildcard(t *testing.T) {
	cases := map[string]string{
		"*.foo.com":     "foo.com",
		"*.a.b.example": "a.b.example",
	}
	for in, want := range cases {
		d, ok := IsDNSWildcard(in)
		if !ok || d != want {
			t.Fatalf("IsDNSWildcard(%q) = %q,%v want %q", in, d, ok, want)
		}
	}
	for _, in := range []string{"foo.com", "*.1.2.3", "*.", "*.foo bar.com", "*nodot", "10.0.0.0/8"} {
		if _, ok := IsDNSWildcard(in); ok {
			t.Fatalf("IsDNSWildcard(%q) should be false", in)
		}
	}
}

func TestExpandErrors(t *testing.T) {
	bad := []string{
		"https://",        // no host
		"http://h:99999/", // bad port
		"10.0.0.0/999",    // bad CIDR
		"1.2.3.4-1.2.3.1", // reversed full range
		"1.2.3.300",       // bad octet literal
		"1.2.3.5-1",       // reversed octet range
		"1.2.3.4-999",     // octet out of range
		"has space",       // invalid host
	}
	for _, spec := range bad {
		if _, err := Expand(spec, ExpandOptions{}); err == nil {
			t.Fatalf("Expand(%q) expected error", spec)
		}
	}
}

func TestExpandEmpty(t *testing.T) {
	eps, err := Expand("   ", ExpandOptions{})
	if err != nil || eps != nil {
		t.Fatalf("empty spec should be a no-op, got %v %v", eps, err)
	}
}

func TestExpandIPv6CIDRAndBracket(t *testing.T) {
	hs := hostsOf(t, "2001:db8::/126")
	if len(hs) != 4 {
		t.Fatalf("want 4 IPv6 hosts, got %d: %v", len(hs), hs)
	}
	bh := hostsOf(t, "[2001:db8::5]")
	if len(bh) != 1 || bh[0] != "2001:db8::5" {
		t.Fatalf("bracketed IPv6: %v", bh)
	}
}

func TestExpandIPv6Range(t *testing.T) {
	hs := hostsOf(t, "2001:db8::1-2001:db8::5")
	if len(hs) != 5 || hs[0] != "2001:db8::1" || hs[4] != "2001:db8::5" {
		t.Fatalf("IPv6 range: %v", hs)
	}
}

func TestExpandIPv6Wildcard(t *testing.T) {
	hs := hostsOf(t, "2001:db8::ff00:*")
	if len(hs) != 65536 {
		t.Fatalf("IPv6 wildcard should expand to 65536, got %d", len(hs))
	}
	if hs[0] != "2001:db8::ff00:0" {
		t.Fatalf("first: %s", hs[0])
	}
}

func TestExpandIPv6Errors(t *testing.T) {
	if _, err := Expand("2001:db8::5-2001:db8::1", ExpandOptions{}); err == nil {
		t.Fatal("reversed IPv6 range should error")
	}
	if _, err := Expand("2001:db8::zz*", ExpandOptions{}); err == nil {
		t.Fatal("invalid IPv6 wildcard should error")
	}
	if _, err := Expand("2001:db8::1-2001:db8::ffff", ExpandOptions{MaxHosts: 10}); err == nil {
		t.Fatal("oversized IPv6 range should error")
	}
}

func TestExpandAll(t *testing.T) {
	eps, err := ExpandAll([]string{"192.168.0.1", "192.168.0.2"}, ExpandOptions{})
	if err != nil || len(eps) != 2 {
		t.Fatalf("ExpandAll: %v %v", eps, err)
	}
	if _, err := ExpandAll([]string{"10.0.0.0/8"}, ExpandOptions{MaxHosts: 10}); err == nil {
		t.Fatal("ExpandAll should propagate expansion errors")
	}
}
