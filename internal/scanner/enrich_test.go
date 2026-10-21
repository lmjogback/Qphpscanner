package scanner

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

type fakeDNS struct {
	hosts map[string][]string
	ptr   map[string][]string
}

func (f fakeDNS) LookupHost(_ context.Context, host string) ([]string, error) {
	if a, ok := f.hosts[host]; ok {
		return a, nil
	}
	return nil, errors.New("no such host")
}

func (f fakeDNS) LookupAddr(_ context.Context, addr string) ([]string, error) {
	if n, ok := f.ptr[addr]; ok {
		return n, nil
	}
	return nil, errors.New("no ptr")
}

func TestResolveHost(t *testing.T) {
	f := fakeDNS{
		hosts: map[string][]string{"example.com": {"203.0.113.4"}},
		ptr:   map[string][]string{"203.0.113.4": {"host.example."}, "9.9.9.9": {"dns9.example"}},
	}
	addrs, ptr := resolveHost(context.Background(), f, "example.com")
	if len(addrs) != 1 || addrs[0] != "203.0.113.4" || len(ptr) != 1 || ptr[0] != "host.example" {
		t.Fatalf("name resolve: %v %v", addrs, ptr)
	}
	// IP literal: forward is the IP itself, reverse via PTR.
	a2, p2 := resolveHost(context.Background(), f, "9.9.9.9")
	if len(a2) != 1 || a2[0] != "9.9.9.9" || len(p2) != 1 || p2[0] != "dns9.example" {
		t.Fatalf("ip resolve: %v %v", a2, p2)
	}
}

func TestScanResolveDNS(t *testing.T) {
	t.Setenv("NO_PROXY", "*")
	ts := phpTestServer()
	defer ts.Close()
	res, err := Scan(context.Background(), []string{ts.URL}, Options{
		Mode: ModeDetect, TLSMode: TLSOff, Timeout: 3 * time.Second,
		ResolveDNS: true,
		Resolver:   fakeDNS{ptr: map[string][]string{"127.0.0.1": {"localhost"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	tr := res.Targets[0]
	if len(tr.Addresses) != 1 || tr.Addresses[0] != "127.0.0.1" || len(tr.PTR) != 1 || tr.PTR[0] != "localhost" {
		t.Fatalf("DNS enrichment: %+v", tr)
	}
}

func TestCheckpointRoundTrip(t *testing.T) {
	// A nil-path checkpoint is a no-op.
	noop, err := loadCheckpoint("")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := noop.lookup(jobKey("h", 80)); ok {
		t.Fatal("empty checkpoint should have nothing")
	}
	noop.record(ServiceResult{Host: "h", Port: 80})
	noop.close()

	path := filepath.Join(t.TempDir(), "cp.ndjson")
	c, err := loadCheckpoint(path)
	if err != nil {
		t.Fatal(err)
	}
	c.record(ServiceResult{Host: "h", Port: 80, PortOpen: true})
	c.record(ServiceResult{Host: "h", Port: 443, PortOpen: false})
	c.close()

	c2, err := loadCheckpoint(path)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.close()
	r, ok := c2.lookup(jobKey("h", 80))
	if !ok || !r.PortOpen {
		t.Fatalf("resume lookup failed: %+v ok=%v", r, ok)
	}
	if _, ok := c2.lookup(jobKey("h", 8080)); ok {
		t.Fatal("unknown key should miss")
	}
}

func TestScanResumeSkips(t *testing.T) {
	t.Setenv("NO_PROXY", "*")
	ts := phpTestServer()
	defer ts.Close()
	host, portStr, _ := net.SplitHostPort(trimScheme(ts.URL))
	port, _ := strconv.Atoi(portStr)

	path := filepath.Join(t.TempDir(), "cp.ndjson")
	// Seed the checkpoint with a fake "already done" result for this service.
	seed, _ := loadCheckpoint(path)
	seed.record(ServiceResult{Host: host, Port: port, PortOpen: true, Scheme: "http",
		URL: ts.URL + "/", Banner: "from-checkpoint"})
	seed.close()

	res, err := Scan(context.Background(), []string{host}, Options{
		Mode: ModeDetect, Ports: []int{port}, TLSMode: TLSOff, Timeout: 3 * time.Second,
		IncludeClosed: true, CheckpointPath: path,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Targets[0].Services[0].Banner != "from-checkpoint" {
		t.Fatalf("expected resumed result, got %+v", res.Targets[0].Services[0])
	}
}

func TestHostGate(t *testing.T) {
	g := newHostGate(1)
	g.acquire("h")
	released := make(chan struct{})
	go func() {
		g.acquire("h") // blocks until the first is released
		released <- struct{}{}
		g.release("h")
	}()
	select {
	case <-released:
		t.Fatal("second acquire should have blocked")
	case <-time.After(100 * time.Millisecond):
	}
	g.release("h")
	select {
	case <-released:
	case <-time.After(time.Second):
		t.Fatal("second acquire never proceeded")
	}

	// Zero gate is a no-op.
	z := newHostGate(0)
	z.acquire("x")
	z.release("x")
}

func TestRateBurst(t *testing.T) {
	if rateBurst(0) != 0 || rateBurst(5) != 5 || rateBurst(0.5) != 1 {
		t.Fatal("rateBurst")
	}
}

func trimScheme(u string) string {
	for _, p := range []string{"http://", "https://"} {
		if len(u) >= len(p) && u[:len(p)] == p {
			return u[len(p):]
		}
	}
	return u
}
