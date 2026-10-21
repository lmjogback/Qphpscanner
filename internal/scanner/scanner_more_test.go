package scanner

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rom/qphpscanner/internal/target"
)

func TestProgressCallback(t *testing.T) {
	t.Setenv("NO_PROXY", "*")
	ts := phpTestServer()
	defer ts.Close()

	var mu sync.Mutex
	var events []ProgressEvent
	_, err := Scan(context.Background(), []string{ts.URL}, Options{
		Mode:    ModeDetect,
		TLSMode: TLSOff,
		Timeout: 3 * time.Second,
		OnProgress: func(ev ProgressEvent) {
			mu.Lock()
			events = append(events, ev)
			mu.Unlock()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) == 0 {
		t.Fatal("expected progress events")
	}
	last := events[len(events)-1]
	if last.Phase != "service" || last.Done != last.Total {
		t.Fatalf("final progress event unexpected: %+v", last)
	}
}

func TestIncludeClosed(t *testing.T) {
	t.Setenv("NO_PROXY", "*")
	res, err := Scan(context.Background(), []string{"127.0.0.1"}, Options{
		Mode:          ModeDetect,
		Ports:         []int{1},
		Timeout:       400 * time.Millisecond,
		IncludeClosed: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Targets) != 1 || res.Targets[0].Services[0].PortOpen {
		t.Fatalf("expected a closed service entry, got %+v", res.Targets)
	}
}

type fakeEnum struct{ hosts []string }

func (f fakeEnum) Enumerate(_ context.Context, _ string) ([]string, error) { return f.hosts, nil }

func TestDNSWildcardEnumeration(t *testing.T) {
	t.Setenv("NO_PROXY", "*")
	ts := phpTestServer()
	defer ts.Close()
	host, portStr, _ := net.SplitHostPort(strings.TrimPrefix(ts.URL, "http://"))
	port, _ := strconv.Atoi(portStr)

	var enumMsgs int
	res, err := Scan(context.Background(), []string{"*.example.test"}, Options{
		Mode:       ModeDetect,
		TLSMode:    TLSOff,
		Ports:      []int{port},
		Timeout:    3 * time.Second,
		Enumerator: fakeEnum{hosts: []string{host}},
		OnProgress: func(ev ProgressEvent) {
			if ev.Phase == "enumerate" {
				enumMsgs++
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if enumMsgs == 0 {
		t.Fatal("expected enumerate progress messages")
	}
	if len(res.Targets) != 1 || res.Targets[0].Host != host {
		t.Fatalf("expected enumerated host scanned, got %+v", res.Targets)
	}
	if res.Summary.PHPConfirmed != 1 {
		t.Fatalf("expected PHP on enumerated host, got %d", res.Summary.PHPConfirmed)
	}
}

func TestDNSWildcardDisabled(t *testing.T) {
	t.Setenv("NO_PROXY", "*")
	res, err := Scan(context.Background(), []string{"*.example.test"}, Options{
		Mode:           ModeDetect,
		DisableDNSEnum: true,
		Timeout:        time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Targets) != 0 {
		t.Fatalf("disabled enumeration should yield no targets, got %+v", res.Targets)
	}
}

func TestOpenNonHTTPPort(t *testing.T) {
	t.Setenv("NO_PROXY", "*")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	// Accept connections but never respond, forcing an HTTP read timeout.
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c // hold open; do not close immediately
			time.AfterFunc(2*time.Second, func() { c.Close() })
		}
	}()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)

	res, err := Scan(context.Background(), []string{"127.0.0.1"}, Options{
		Mode:          ModeDetect,
		TLSMode:       TLSOff,
		Ports:         []int{port},
		Timeout:       400 * time.Millisecond,
		IncludeClosed: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	svc := res.Targets[0].Services[0]
	if !svc.PortOpen {
		t.Fatal("port should be open")
	}
	if svc.HTTP != nil {
		t.Fatal("non-HTTP service should have no HTTP info")
	}
}

func TestScanDetectsProxyAndServer(t *testing.T) {
	t.Setenv("NO_PROXY", "*")
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "cloudflare")
		w.Header().Set("CF-RAY", "7abc-LHR")
		w.Header().Set("X-Powered-By", "PHP/8.2.0")
		_, _ = w.Write([]byte("<title>t</title>"))
	}))
	defer ts.Close()

	res, err := Scan(context.Background(), []string{ts.URL}, Options{
		Mode: ModeDetect, TLSMode: TLSOff, Timeout: 3 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	svc := res.Targets[0].Services[0]
	if svc.Proxy == nil || !svc.Proxy.Present || !svc.Proxy.Concealed {
		t.Fatalf("expected a concealing proxy: %+v", svc.Proxy)
	}
	found := false
	for _, c := range svc.Proxy.CDN {
		if c == "Cloudflare" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected Cloudflare CDN: %v", svc.Proxy.CDN)
	}
	if res.Summary.BehindProxy != 1 {
		t.Fatalf("summary BehindProxy = %d", res.Summary.BehindProxy)
	}
}

func TestDecideSchemesAndOrigin(t *testing.T) {
	cases := []struct {
		ep     target.Endpoint
		port   int
		mode   string
		scheme string
	}{
		{target.Endpoint{Scheme: "https"}, 80, TLSAuto, "https"},
		{target.Endpoint{Scheme: "http"}, 443, TLSAuto, "http"},
		{target.Endpoint{}, 443, TLSAuto, "https"},
		{target.Endpoint{}, 80, TLSAuto, "http"},
		{target.Endpoint{}, 80, TLSOn, "https"},
		{target.Endpoint{}, 443, TLSOff, "http"},
	}
	for _, c := range cases {
		got := decideSchemes(c.ep, c.port, c.mode)
		if got[0].scheme != c.scheme {
			t.Fatalf("decideSchemes(%+v,%d,%s) first=%s want %s", c.ep, c.port, c.mode, got[0].scheme, c.scheme)
		}
	}
	if origin("https", "2001:db8::1", 8443) != "https://[2001:db8::1]:8443" {
		t.Fatalf("ipv6 origin wrong: %s", origin("https", "2001:db8::1", 8443))
	}
	if ensureLeadingSlash("x") != "/x" || ensureLeadingSlash("") != "/" {
		t.Fatal("ensureLeadingSlash")
	}
}
