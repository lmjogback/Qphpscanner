package scanner

import (
	"encoding/binary"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/qphpscanner/internal/php"
	"github.com/rom/qphpscanner/internal/probe"
	"github.com/rom/qphpscanner/internal/webserver"
)

func TestServerIP(t *testing.T) {
	if got := serverIP("203.0.113.9"); got != [4]byte{203, 0, 113, 9} {
		t.Errorf("IPv4 literal: got %v", got)
	}
	// Hostname synthesises a stable 10.x.y.z, never ending in .0 or .255.
	a := serverIP("example.test")
	b := serverIP("example.test")
	if a != b {
		t.Errorf("synth not deterministic: %v vs %v", a, b)
	}
	if a[0] != 10 {
		t.Errorf("synth not in 10/8: %v", a)
	}
	if a[3] == 0 || a[3] == 255 {
		t.Errorf("synth last octet invalid: %v", a)
	}
	// IPv6 literal cannot ride raw IPv4, so it is also synthesised.
	if v6 := serverIP("2001:db8::1"); v6[0] != 10 {
		t.Errorf("IPv6 should synthesise into 10/8, got %v", v6)
	}
}

func TestClampPort(t *testing.T) {
	cases := map[int]uint16{0: 80, -1: 80, 70000: 80, 8080: 8080, 443: 443}
	for in, want := range cases {
		if got := clampPort(in); got != want {
			t.Errorf("clampPort(%d) = %d, want %d", in, got, want)
		}
	}
}

func TestRequestTarget(t *testing.T) {
	cases := map[string]string{
		"http://h:80/a/b?x=1&y=2": "/a/b?x=1&y=2",
		"https://h/":              "/",
		"http://h":                "/",
		"://bad url":              "/",
	}
	for in, want := range cases {
		if got := requestTarget(in); got != want {
			t.Errorf("requestTarget(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRequestResponseBytes(t *testing.T) {
	ex := probe.Exchange{
		Method:  "GET",
		URL:     "http://host.test:80/index.php?a=1",
		ReqHost: "host.test",
		ReqHeaders: http.Header{
			"User-Agent": {"qphpscanner"},
			"Accept":     {"*/*"},
			"Host":       {"ignored.test"},
		},
		Status:      200,
		Proto:       "HTTP/1.1",
		RespHeaders: http.Header{"Server": {"Apache"}, "X-Powered-By": {"PHP/8.1.2"}},
		RespBody:    []byte("<html>ok</html>"),
	}
	req := string(requestBytes(ex))
	if !strings.HasPrefix(req, "GET /index.php?a=1 HTTP/1.1\r\n") {
		t.Errorf("request line wrong: %q", req)
	}
	if !strings.Contains(req, "Host: host.test\r\n") {
		t.Errorf("missing Host header: %q", req)
	}
	if strings.Count(req, "Host:") != 1 {
		t.Errorf("Host header duplicated: %q", req)
	}
	if !strings.Contains(req, "User-Agent: qphpscanner\r\n") {
		t.Errorf("missing User-Agent: %q", req)
	}
	if !strings.HasSuffix(req, "\r\n\r\n") {
		t.Errorf("request not terminated by blank line: %q", req)
	}

	resp := string(responseBytes(ex))
	if !strings.HasPrefix(resp, "HTTP/1.1 200 OK\r\n") {
		t.Errorf("status line wrong: %q", resp)
	}
	if !strings.Contains(resp, "X-Powered-By: PHP/8.1.2\r\n") {
		t.Errorf("missing response header: %q", resp)
	}
	if !strings.HasSuffix(resp, "<html>ok</html>") {
		t.Errorf("missing body: %q", resp)
	}

	// No response arrived.
	if responseBytes(probe.Exchange{Status: 0}) != nil {
		t.Error("responseBytes with status 0 should be nil")
	}
	// Missing proto defaults to HTTP/1.1.
	if r := string(responseBytes(probe.Exchange{Status: 404})); !strings.HasPrefix(r, "HTTP/1.1 404 Not Found\r\n") {
		t.Errorf("default proto wrong: %q", r)
	}
}

func TestWriteHeadersSortedAndOmit(t *testing.T) {
	var b strings.Builder
	writeHeaders(&b, http.Header{"Zeta": {"z"}, "Alpha": {"a"}, "Drop": {"d"}}, map[string]bool{"Drop": true})
	got := b.String()
	if strings.Contains(got, "Drop") {
		t.Errorf("omitted header present: %q", got)
	}
	if strings.Index(got, "Alpha") > strings.Index(got, "Zeta") {
		t.Errorf("headers not sorted: %q", got)
	}
	// nil header is a no-op.
	var b2 strings.Builder
	writeHeaders(&b2, nil, nil)
	if b2.Len() != 0 {
		t.Error("nil header should write nothing")
	}
}

func TestIntsCSVAndProxyDetail(t *testing.T) {
	if got := intsCSV([]int{80, 443, 8080}); got != "80,443,8080" {
		t.Errorf("intsCSV = %q", got)
	}
	p := &webserver.ProxyInfo{
		Present: true, CDN: []string{"Cloudflare"}, WAF: []string{"ModSecurity"},
		LoadBalancers: []string{"HAProxy"}, Caches: []string{"Varnish"},
	}
	d := proxyDetail(p)
	for _, want := range []string{"CDN Cloudflare", "WAF ModSecurity", "LB HAProxy", "cache Varnish"} {
		if !strings.Contains(d, want) {
			t.Errorf("proxyDetail missing %q: %q", want, d)
		}
	}
	if proxyDetail(&webserver.ProxyInfo{Present: true}) != "" {
		t.Error("proxyDetail with no components should be empty")
	}
}

func TestAuditSinkDisabled(t *testing.T) {
	a, err := newAuditSink(Options{}, nil, time.Now())
	if err != nil {
		t.Fatalf("newAuditSink: %v", err)
	}
	if a != nil {
		t.Fatal("expected nil sink when neither path is set")
	}
	// Methods on nil sink must not panic.
	a.Record(probe.Exchange{})
	a.logService(ServiceResult{})
	a.logResumed(ServiceResult{})
	if err := a.close(); err != nil {
		t.Errorf("nil close: %v", err)
	}
}

func TestAuditSinkEndToEnd(t *testing.T) {
	dir := t.TempDir()
	pcapPath := filepath.Join(dir, "scan.pcap")
	logPath := filepath.Join(dir, "scan.log")
	opts := Options{Mode: ModeDeep, Ports: []int{80}, PCAPPath: pcapPath, LogPath: logPath}

	a, err := newAuditSink(opts, []string{"host.test"}, time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatalf("newAuditSink: %v", err)
	}
	if a == nil {
		t.Fatal("expected a sink")
	}

	a.Record(probe.Exchange{
		Time: time.Unix(1_700_000_000, 0), Method: "GET", URL: "http://host.test:80/",
		Host: "host.test", Port: 80, ReqHost: "host.test",
		ReqHeaders:  http.Header{"User-Agent": {"qphpscanner"}},
		Status:      200,
		Proto:       "HTTP/1.1",
		RespHeaders: http.Header{"Server": {"Apache/2.4.1"}, "X-Powered-By": {"PHP/8.1.2"}},
		RespBody:    []byte("<html>hi</html>"),
	})
	// A transport-level failure (no response).
	a.Record(probe.Exchange{
		Time: time.Unix(1_700_000_001, 0), Method: "GET", URL: "http://host.test:80/x",
		Host: "host.test", Port: 80, ReqHost: "host.test", Err: "connection reset",
	})

	res := ServiceResult{
		Host: "host.test", Port: 80, PortOpen: true, URL: "http://host.test:80/",
		HTTP:   &HTTPInfo{Status: 200},
		Server: &webserver.ServerInfo{Product: "Apache", Version: "2.4.1"},
		Proxy:  &webserver.ProxyInfo{Present: true, CDN: []string{"Cloudflare"}},
		PHP: &php.Detection{
			Verdict: php.VerdictConfirmed, Confidence: 95, Version: "8.1.2",
			VersionSource: "X-Powered-By header", EndOfLife: true, EOLDetail: "8.1 reached EOL",
			Evidence: []php.Evidence{{
				Signal: "header.x-powered-by", Detail: "X-Powered-By reveals PHP",
				Weight: 70, Confidence: "high", Where: "response header 'X-Powered-By'",
				How: "header substring match", Pattern: "PHP/", Snippet: "PHP/8.1.2",
				Probe: "GET http://host.test:80/",
			}, {
				Signal: "body.marker", Detail: "body marker", Weight: 10, Confidence: "low",
				Source: "body", Line: 3,
			}},
			Vulnerabilities: []php.Vulnerability{{ID: "CVE-0000-0001", Severity: "high", Title: "x"}},
		},
	}
	a.logService(res)

	// Closed and no-HTTP services exercise the other branches.
	a.logService(ServiceResult{Host: "h2", Port: 81, URL: "http://h2:81/", Error: "refused"})
	a.logService(ServiceResult{Host: "h3", Port: 82, URL: "http://h3:82/", PortOpen: true, Banner: "SSH-2.0"})
	a.logResumed(ServiceResult{Host: "h4", Port: 83, URL: "http://h4:83/"})

	if err := a.close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	log := string(logData)
	for _, want := range []string{
		"qphpscanner session log",
		"mode:    deep",
		"GET http://host.test:80/",
		"Server: Apache/2.4.1",
		"transport error: connection reset",
		"DECISION  host.test:80",
		"web server: Apache 2.4.1",
		"reverse proxy: YES",
		"PHP verdict: CONFIRMED (confidence 95/100)",
		"version: 8.1.2 — learned via X-Powered-By header",
		"END OF LIFE",
		"header.x-powered-by",
		"matcher: PHP/",
		"match: PHP/8.1.2",
		"body line: 3",
		"vulnerability leads: 1",
		"port closed/filtered",
		"open port, no HTTP response",
		"banner: SSH-2.0",
		"resumed from checkpoint",
		"session finished:",
	} {
		if !strings.Contains(log, want) {
			t.Errorf("session log missing %q", want)
		}
	}

	pcapData, err := os.ReadFile(pcapPath)
	if err != nil {
		t.Fatalf("read pcap: %v", err)
	}
	if len(pcapData) < 24 {
		t.Fatal("pcap missing global header")
	}
	if binary.LittleEndian.Uint32(pcapData[0:]) != 0xa1b2c3d4 {
		t.Error("pcap magic wrong")
	}
	if len(pcapData) <= 24 {
		t.Error("pcap has no packets")
	}
}

func TestAuditSinkNoPHP(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "s.log")
	a, err := newAuditSink(Options{Ports: []int{80}, LogPath: logPath}, nil, time.Now())
	if err != nil {
		t.Fatalf("newAuditSink: %v", err)
	}
	// Service with HTTP but no PHP analysis, and no evidence.
	a.logService(ServiceResult{
		Host: "h", Port: 80, PortOpen: true, URL: "http://h:80/", HTTP: &HTTPInfo{Status: 200},
	})
	a.logService(ServiceResult{
		Host: "h", Port: 80, PortOpen: true, URL: "http://h:80/", HTTP: &HTTPInfo{Status: 200},
		PHP: &php.Detection{Verdict: php.VerdictNone, Confidence: 0},
	})
	if err := a.close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	b, _ := os.ReadFile(logPath)
	log := string(b)
	if !strings.Contains(log, "PHP verdict: not analysed") {
		t.Errorf("missing not-analysed line:\n%s", log)
	}
	if !strings.Contains(log, "no positive PHP evidence") {
		t.Errorf("missing no-evidence line:\n%s", log)
	}
}

func TestNewAuditSinkErrors(t *testing.T) {
	// Unwritable pcap path.
	if _, err := newAuditSink(Options{PCAPPath: filepath.Join(t.TempDir(), "nope", "a.pcap")}, nil, time.Now()); err == nil {
		t.Error("expected error for bad pcap path")
	}
	// Good pcap but bad log path: the already-opened pcap file must be closed.
	dir := t.TempDir()
	_, err := newAuditSink(Options{
		PCAPPath: filepath.Join(dir, "ok.pcap"),
		LogPath:  filepath.Join(dir, "missing", "a.log"),
	}, nil, time.Now())
	if err == nil {
		t.Error("expected error for bad log path")
	}
}
