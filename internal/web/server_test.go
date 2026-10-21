package web

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	os.Setenv("NO_PROXY", "*")
	os.Setenv("HTTP_PROXY", "")
	os.Setenv("http_proxy", "")
	os.Exit(m.Run())
}

func phpTarget() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "PHP/8.2.0")
		http.SetCookie(w, &http.Cookie{Name: "PHPSESSID", Value: "x"})
		_, _ = w.Write([]byte("<title>t</title>"))
	}))
}

func TestStaticServing(t *testing.T) {
	srv := httptest.NewServer(NewServer("x").Handler())
	defer srv.Close()
	for _, path := range []string{"/", "/app.js", "/style.css"} {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != 200 {
			t.Fatalf("GET %s => %d", path, resp.StatusCode)
		}
		resp.Body.Close()
	}
}

func TestScanStreamAndDownload(t *testing.T) {
	target := phpTarget()
	defer target.Close()

	s := NewServer("x")
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	body := `{"targets":["` + target.URL + `"],"mode":"detect","tls":"off","security_txt":false}`
	resp, err := http.Post(srv.URL+"/api/scan", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("scan status %d", resp.StatusCode)
	}

	var sawProgress, sawResult bool
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var msg streamMsg
		if err := json.Unmarshal([]byte(line), &msg); err != nil {
			t.Fatalf("bad NDJSON line %q: %v", line, err)
		}
		switch msg.Type {
		case "progress":
			sawProgress = true
		case "result":
			sawResult = true
			if msg.Result == nil || msg.Result.Summary.PHPConfirmed != 1 {
				t.Fatalf("unexpected result: %+v", msg.Result)
			}
		case "error":
			t.Fatalf("scan error: %s", msg.Error)
		}
	}
	if !sawProgress || !sawResult {
		t.Fatalf("stream incomplete: progress=%v result=%v", sawProgress, sawResult)
	}

	// Downloads operate on the stored last result.
	for _, tc := range []struct{ format, prefix string }{
		{"json", "{"},
		{"xml", "<?xml"},
		{"text", "PHP SERVICE"},
		{"rtf", `{\rtf1`},
		{"pdf", "%PDF"},
	} {
		dr, err := http.Get(srv.URL + "/api/download?format=" + tc.format)
		if err != nil {
			t.Fatal(err)
		}
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(dr.Body)
		dr.Body.Close()
		if dr.StatusCode != 200 {
			t.Fatalf("download %s => %d", tc.format, dr.StatusCode)
		}
		if !strings.Contains(buf.String()[:min(40, buf.Len())], tc.prefix) &&
			!strings.HasPrefix(strings.TrimSpace(buf.String()), tc.prefix) {
			t.Fatalf("download %s missing prefix %q", tc.format, tc.prefix)
		}
	}
}

func TestScanBadRequests(t *testing.T) {
	s := NewServer("x")
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	// Invalid JSON.
	resp, _ := http.Post(srv.URL+"/api/scan", "application/json", strings.NewReader("{bad"))
	if resp.StatusCode != 400 {
		t.Fatalf("bad json => %d", resp.StatusCode)
	}
	resp.Body.Close()

	// No targets.
	resp, _ = http.Post(srv.URL+"/api/scan", "application/json", strings.NewReader(`{"targets":[]}`))
	if resp.StatusCode != 400 {
		t.Fatalf("no targets => %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Bad ports.
	resp, _ = http.Post(srv.URL+"/api/scan", "application/json", strings.NewReader(`{"targets":["x"],"ports":"nope"}`))
	if resp.StatusCode != 400 {
		t.Fatalf("bad ports => %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Download before any scan.
	dr, _ := http.Get(srv.URL + "/api/download?format=json")
	if dr.StatusCode != 400 {
		t.Fatalf("download before scan => %d", dr.StatusCode)
	}
	dr.Body.Close()
}

func TestHelpers(t *testing.T) {
	if got := splitTargets("a, b\nc\td"); len(got) != 4 {
		t.Fatalf("splitTargets: %v", got)
	}
	if got := cleanTargets([]string{" a ", "", "b"}); len(got) != 2 {
		t.Fatalf("cleanTargets: %v", got)
	}
	if normMode("deep") != "deep" || normMode("x") != "detect" {
		t.Fatal("normMode")
	}
	if normTLS("on") != "on" || normTLS("off") != "off" || normTLS("x") != "auto" {
		t.Fatal("normTLS")
	}
	if _, err := parsePortsField("80,443"); err != nil {
		t.Fatalf("parsePortsField: %v", err)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
