package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func phpTestServer() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/security.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("Contact: mailto:security@example.test\nExpires: 2099-01-01T00:00:00Z\n"))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "PHP/8.2.4")
		w.Header().Set("Server", "Apache/2.4.57 (Debian)")
		http.SetCookie(w, &http.Cookie{Name: "PHPSESSID", Value: "deadbeef"})
		_, _ = w.Write([]byte(`<html><head><title>My Site</title>` +
			`<meta name="generator" content="WordPress 6.4.2"></head>` +
			`<body><link href="/wp-content/themes/x/style.css"></body></html>`))
	})
	return httptest.NewServer(mux)
}

func TestScanDetectsPHP(t *testing.T) {
	t.Setenv("HTTP_PROXY", "")
	t.Setenv("http_proxy", "")
	t.Setenv("NO_PROXY", "*")

	ts := phpTestServer()
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	res, err := Scan(ctx, []string{ts.URL}, Options{
		Mode:        ModeDeep,
		TLSMode:     TLSOff,
		SecurityTxt: true,
		Timeout:     5 * time.Second,
		Concurrency: 10,
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.Targets) != 1 {
		t.Fatalf("want 1 target, got %d", len(res.Targets))
	}
	svc := res.Targets[0].Services[0]
	if svc.PHP == nil || !svc.PHP.IsPHP {
		t.Fatalf("expected PHP detection, got %+v", svc.PHP)
	}
	if svc.PHP.Version != "8.2.4" {
		t.Fatalf("want version 8.2.4, got %q", svc.PHP.Version)
	}
	foundWP := false
	for _, f := range svc.PHP.Frameworks {
		if f == "WordPress" {
			foundWP = true
		}
	}
	if !foundWP {
		t.Fatalf("expected WordPress framework, got %v", svc.PHP.Frameworks)
	}
	if svc.SecurityTxt == nil || !svc.SecurityTxt.Present {
		t.Fatal("expected security.txt to be found")
	}
	if res.Summary.PHPConfirmed != 1 {
		t.Fatalf("summary PHPConfirmed = %d, want 1", res.Summary.PHPConfirmed)
	}
}

func TestScanClosedPort(t *testing.T) {
	t.Setenv("NO_PROXY", "*")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 127.0.0.1 with an unlikely-open port and a short timeout.
	res, err := Scan(ctx, []string{"127.0.0.1"}, Options{
		Mode:    ModeDetect,
		Ports:   []int{1},
		Timeout: 500 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	// Closed ports are excluded by default, so no targets should appear.
	if len(res.Targets) != 0 {
		t.Fatalf("expected no open services, got %d", len(res.Targets))
	}
	if res.Summary.ServicesProbed != 1 {
		t.Fatalf("want 1 probed service, got %d", res.Summary.ServicesProbed)
	}
}
