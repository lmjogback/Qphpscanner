package php

import (
	"net/http"
	"testing"

	"github.com/rom/qphpscanner/internal/probe"
)

func resp(status int, headers map[string]string, cookies []string, body string) *probe.Response {
	h := http.Header{}
	for k, v := range headers {
		h.Set(k, v)
	}
	r := &probe.Response{Status: status, Header: h, Body: []byte(body)}
	for _, name := range cookies {
		r.Cookies = append(r.Cookies, &http.Cookie{Name: name, Value: "x"})
	}
	return r
}

func TestDetectViaHeaderAndCookie(t *testing.T) {
	in := Input{
		TargetURL: "http://host/app.php",
		Deep:      true,
		Root: resp(200,
			map[string]string{"X-Powered-By": "PHP/7.4.3", "Server": "Apache/2.4.41 (Ubuntu) OpenSSL/1.1.1f"},
			[]string{"PHPSESSID"}, "<html><title>App</title></html>"),
	}
	d := Analyze(in)
	if d == nil || !d.IsPHP {
		t.Fatalf("expected PHP detection, got %+v", d)
	}
	if d.Verdict != VerdictConfirmed {
		t.Fatalf("want confirmed verdict, got %s (conf %d)", d.Verdict, d.Confidence)
	}
	if d.Version != "7.4.3" {
		t.Fatalf("want version 7.4.3, got %q", d.Version)
	}
	if !d.EndOfLife {
		t.Fatalf("PHP 7.4 should be flagged end of life")
	}
	if len(d.Vulnerabilities) == 0 {
		t.Fatalf("expected vulnerability leads for 7.4.3")
	}
	// Server modules should include the OpenSSL token.
	foundSSL := false
	for _, m := range d.Modules {
		if m == "OpenSSL/1.1.1f" {
			foundSSL = true
		}
	}
	if !foundSSL {
		t.Fatalf("expected OpenSSL module, got %v", d.Modules)
	}
}

func TestDetectFrameworkFromCookie(t *testing.T) {
	in := Input{
		TargetURL: "http://host/",
		Root:      resp(200, map[string]string{}, []string{"laravel_session"}, ""),
	}
	d := Analyze(in)
	if d == nil {
		t.Fatal("nil detection")
	}
	found := false
	for _, f := range d.Frameworks {
		if f == "Laravel" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected Laravel framework, got %v", d.Frameworks)
	}
}

func TestNonPHP(t *testing.T) {
	in := Input{
		TargetURL: "http://host/",
		Root: resp(200, map[string]string{
			"Server":       "nginx/1.25.3",
			"X-Powered-By": "ASP.NET",
		}, nil, "<html><title>IIS</title></html>"),
	}
	d := Analyze(in)
	if d == nil {
		t.Fatal("nil detection")
	}
	if d.IsPHP {
		t.Fatalf("should not detect PHP, got verdict %s conf %d", d.Verdict, d.Confidence)
	}
}

func TestVersionNotCorrelatedInDetectMode(t *testing.T) {
	in := Input{
		TargetURL: "http://host/",
		Deep:      false,
		Root:      resp(200, map[string]string{"X-Powered-By": "PHP/5.4.0"}, []string{"PHPSESSID"}, ""),
	}
	d := Analyze(in)
	if !d.IsPHP {
		t.Fatal("expected PHP")
	}
	if len(d.Vulnerabilities) != 0 {
		t.Fatalf("detect mode must not correlate vulnerabilities, got %d", len(d.Vulnerabilities))
	}
}

func TestVersionParsing(t *testing.T) {
	cases := map[string][3]int{
		"7.4.33":    {7, 4, 33},
		"8.2.0":     {8, 2, 0},
		"8.3":       {8, 3, 0},
		"7.4.33RC1": {7, 4, 33},
		"5.6.40-1":  {5, 6, 40},
	}
	for in, want := range cases {
		a, b, c, ok := parseVersion(in)
		if !ok || a != want[0] || b != want[1] || c != want[2] {
			t.Fatalf("parseVersion(%q) = %d.%d.%d ok=%v, want %v", in, a, b, c, ok, want)
		}
	}
}

func TestCorrelateCVE20244577(t *testing.T) {
	vulns := CorrelateVulns("PHP", "8.3.7")
	found := false
	for _, v := range vulns {
		if v.ID == "CVE-2024-4577" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected CVE-2024-4577 for 8.3.7, got %+v", vulns)
	}
	// 8.3.8 is fixed.
	for _, v := range CorrelateVulns("PHP", "8.3.8") {
		if v.ID == "CVE-2024-4577" {
			t.Fatalf("CVE-2024-4577 should not match fixed 8.3.8")
		}
	}
}
