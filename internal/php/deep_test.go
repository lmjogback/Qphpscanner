package php

import (
	"strings"
	"testing"

	"github.com/rom/qphpscanner/internal/probe"
)

func TestDeepPHPInfoAndComposer(t *testing.T) {
	phpinfo := `<!DOCTYPE html><html><head><title>phpinfo()</title></head><body>` +
		`<h1>PHP Version 8.3.1</h1>` +
		`<div>Zend Engine v4.3.0, Copyright (c) Zend Technologies with Zend OPcache v8.3.1, with Xdebug v3.3.0</div>` +
		`<table><tr><td>mysqli</td></tr><tr><td>curl</td></tr><tr><td>gd</td></tr><tr><td>openssl</td></tr></table>` +
		`</body></html>`

	in := Input{
		TargetURL: "http://h/index.php",
		Deep:      true,
		Root:      resp(200, map[string]string{"Server": "nginx/1.25"}, nil, "<html></html>"),
		Extra: map[string]*probe.Response{
			"http://h/phpinfo.php":   resp(200, nil, nil, phpinfo),
			"http://h/composer.json": resp(200, nil, nil, `{"require":{"php":">=8.1"}}`),
		},
		EasterCredits: resp(200, nil, nil, "PHP Credits — Zend Engine, the PHP Group"),
		EasterLogo:    resp(200, map[string]string{"Content-Type": "image/png"}, nil, "\x89PNG\r\n\x1a\n...."),
	}
	d := Analyze(in)
	if d == nil || !d.IsPHP {
		t.Fatalf("expected PHP: %+v", d)
	}
	if !d.PHPInfoExposed || d.PHPInfoURL == "" {
		t.Fatal("phpinfo should be marked exposed")
	}
	if d.Version != "8.3.1" || d.VersionSource != "phpinfo()" {
		t.Fatalf("version from phpinfo expected, got %q via %q", d.Version, d.VersionSource)
	}
	if d.EndOfLife {
		t.Fatal("PHP 8.3 should not be end of life")
	}
	if d.EOLDetail == "" {
		t.Fatal("expected a lifecycle detail for a supported branch")
	}
	for _, want := range []string{"mysqli", "curl", "gd", "openssl"} {
		if !hasStr(d.Extensions, want) {
			t.Fatalf("extension %q missing from %v", want, d.Extensions)
		}
	}
	if !hasEvidence(d, "diag.composer") {
		t.Fatal("composer evidence missing")
	}
	if !hasEvidence(d, "easter-egg.credits") || !hasEvidence(d, "easter-egg.logo") {
		t.Fatalf("easter-egg evidence missing: %+v", d.Evidence)
	}
	if len(d.Vulnerabilities) == 0 {
		t.Fatal("expected vulnerability leads for 8.3.1")
	}
}

func TestHHVMVariant(t *testing.T) {
	d := Analyze(Input{
		TargetURL: "http://h/",
		Deep:      true,
		Root:      resp(200, map[string]string{"X-Powered-By": "HHVM/4.128.1"}, nil, ""),
	})
	if d == nil || !d.IsPHP {
		t.Fatal("HHVM should be treated as PHP")
	}
	if d.Variant != "HHVM" {
		t.Fatalf("variant: %q", d.Variant)
	}
	if len(d.Vulnerabilities) != 0 {
		t.Fatal("HHVM version must not correlate PHP CVEs")
	}
}

func TestEOLHelpers(t *testing.T) {
	if eol, detail := evaluateEOL("PHP", "5.2.0"); !eol || detail == "" {
		t.Fatalf("ancient PHP should be EOL: %v %q", eol, detail)
	}
	if eol, _ := evaluateEOL("PHP", "8.3.1"); eol {
		t.Fatal("8.3 should be supported")
	}
	if eol, _ := evaluateEOL("HHVM", "4.0"); eol {
		t.Fatal("non-PHP variant should not be evaluated")
	}
	if eol, _ := evaluateEOL("PHP", "9.9.9"); eol {
		t.Fatal("unknown future branch should be treated as supported")
	}
}

func TestCorrelateEdgeCases(t *testing.T) {
	if CorrelateVulns("PHP", "") != nil {
		t.Fatal("empty version => nil")
	}
	if CorrelateVulns("HHVM", "4.0.0") != nil {
		t.Fatal("HHVM => nil")
	}
	if CorrelateVulns("PHP", "garbage") != nil {
		t.Fatal("unparseable => nil")
	}
}

func TestURLExtensionSignal(t *testing.T) {
	d := Analyze(Input{TargetURL: "http://h/page.phtml?x=1", Root: resp(200, nil, nil, "")})
	if !hasEvidence(d, "url.php-extension") {
		t.Fatalf("expected .phtml extension evidence: %+v", d.Evidence)
	}
}

func TestPHPErrorBodyDetection(t *testing.T) {
	body := `<b>Fatal error</b>: Uncaught Error in <b>/var/www/app.php</b> on line 5`
	d := Analyze(Input{TargetURL: "http://h/", Root: resp(200, nil, nil, body)})
	if !d.IsPHP {
		t.Fatalf("PHP fatal error body should indicate PHP, conf=%d", d.Confidence)
	}
}

func hasStr(xs []string, s string) bool {
	for _, x := range xs {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}

func hasEvidence(d *Detection, signal string) bool {
	for _, e := range d.Evidence {
		if e.Signal == signal {
			return true
		}
	}
	return false
}
