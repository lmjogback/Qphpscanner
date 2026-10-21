package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/rom/qphpscanner/internal/scanner"
	"github.com/rom/qphpscanner/internal/securitytxt"
)

func TestTextNoTargets(t *testing.T) {
	res := &scanner.ScanResult{Meta: scanner.Meta{Tool: "qphpscanner", StartedAt: time.Now(), FinishedAt: time.Now()}}
	var b bytes.Buffer
	if err := WriteOutput(&b, res, "text"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "No open services") {
		t.Fatalf("expected empty notice:\n%s", b.String())
	}
}

func TestClosedServiceAndSecurityTxt(t *testing.T) {
	res := &scanner.ScanResult{
		Meta: scanner.Meta{Tool: "qphpscanner", StartedAt: time.Now(), FinishedAt: time.Now()},
		Targets: []scanner.TargetResult{{
			Host: "h",
			Services: []scanner.ServiceResult{
				{Host: "h", Port: 81, Scheme: "http", URL: "http://h:81/", PortOpen: false, Error: "connection refused"},
				{
					Host: "h", Port: 80, Scheme: "http", URL: "http://h:80/", PortOpen: true,
					HTTP: &scanner.HTTPInfo{Status: 200},
					SecurityTxt: &securitytxt.SecurityTxt{
						Present: true, URL: "http://h/.well-known/security.txt", Signed: true,
						Contact: []string{"mailto:x@h"}, Expires: "2000-01-01T00:00:00Z", Expired: true,
						Policy: []string{"http://h/policy"},
					},
				},
				{Host: "h", Port: 8080, Scheme: "http", URL: "http://h:8080/", PortOpen: true, Error: "x"},
			},
		}},
	}
	var b bytes.Buffer
	if err := WriteReport(&b, res, "text"); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{"closed/filtered", "security.txt", "EXPIRED", "no HTTP response"} {
		if !strings.Contains(out, want) {
			t.Fatalf("report missing %q:\n%s", want, out)
		}
	}
}

func TestWrapIndent(t *testing.T) {
	long := strings.Repeat("word ", 40)
	got := wrapIndent(long, "  - ", 40)
	for _, line := range strings.Split(got, "\n") {
		if len(line) > 40 {
			t.Fatalf("line exceeds width: %q", line)
		}
	}
	if !strings.HasPrefix(got, "  - ") {
		t.Fatal("first line should carry prefix")
	}
}

func TestRTFEscape(t *testing.T) {
	s := rtfEscape(`a{b}c\d` + "\n" + "café")
	for _, bad := range []string{"{b}", `\d` + "x"} {
		_ = bad
	}
	if !strings.Contains(s, `\{`) || !strings.Contains(s, `\}`) || !strings.Contains(s, `\\`) {
		t.Fatalf("rtf escaping wrong: %s", s)
	}
	if !strings.Contains(s, `\u`) {
		t.Fatalf("non-ascii should be \\u encoded: %s", s)
	}
}

func TestPDFMultiPage(t *testing.T) {
	// Build a result with enough content to force multiple PDF pages.
	svcs := make([]scanner.ServiceResult, 0, 60)
	for i := 0; i < 60; i++ {
		svcs = append(svcs, scanner.ServiceResult{
			Host: "h", Port: 80 + i, Scheme: "http", URL: "http://h/", PortOpen: true,
			HTTP: &scanner.HTTPInfo{Status: 200, Server: "Apache"},
		})
	}
	res := &scanner.ScanResult{
		Meta:    scanner.Meta{Tool: "qphpscanner", StartedAt: time.Now(), FinishedAt: time.Now()},
		Targets: []scanner.TargetResult{{Host: "h", Services: svcs}},
	}
	var b bytes.Buffer
	if err := WriteReport(&b, res, "pdf"); err != nil {
		t.Fatal(err)
	}
	if bytes.Count(b.Bytes(), []byte("/Type /Page ")) < 2 {
		t.Fatal("expected multiple PDF pages")
	}
}

func TestPDFEscapeFallback(t *testing.T) {
	if pdfEscape("a(b)c\\d") != `a\(b\)c\\d` {
		t.Fatalf("pdf escape: %s", pdfEscape("a(b)c\\d"))
	}
	if asciiFallback('•') != '*' || asciiFallback('—') != '-' || asciiFallback('界') != '?' {
		t.Fatal("asciiFallback")
	}
}
