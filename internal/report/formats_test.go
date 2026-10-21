package report

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/rom/qphpscanner/internal/php"
	"github.com/rom/qphpscanner/internal/scanner"
)

func richResult() *scanner.ScanResult {
	now := time.Now()
	return &scanner.ScanResult{
		Meta: scanner.Meta{Tool: "qphpscanner", Version: "0.1.0", Mode: "deep", StartedAt: now, FinishedAt: now},
		Targets: []scanner.TargetResult{{
			Host: "h", Addresses: []string{"203.0.113.5"}, PTR: []string{"host.example"},
			Services: []scanner.ServiceResult{{
				Host: "h", Port: 443, TLS: true, Scheme: "https", URL: "https://h/", PortOpen: true,
				HTTP: &scanner.HTTPInfo{Status: 200, Server: "Apache", PoweredBy: "PHP/7.4.3"},
				PHP: &php.Detection{
					IsPHP: true, Verdict: php.VerdictConfirmed, Confidence: 95, Variant: "PHP",
					Version: "7.4.3", EndOfLife: true, EOLDetail: "PHP 7.4 end of life",
					Frameworks: []string{"WordPress"}, FrameworkVersions: map[string]string{"WordPress": "5.8.0"},
					FaviconHash: "-12345", PHPInfoExposed: true, PHPInfoURL: "https://h/phpinfo.php",
					Vulnerabilities: []php.Vulnerability{
						{ID: "CVE-2022-31626", Severity: "critical", Title: "pdo_mysql overflow", AffectedVersions: "< 7.4.30", MatchBasis: "version-correlation"},
						{ID: "CVE-2020-7066", Severity: "low", Title: "get_headers null", AffectedVersions: "< 7.4.4", MatchBasis: "version-correlation"},
					},
				},
			}, {
				Host: "h", Port: 22, Scheme: "http", URL: "http://h:22/", PortOpen: true,
				Banner: "SSH-2.0-OpenSSH_8.9",
			}},
		}},
		Summary: scanner.Summary{HostsScanned: 1, OpenPorts: 2, PHPConfirmed: 1, Vulnerabilities: 2},
	}
}

func TestSARIFOutput(t *testing.T) {
	var b bytes.Buffer
	if err := WriteOutput(&b, richResult(), "sarif"); err != nil {
		t.Fatal(err)
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(b.Bytes(), &doc); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}
	if doc["version"] != "2.1.0" {
		t.Fatalf("version: %v", doc["version"])
	}
	s := b.String()
	for _, want := range []string{"CVE-2022-31626", "php-end-of-life", "phpinfo-exposed", "security-severity"} {
		if !strings.Contains(s, want) {
			t.Fatalf("SARIF missing %q", want)
		}
	}
}

func TestCSVOutput(t *testing.T) {
	var b bytes.Buffer
	if err := WriteOutput(&b, richResult(), "csv"); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(&b).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 { // header + 2 services
		t.Fatalf("want 3 rows, got %d", len(rows))
	}
	if rows[0][0] != "host" {
		t.Fatalf("header: %v", rows[0])
	}
	joined := strings.Join(rows[1], ",")
	if !strings.Contains(joined, "CVE-2022-31626") || !strings.Contains(joined, "critical") {
		t.Fatalf("row missing vuln data: %v", rows[1])
	}
}

func TestNDJSONOutput(t *testing.T) {
	var b bytes.Buffer
	if err := WriteOutput(&b, richResult(), "ndjson"); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(b.String()), "\n")
	if len(lines) != 3 { // meta + 2 services
		t.Fatalf("want 3 NDJSON lines, got %d", len(lines))
	}
	var meta map[string]interface{}
	if err := json.Unmarshal([]byte(lines[0]), &meta); err != nil || meta["type"] != "meta" {
		t.Fatalf("first line should be meta: %v", meta)
	}
}

func TestHTMLReport(t *testing.T) {
	var b bytes.Buffer
	if err := WriteReport(&b, richResult(), "html"); err != nil {
		t.Fatal(err)
	}
	s := b.String()
	if !strings.HasPrefix(s, "<!doctype html>") {
		t.Fatal("not HTML")
	}
	for _, want := range []string{"<h1>", "CVE-2022-31626", "SSH-2.0-OpenSSH_8.9", "WordPress"} {
		if !strings.Contains(s, want) {
			t.Fatalf("HTML missing %q", want)
		}
	}
}

func TestSeverityHelpers(t *testing.T) {
	res := richResult()
	sev, rank := HighestSeverity(res)
	if sev != "critical" || rank != 4 {
		t.Fatalf("highest severity: %s/%d", sev, rank)
	}
	if !HasEOL(res) {
		t.Fatal("should detect EOL")
	}
	for _, level := range []string{"low", "medium", "high", "critical", "eol"} {
		if !FailOn(res, level) {
			t.Fatalf("FailOn(%q) should trigger", level)
		}
	}
	if FailOn(res, "bogus") {
		t.Fatal("unknown level must not trigger")
	}
	// A clean result should not trip any gate.
	clean := &scanner.ScanResult{}
	if FailOn(clean, "low") || FailOn(clean, "eol") {
		t.Fatal("clean scan must not fail gates")
	}
}

func TestDiff(t *testing.T) {
	oldRes := richResult()
	newRes := richResult()
	// Change the version and drop a vuln; add a new service.
	newRes.Targets[0].Services[0].PHP.Version = "8.3.1"
	newRes.Targets[0].Services[0].PHP.Vulnerabilities = []php.Vulnerability{
		{ID: "CVE-2024-4577", Severity: "critical"},
	}
	newRes.Targets[0].Services = append(newRes.Targets[0].Services, scanner.ServiceResult{
		Host: "h", Port: 8080, URL: "http://h:8080/", PortOpen: true,
	})

	d := Diff(oldRes, newRes)
	if d.Empty() {
		t.Fatal("expected differences")
	}
	if len(d.AddedServices) != 1 || d.AddedServices[0] != "http://h:8080/" {
		t.Fatalf("added: %v", d.AddedServices)
	}
	found := false
	for _, c := range d.Changed {
		if c.URL == "https://h/" {
			found = true
			if c.VersionChange == "" || len(c.NewVulns) == 0 || len(c.ResolvedVulns) == 0 {
				t.Fatalf("incomplete change: %+v", c)
			}
		}
	}
	if !found {
		t.Fatal("expected a change on https://h/")
	}

	var jb bytes.Buffer
	if err := WriteDiff(&jb, d, "json"); err != nil {
		t.Fatal(err)
	}
	var tb bytes.Buffer
	if err := WriteDiff(&tb, d, "text"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(tb.String(), "SCAN DIFF") {
		t.Fatal("text diff missing header")
	}

	// Identical scans → empty diff.
	same := Diff(richResult(), richResult())
	if !same.Empty() {
		t.Fatal("identical scans should diff empty")
	}
}

func TestLoadScan(t *testing.T) {
	var b bytes.Buffer
	if err := WriteOutput(&b, richResult(), "json"); err != nil {
		t.Fatal(err)
	}
	res, err := LoadScan(b.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Targets) != 1 {
		t.Fatalf("round-trip lost targets: %+v", res)
	}
	if _, err := LoadScan([]byte("not json")); err == nil {
		t.Fatal("expected parse error")
	}
}
