package config

import (
	"os"
	"path/filepath"
	"testing"
)

const sample = `# qphpscanner config
targets:
  - https://example.com
  - 10.0.0.0/30
ports: "80,443,8000-8010"
mode: deep
tls: auto
timeout: 8s
concurrency: 25
follow_redirects: true
insecure: false
security_txt: true
user_agent: "custom-agent/1.0"
output:
  format: json
  file: scan.json
report:
  format: pdf
  file: report.pdf
web:
  enabled: false
  listen: "127.0.0.1:9000"
`

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cfg.yaml")
	if err := os.WriteFile(path, []byte(sample), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(c.Targets) != 2 || c.Targets[0] != "https://example.com" {
		t.Fatalf("targets: %v", c.Targets)
	}
	if c.Ports != "80,443,8000-8010" {
		t.Fatalf("ports: %q", c.Ports)
	}
	if c.Mode != "deep" || c.TLS != "auto" || c.Timeout != "8s" {
		t.Fatalf("mode/tls/timeout: %q %q %q", c.Mode, c.TLS, c.Timeout)
	}
	if c.Concurrency != 25 {
		t.Fatalf("concurrency: %d", c.Concurrency)
	}
	if c.FollowRedirects == nil || !*c.FollowRedirects {
		t.Fatal("follow_redirects should be true")
	}
	if c.Insecure == nil || *c.Insecure {
		t.Fatal("insecure should be false")
	}
	if c.UserAgent != "custom-agent/1.0" {
		t.Fatalf("user_agent: %q", c.UserAgent)
	}
	if c.Output.Format != "json" || c.Output.File != "scan.json" {
		t.Fatalf("output: %+v", c.Output)
	}
	if c.Report.Format != "pdf" || c.Report.File != "report.pdf" {
		t.Fatalf("report: %+v", c.Report)
	}
	if c.Web.Listen != "127.0.0.1:9000" {
		t.Fatalf("web.listen: %q", c.Web.Listen)
	}
	if c.Web.Enabled == nil || *c.Web.Enabled {
		t.Fatal("web.enabled should be false")
	}
}

func TestUnmarshalRejectsTabs(t *testing.T) {
	_, err := Unmarshal([]byte("output:\n\tformat: json\n"))
	if err == nil {
		t.Fatal("expected tab indentation error")
	}
}

func TestUnmarshalInlineComment(t *testing.T) {
	m, err := Unmarshal([]byte("mode: deep # scan deeply\nurl: http://x/#frag\n"))
	if err != nil {
		t.Fatal(err)
	}
	if m["mode"] != "deep" {
		t.Fatalf("mode: %v", m["mode"])
	}
	if m["url"] != "http://x/#frag" {
		t.Fatalf("url fragment should be preserved: %v", m["url"])
	}
}
