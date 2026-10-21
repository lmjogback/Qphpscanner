package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunTextToStdout(t *testing.T) {
	ts := phpServer()
	defer ts.Close()
	out := captureStdout(t, func() {
		if err := run([]string{"--quiet", ts.URL}); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "PHP SERVICE SCAN REPORT") {
		t.Fatalf("stdout text output missing header:\n%s", out)
	}
}

func TestRunReportTextToStdout(t *testing.T) {
	ts := phpServer()
	defer ts.Close()
	out := captureStdout(t, func() {
		if err := run([]string{"--quiet", "--report", "text", ts.URL}); err != nil {
			t.Fatal(err)
		}
	})
	// Both scan output and report go to stdout; the header appears at least once.
	if !strings.Contains(out, "PHP SERVICE SCAN REPORT") {
		t.Fatalf("report-to-stdout missing header")
	}
}

func TestRunOutputXMLInferred(t *testing.T) {
	ts := phpServer()
	defer ts.Close()
	dir := t.TempDir()
	out := filepath.Join(dir, "scan.xml")
	if err := run([]string{"--quiet", "--out", out, ts.URL}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(data), "<?xml") {
		t.Fatalf("expected XML (inferred from extension), got: %.20s", data)
	}
}

func TestRunBadPorts(t *testing.T) {
	if err := run([]string{"--quiet", "--ports", "nonsense", "example.com"}); err == nil {
		t.Fatal("expected error for bad port spec")
	}
}

func TestRunBadConfig(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "bad.yaml")
	_ = os.WriteFile(cfg, []byte("concurrency: notanint\n"), 0o644)
	if err := run([]string{"--quiet", "--config", cfg, "example.com"}); err == nil {
		t.Fatal("expected config load error")
	}
}
