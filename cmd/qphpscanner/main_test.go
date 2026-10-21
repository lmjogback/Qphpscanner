package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	os.Setenv("NO_PROXY", "*")
	os.Setenv("HTTP_PROXY", "")
	os.Setenv("http_proxy", "")
	os.Exit(m.Run())
}

func phpServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "PHP/8.2.0")
		http.SetCookie(w, &http.Cookie{Name: "PHPSESSID", Value: "x"})
		_, _ = w.Write([]byte("<title>t</title>"))
	}))
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	done := make(chan string)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		done <- buf.String()
	}()
	fn()
	_ = w.Close()
	os.Stdout = old
	return <-done
}

func TestRunVersion(t *testing.T) {
	out := captureStdout(t, func() {
		if err := run([]string{"--version"}); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "qphpscanner") {
		t.Fatalf("version output: %q", out)
	}
}

func TestRunHelp(t *testing.T) {
	if err := run([]string{"--help"}); err != nil {
		t.Fatalf("--help should not error, got %v", err)
	}
}

func TestRunNoTargets(t *testing.T) {
	if err := run([]string{"--quiet"}); err == nil {
		t.Fatal("expected error when no targets given")
	}
}

func TestRunBadTarget(t *testing.T) {
	if err := run([]string{"--quiet", "10.0.0.0/8", "--max-hosts", "16"}); err == nil {
		t.Fatal("expected error for oversized CIDR")
	}
}

func TestRunScanJSON(t *testing.T) {
	ts := phpServer()
	defer ts.Close()
	dir := t.TempDir()
	out := filepath.Join(dir, "scan.json")
	if err := run([]string{"--quiet", "--format", "json", "--out", out, ts.URL}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Summary struct {
			PHPConfirmed int `json:"php_confirmed"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if v.Summary.PHPConfirmed != 1 {
		t.Fatalf("expected 1 PHP service, got %d", v.Summary.PHPConfirmed)
	}
}

func TestRunReportPDFInferred(t *testing.T) {
	ts := phpServer()
	defer ts.Close()
	dir := t.TempDir()
	out := filepath.Join(dir, "report.pdf")
	if err := run([]string{"--quiet", "--report-out", out, ts.URL}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(data, []byte("%PDF")) {
		t.Fatal("report is not a PDF")
	}
}

func TestRunReportRTFToStdoutErrors(t *testing.T) {
	ts := phpServer()
	defer ts.Close()
	// rtf without a file must error.
	err := run([]string{"--quiet", "--report", "rtf", ts.URL})
	if err == nil {
		t.Fatal("expected error: rtf report needs a file")
	}
}

func TestRunConfig(t *testing.T) {
	ts := phpServer()
	defer ts.Close()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "c.yaml")
	content := "targets:\n  - " + ts.URL + "\nmode: detect\ntls: \"off\"\nsecurity_txt: false\n"
	if err := os.WriteFile(cfg, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "o.json")
	if err := run([]string{"--quiet", "--config", cfg, "--format", "json", "--out", out}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatalf("output not written: %v", err)
	}
}

func TestParseArgsInterspersed(t *testing.T) {
	fs := newFlagSet()
	f := bindFlags(fs)
	pos, err := parseArgs(fs, []string{"--mode", "deep", "host1", "--verbose", "host2", "--ports", "80"})
	if err != nil {
		t.Fatal(err)
	}
	if !f.verbose || f.mode != "deep" || f.ports != "80" {
		t.Fatalf("flags not parsed across positionals: %+v", f)
	}
	if len(pos) != 2 || pos[0] != "host1" || pos[1] != "host2" {
		t.Fatalf("positionals: %v", pos)
	}
}

func TestFormatHelpers(t *testing.T) {
	if ext("a/b.pdf") != "pdf" || ext("noext") != "" {
		t.Fatal("ext")
	}
	if inferReportFormat("x.pdf") != "pdf" || inferReportFormat("x.rtf") != "rtf" || inferReportFormat("x.txt") != "text" {
		t.Fatal("inferReportFormat")
	}
	if inferOutputFormat("x.json") != "json" || inferOutputFormat("x.xml") != "xml" || inferOutputFormat("x.dat") != "" {
		t.Fatal("inferOutputFormat")
	}
	if !boolVal(ptr(true), false) || boolVal(nil, true) != true {
		t.Fatal("boolVal")
	}
	if validateMode("deep") != nil || validateMode("bad") == nil {
		t.Fatal("validateMode")
	}
	if validateTLS("auto") != nil || validateTLS("bad") == nil {
		t.Fatal("validateTLS")
	}
	if displayAddr(":8088") != "localhost:8088" || displayAddr("1.2.3.4:80") != "1.2.3.4:80" {
		t.Fatal("displayAddr")
	}
}

func ptr(b bool) *bool { return &b }
