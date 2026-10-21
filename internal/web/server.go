// Package web provides the browser-based GUI: a small single-page frontend
// plus a JSON API that drives the same scanner the CLI uses.
package web

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/rom/qphpscanner/internal/portspec"
	"github.com/rom/qphpscanner/internal/report"
	"github.com/rom/qphpscanner/internal/scanner"
)

//go:embed assets
var assets embed.FS

// Server hosts the GUI and API. The most recent scan result is retained in
// memory so report downloads do not require re-scanning.
type Server struct {
	addr       string
	maxTargets int

	mu   sync.Mutex
	last *scanner.ScanResult
}

// NewServer creates a Server bound to addr (e.g. "127.0.0.1:8088").
func NewServer(addr string) *Server {
	return &Server{addr: addr, maxTargets: 4096}
}

// Handler returns the HTTP handler (useful for tests).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	sub, _ := fs.Sub(assets, "assets")
	fileServer := http.FileServer(http.FS(sub))

	mux.HandleFunc("POST /api/scan", s.handleScan)
	mux.HandleFunc("GET /api/download", s.handleDownload)
	mux.Handle("/", fileServer)
	return logMiddleware(mux)
}

// ListenAndServe starts the server.
func (s *Server) ListenAndServe() error {
	srv := &http.Server{
		Addr:              s.addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	return srv.ListenAndServe()
}

type scanRequest struct {
	Targets        []string `json:"targets"`
	TargetsText    string   `json:"targets_text"`
	Ports          string   `json:"ports"`
	Mode           string   `json:"mode"`
	TLS            string   `json:"tls"`
	TimeoutSeconds int      `json:"timeout_seconds"`
	Concurrency    int      `json:"concurrency"`
	Follow         bool     `json:"follow_redirects"`
	Insecure       bool     `json:"insecure"`
	SecurityTxt    bool     `json:"security_txt"`
	IncludeClosed  bool     `json:"include_closed"`
	NoDNSEnum      bool     `json:"no_dns_enum"`
}

// streamMsg is one line of the NDJSON response stream.
type streamMsg struct {
	Type   string                 `json:"type"` // "progress" | "result" | "error"
	Event  *scanner.ProgressEvent `json:"event,omitempty"`
	Result *scanner.ScanResult    `json:"result,omitempty"`
	Error  string                 `json:"error,omitempty"`
}

// buildOptions turns a request into scanner options, or returns a user error.
func (s *Server) buildOptions(req scanRequest) (scanner.Options, []string, error) {
	targets := append([]string{}, req.Targets...)
	targets = append(targets, splitTargets(req.TargetsText)...)
	targets = cleanTargets(targets)
	if len(targets) == 0 {
		return scanner.Options{}, nil, fmt.Errorf("no targets supplied")
	}
	opts := scanner.Options{
		Mode:            normMode(req.Mode),
		TLSMode:         normTLS(req.TLS),
		Follow:          req.Follow,
		Insecure:        req.Insecure,
		SecurityTxt:     req.SecurityTxt,
		IncludeClosed:   req.IncludeClosed,
		Concurrency:     req.Concurrency,
		DisableDNSEnum:  req.NoDNSEnum,
		MaxHostsPerSpec: s.maxTargets,
	}
	if req.Ports != "" {
		ports, err := parsePortsField(req.Ports)
		if err != nil {
			return scanner.Options{}, nil, err
		}
		opts.Ports = ports
	}
	if req.TimeoutSeconds > 0 {
		opts.Timeout = time.Duration(req.TimeoutSeconds) * time.Second
	}
	return opts, targets, nil
}

// handleScan runs a scan and streams NDJSON: a line per progress event
// followed by a final {"type":"result", ...} line (or {"type":"error"}).
func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	var req scanRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, streamMsg{Type: "error", Error: "invalid request: " + err.Error()})
		return
	}
	opts, targets, err := s.buildOptions(req)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, streamMsg{Type: "error", Error: err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	flusher, _ := w.(http.Flusher)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	var writeMu sync.Mutex
	send := func(m streamMsg) {
		writeMu.Lock()
		_ = enc.Encode(m)
		if flusher != nil {
			flusher.Flush()
		}
		writeMu.Unlock()
	}

	opts.OnProgress = func(ev scanner.ProgressEvent) {
		e := ev
		send(streamMsg{Type: "progress", Event: &e})
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()

	result, err := scanner.Scan(ctx, targets, opts)
	if err != nil {
		send(streamMsg{Type: "error", Error: err.Error()})
		return
	}

	s.mu.Lock()
	s.last = result
	s.mu.Unlock()

	send(streamMsg{Type: "result", Result: result})
}

func (s *Server) handleDownload(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	last := s.last
	s.mu.Unlock()
	if last == nil {
		http.Error(w, "no scan has been run yet", http.StatusBadRequest)
		return
	}

	format := strings.ToLower(r.URL.Query().Get("format"))
	var (
		ctype string
		fname string
		isOut bool
	)
	switch format {
	case "json":
		ctype, fname, isOut = "application/json", "qphpscan.json", true
	case "xml":
		ctype, fname, isOut = "application/xml", "qphpscan.xml", true
	case "text", "txt":
		ctype, fname, isOut = "text/plain; charset=utf-8", "qphpscan.txt", true
	case "rtf":
		ctype, fname = "application/rtf", "qphpscan-report.rtf"
	case "pdf":
		ctype, fname = "application/pdf", "qphpscan-report.pdf"
	default:
		http.Error(w, "unknown format (want json, xml, text, rtf or pdf)", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", fname))

	var err error
	if isOut {
		err = report.WriteOutput(w, last, format)
	} else {
		err = report.WriteReport(w, last, format)
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func logMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
	})
}

func splitTargets(s string) []string {
	if s == "" {
		return nil
	}
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r == '\n' || r == '\r' || r == ',' || r == ' ' || r == '\t'
	})
	return fields
}

func cleanTargets(in []string) []string {
	var out []string
	for _, t := range in {
		if t = strings.TrimSpace(t); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func normMode(m string) string {
	if strings.ToLower(m) == scanner.ModeDeep {
		return scanner.ModeDeep
	}
	return scanner.ModeDetect
}

func parsePortsField(s string) ([]int, error) {
	return portspec.Parse(s)
}

func normTLS(t string) string {
	switch strings.ToLower(t) {
	case scanner.TLSOn:
		return scanner.TLSOn
	case scanner.TLSOff:
		return scanner.TLSOff
	default:
		return scanner.TLSAuto
	}
}
