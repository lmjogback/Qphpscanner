package scanner

import "context"

// ProgressEvent reports incremental scan progress to an optional callback.
type ProgressEvent struct {
	// Phase is "enumerate" (subdomain discovery) or "service" (a probe result).
	Phase string `json:"phase"`
	// Done and Total apply to the "service" phase.
	Done  int `json:"done"`
	Total int `json:"total"`
	// Host/Port identify the service a "service" event refers to.
	Host string `json:"host,omitempty"`
	Port int    `json:"port,omitempty"`
	Open bool   `json:"open"`
	HTTP bool   `json:"http"`
	// PHPVerdict is the PHP verdict string when one was produced.
	PHPVerdict string `json:"php_verdict,omitempty"`
	Version    string `json:"version,omitempty"`
	// Err holds a connection error (closed/filtered/unreachable).
	Err string `json:"err,omitempty"`
	// Message carries human-readable text for "enumerate" events.
	Message string `json:"message,omitempty"`
}

// ProgressFunc receives ProgressEvents. It may be called concurrently-safely:
// the scanner serialises calls, so a callback sees a monotonic Done counter.
type ProgressFunc func(ProgressEvent)

// SubdomainEnumerator discovers hosts for a DNS wildcard target.
type SubdomainEnumerator interface {
	Enumerate(ctx context.Context, domain string) ([]string, error)
}
