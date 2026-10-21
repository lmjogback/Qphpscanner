// Package probe performs the low-level network interactions: TCP connect
// checks and bounded HTTP(S) requests whose responses become scan evidence.
package probe

import (
	"context"
	"net"
	"strconv"
	"time"
)

// PortStatus is the outcome of a TCP connect check.
type PortStatus struct {
	Open    bool
	Err     error
	Elapsed time.Duration
}

// CheckPort performs a TCP connect scan against host:port. A successful
// handshake means the port is open; a refused connection means closed; a
// timeout is reported as not-open with the underlying error preserved.
func CheckPort(ctx context.Context, host string, port int, timeout time.Duration) PortStatus {
	start := time.Now()
	d := net.Dialer{Timeout: timeout}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := d.DialContext(ctx, "tcp", addr)
	elapsed := time.Since(start)
	if err != nil {
		return PortStatus{Open: false, Err: err, Elapsed: elapsed}
	}
	_ = conn.Close()
	return PortStatus{Open: true, Elapsed: elapsed}
}
