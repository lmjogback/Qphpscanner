package probe

import (
	"context"
	"net"
	"strconv"
	"strings"
	"time"
)

// GrabBanner opens a TCP connection and reads a short service banner, for open
// ports that did not speak HTTP. It first waits for a server-initiated banner
// (SSH/FTP/SMTP announce themselves); if none arrives it sends a CRLF nudge and
// reads once more. The returned string is sanitised and length-bounded.
func GrabBanner(ctx context.Context, host string, port int, timeout time.Duration) string {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return ""
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))
	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	if n == 0 {
		// Reset the deadline before writing: a prior read timeout leaves the
		// deadline in the past, which would also fail the nudge write.
		_ = conn.SetDeadline(time.Now().Add(timeout))
		_, _ = conn.Write([]byte("\r\n"))
		n, _ = conn.Read(buf)
	}
	return sanitizeBanner(buf[:n])
}

func sanitizeBanner(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		switch {
		case c == '\n' || c == '\r' || c == '\t':
			sb.WriteByte(' ')
		case c >= 0x20 && c < 0x7f:
			sb.WriteByte(c)
		default:
			// drop non-printable bytes
		}
	}
	out := strings.TrimSpace(strings.Join(strings.Fields(sb.String()), " "))
	if len(out) > 200 {
		out = out[:200] + "…"
	}
	return out
}
