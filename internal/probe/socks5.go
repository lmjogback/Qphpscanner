package probe

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

// socks5Dialer is a minimal RFC 1928 SOCKS5 client (with optional RFC 1929
// username/password auth). It resolves target names at the proxy (socks5h
// semantics). It exists to keep the tool dependency-free.
type socks5Dialer struct {
	proxyAddr string
	user      string
	pass      string
	base      *net.Dialer
}

func (d *socks5Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("socks5: unsupported network %q", network)
	}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("socks5: invalid port %q", portStr)
	}

	conn, err := d.base.DialContext(ctx, "tcp", d.proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("socks5: dial proxy: %w", err)
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}

	if err := d.negotiate(conn, host, port); err != nil {
		conn.Close()
		return nil, err
	}
	// Clear any handshake deadline so it doesn't bleed into use.
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

func (d *socks5Dialer) negotiate(conn net.Conn, host string, port int) error {
	// Greeting.
	if d.user != "" || d.pass != "" {
		if _, err := conn.Write([]byte{0x05, 0x02, 0x00, 0x02}); err != nil {
			return err
		}
	} else {
		if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
			return err
		}
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return err
	}
	if reply[0] != 0x05 {
		return errors.New("socks5: bad version in method selection")
	}
	switch reply[1] {
	case 0x00:
		// no auth
	case 0x02:
		if err := d.authUserPass(conn); err != nil {
			return err
		}
	case 0xff:
		return errors.New("socks5: no acceptable auth methods")
	default:
		return fmt.Errorf("socks5: unsupported auth method 0x%02x", reply[1])
	}

	// CONNECT request with domain address type (proxy resolves).
	if len(host) > 255 {
		return errors.New("socks5: hostname too long")
	}
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, host...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		return err
	}

	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		return err
	}
	if head[0] != 0x05 {
		return errors.New("socks5: bad version in connect reply")
	}
	if head[1] != 0x00 {
		return fmt.Errorf("socks5: connect failed (reply code 0x%02x)", head[1])
	}
	// Consume the bound address so the stream is positioned for data.
	var alen int
	switch head[3] {
	case 0x01:
		alen = 4
	case 0x04:
		alen = 16
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(conn, l); err != nil {
			return err
		}
		alen = int(l[0])
	default:
		return fmt.Errorf("socks5: unknown address type 0x%02x", head[3])
	}
	if _, err := io.ReadFull(conn, make([]byte, alen+2)); err != nil {
		return err
	}
	return nil
}

func (d *socks5Dialer) authUserPass(conn net.Conn) error {
	if len(d.user) > 255 || len(d.pass) > 255 {
		return errors.New("socks5: credential too long")
	}
	buf := []byte{0x01, byte(len(d.user))}
	buf = append(buf, d.user...)
	buf = append(buf, byte(len(d.pass)))
	buf = append(buf, d.pass...)
	if _, err := conn.Write(buf); err != nil {
		return err
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return err
	}
	if resp[1] != 0x00 {
		return errors.New("socks5: username/password authentication failed")
	}
	return nil
}
