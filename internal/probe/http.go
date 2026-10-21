package probe

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DefaultMaxBodyBytes bounds how much of a response body is read for analysis.
const DefaultMaxBodyBytes int64 = 512 * 1024

// DefaultUserAgent identifies the scanner honestly in request logs.
const DefaultUserAgent = "qphpscanner/0.1 (+https://github.com/rom/qphpscanner)"

// TLSInfo summarises the negotiated TLS parameters of a connection.
type TLSInfo struct {
	Version     string   `json:"version"`
	CipherSuite string   `json:"cipher_suite"`
	ServerName  string   `json:"server_name,omitempty"`
	PeerCN      string   `json:"peer_cn,omitempty"`
	PeerDNS     []string `json:"peer_dns,omitempty"`
}

// Response is the aggregated result of fetching a URL, including evidence
// collected across any redirect hops that were followed.
type Response struct {
	RequestURL string         `json:"request_url"`
	FinalURL   string         `json:"final_url"`
	Status     int            `json:"status"`
	Proto      string         `json:"proto"`
	Header     http.Header    `json:"-"`
	Cookies    []*http.Cookie `json:"-"`
	Body       []byte         `json:"-"`
	TLS        *TLSInfo       `json:"tls,omitempty"`
	Hops       int            `json:"hops"`
	Elapsed    time.Duration  `json:"-"`
	Err        string         `json:"error,omitempty"`
}

// BodyString returns the response body as a string.
func (r *Response) BodyString() string {
	if r == nil {
		return ""
	}
	return string(r.Body)
}

// HeaderGet is a nil-safe accessor for a single header value.
func (r *Response) HeaderGet(key string) string {
	if r == nil || r.Header == nil {
		return ""
	}
	return r.Header.Get(key)
}

// HeaderValues returns every value seen for a header across all hops.
func (r *Response) HeaderValues(key string) []string {
	if r == nil || r.Header == nil {
		return nil
	}
	return r.Header.Values(key)
}

// Fetcher issues HTTP(S) requests with a fixed policy.
type Fetcher struct {
	client       *http.Client
	userAgent    string
	maxBody      int64
	follow       bool
	maxRedirects int
}

// FetcherConfig configures a Fetcher.
type FetcherConfig struct {
	Timeout         time.Duration
	Insecure        bool
	FollowRedirects bool
	UserAgent       string
	MaxBodyBytes    int64
	MaxRedirects    int
}

// NewFetcher builds a Fetcher. The underlying transport never follows
// redirects automatically; Get walks them explicitly so headers and cookies
// from intermediate hops are preserved as evidence.
func NewFetcher(cfg FetcherConfig) *Fetcher {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = DefaultUserAgent
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = DefaultMaxBodyBytes
	}
	if cfg.MaxRedirects <= 0 {
		cfg.MaxRedirects = 10
	}

	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   cfg.Timeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.Insecure, //nolint:gosec // opt-in for self-signed scan targets
			MinVersion:         tls.VersionTLS10,
		},
		TLSHandshakeTimeout:   cfg.Timeout,
		ResponseHeaderTimeout: cfg.Timeout,
		ExpectContinueTimeout: time.Second,
		MaxIdleConns:          100,
		IdleConnTimeout:       30 * time.Second,
		DisableCompression:    false,
	}

	return &Fetcher{
		client: &http.Client{
			Transport: transport,
			Timeout:   cfg.Timeout,
			// Never auto-follow: Get does it manually.
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		userAgent:    cfg.UserAgent,
		maxBody:      cfg.MaxBodyBytes,
		follow:       cfg.FollowRedirects,
		maxRedirects: cfg.MaxRedirects,
	}
}

// Get fetches rawURL, following redirects (when enabled) up to the configured
// limit and aggregating evidence across hops.
func (f *Fetcher) Get(ctx context.Context, rawURL string) *Response {
	return f.do(ctx, http.MethodGet, rawURL)
}

func (f *Fetcher) do(ctx context.Context, method, rawURL string) *Response {
	start := time.Now()
	out := &Response{RequestURL: rawURL, Header: http.Header{}}

	cur := rawURL
	seen := map[string]bool{}
	for hop := 0; hop <= f.maxRedirects; hop++ {
		out.Hops = hop
		req, err := http.NewRequestWithContext(ctx, method, cur, nil)
		if err != nil {
			out.Err = fmt.Sprintf("build request: %v", err)
			out.Elapsed = time.Since(start)
			return out
		}
		req.Header.Set("User-Agent", f.userAgent)
		req.Header.Set("Accept", "*/*")
		req.Header.Set("Accept-Encoding", "identity")

		resp, err := f.client.Do(req)
		if err != nil {
			out.Err = cleanErr(err)
			out.Elapsed = time.Since(start)
			return out
		}

		// Merge evidence from this hop.
		mergeHeaders(out.Header, resp.Header)
		out.Cookies = append(out.Cookies, resp.Cookies()...)
		out.Status = resp.StatusCode
		out.Proto = resp.Proto
		out.FinalURL = cur
		if resp.TLS != nil && out.TLS == nil {
			out.TLS = describeTLS(resp.TLS)
		}

		location := resp.Header.Get("Location")
		isRedirect := resp.StatusCode >= 300 && resp.StatusCode < 400 && location != ""

		if !isRedirect || !f.follow {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, f.maxBody))
			_ = resp.Body.Close()
			out.Body = body
			out.Elapsed = time.Since(start)
			return out
		}

		// Redirect: drain and move on.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()

		next, err := resolveLocation(cur, location)
		if err != nil {
			out.Err = fmt.Sprintf("bad redirect target %q: %v", location, err)
			out.Elapsed = time.Since(start)
			return out
		}
		if seen[next] {
			out.Err = "redirect loop detected"
			out.Elapsed = time.Since(start)
			return out
		}
		seen[cur] = true
		cur = next
	}

	out.Err = "too many redirects"
	out.Elapsed = time.Since(start)
	return out
}

func resolveLocation(base, loc string) (string, error) {
	b, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	l, err := url.Parse(loc)
	if err != nil {
		return "", err
	}
	return b.ResolveReference(l).String(), nil
}

func mergeHeaders(dst, src http.Header) {
	for k, vs := range src {
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

func cleanErr(err error) string {
	s := err.Error()
	// Trim the noisy URL-prefixed wrapper the http client adds.
	if i := strings.Index(s, ": "); i > 0 && strings.HasPrefix(s, "Get ") {
		return s[i+2:]
	}
	return s
}

func describeTLS(cs *tls.ConnectionState) *TLSInfo {
	info := &TLSInfo{
		Version:     tlsVersionName(cs.Version),
		CipherSuite: tls.CipherSuiteName(cs.CipherSuite),
		ServerName:  cs.ServerName,
	}
	if len(cs.PeerCertificates) > 0 {
		leaf := cs.PeerCertificates[0]
		info.PeerCN = leaf.Subject.CommonName
		info.PeerDNS = leaf.DNSNames
	}
	return info
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}
