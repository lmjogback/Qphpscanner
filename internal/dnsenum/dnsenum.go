// Package dnsenum discovers hostnames and subdomains for a domain, so a
// "*.example.com" target can be expanded into concrete hosts to scan.
//
// The primary source is Certificate Transparency (crt.sh), which returns the
// names that appear in issued certificates for the domain. Optionally the
// discovered names can be filtered to those that currently resolve in DNS.
//
// This performs only read-only lookups against public data; it does not probe
// the target hosts.
package dnsenum

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"
)

// DefaultCTLogURL is the Certificate Transparency search endpoint.
const DefaultCTLogURL = "https://crt.sh/"

// DefaultMaxHosts bounds how many discovered hosts are returned.
const DefaultMaxHosts = 2048

// Resolver is the subset of *net.Resolver used for optional verification.
type Resolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
}

// Enumerator discovers subdomains for a domain.
type Enumerator struct {
	Client   *http.Client
	CTLogURL string
	Resolver Resolver
	Timeout  time.Duration
	// Verify, when true, keeps only names that currently resolve.
	Verify   bool
	MaxHosts int
	// VerifyConcurrency bounds parallel DNS lookups during verification.
	VerifyConcurrency int
}

// New returns an Enumerator with sensible defaults.
func New() *Enumerator {
	return &Enumerator{
		Client:            &http.Client{Timeout: 20 * time.Second},
		CTLogURL:          DefaultCTLogURL,
		Resolver:          net.DefaultResolver,
		Timeout:           20 * time.Second,
		Verify:            false,
		MaxHosts:          DefaultMaxHosts,
		VerifyConcurrency: 16,
	}
}

type ctEntry struct {
	NameValue  string `json:"name_value"`
	CommonName string `json:"common_name"`
}

// Enumerate returns the sorted, de-duplicated hostnames discovered for domain.
func (e *Enumerator) Enumerate(ctx context.Context, domain string) ([]string, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return nil, fmt.Errorf("empty domain")
	}
	if e.CTLogURL == "" {
		e.CTLogURL = DefaultCTLogURL
	}
	if e.MaxHosts <= 0 {
		e.MaxHosts = DefaultMaxHosts
	}
	client := e.Client
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}

	names, err := e.queryCT(ctx, client, domain)
	if err != nil {
		return nil, err
	}

	hosts := e.normalise(names, domain)
	if e.Verify && e.Resolver != nil {
		hosts = e.filterResolvable(ctx, hosts)
	}
	sort.Strings(hosts)
	if len(hosts) > e.MaxHosts {
		hosts = hosts[:e.MaxHosts]
	}
	return hosts, nil
}

func (e *Enumerator) queryCT(ctx context.Context, client *http.Client, domain string) ([]string, error) {
	url := strings.TrimRight(e.CTLogURL, "/") + "/?q=%25." + domain + "&output=json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "qphpscanner-dnsenum/0.1")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("certificate transparency lookup failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("certificate transparency lookup returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, err
	}

	var entries []ctEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("parse certificate transparency response: %w", err)
	}

	var names []string
	for _, en := range entries {
		if en.CommonName != "" {
			names = append(names, en.CommonName)
		}
		for _, n := range strings.Split(en.NameValue, "\n") {
			names = append(names, n)
		}
	}
	return names, nil
}

func (e *Enumerator) normalise(names []string, domain string) []string {
	suffix := "." + domain
	seen := map[string]bool{}
	var out []string
	for _, n := range names {
		n = strings.ToLower(strings.TrimSpace(n))
		n = strings.TrimPrefix(n, "*.")
		if n == "" || strings.ContainsAny(n, " \t*") {
			continue
		}
		if n != domain && !strings.HasSuffix(n, suffix) {
			continue
		}
		if seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	return out
}

func (e *Enumerator) filterResolvable(ctx context.Context, hosts []string) []string {
	conc := e.VerifyConcurrency
	if conc <= 0 {
		conc = 16
	}
	type res struct {
		host string
		ok   bool
	}
	in := make(chan string)
	out := make(chan res)
	done := make(chan struct{})

	for i := 0; i < conc; i++ {
		go func() {
			for h := range in {
				lctx := ctx
				if e.Timeout > 0 {
					var cancel context.CancelFunc
					lctx, cancel = context.WithTimeout(ctx, e.Timeout)
					_, err := e.Resolver.LookupHost(lctx, h)
					cancel()
					out <- res{h, err == nil}
					continue
				}
				_, err := e.Resolver.LookupHost(lctx, h)
				out <- res{h, err == nil}
			}
		}()
	}

	go func() {
		for _, h := range hosts {
			in <- h
		}
		close(in)
	}()

	var kept []string
	go func() {
		for i := 0; i < len(hosts); i++ {
			r := <-out
			if r.ok {
				kept = append(kept, r.host)
			}
		}
		close(done)
	}()
	<-done
	return kept
}
