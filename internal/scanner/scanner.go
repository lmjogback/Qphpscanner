package scanner

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rom/qphpscanner/internal/dnsenum"
	"github.com/rom/qphpscanner/internal/php"
	"github.com/rom/qphpscanner/internal/portspec"
	"github.com/rom/qphpscanner/internal/probe"
	"github.com/rom/qphpscanner/internal/securitytxt"
	"github.com/rom/qphpscanner/internal/target"
	"github.com/rom/qphpscanner/internal/version"
)

// Mode selects how deep the analysis goes.
const (
	ModeDetect = "detect" // only decide whether the service is PHP
	ModeDeep   = "deep"   // also fingerprint version/extensions/modules and vulns
)

// TLS modes.
const (
	TLSAuto = "auto"
	TLSOn   = "on"
	TLSOff  = "off"
)

// Options configures a scan.
type Options struct {
	Mode            string
	TLSMode         string
	Ports           []int
	Timeout         time.Duration
	Concurrency     int
	Follow          bool
	Insecure        bool
	MaxBodyBytes    int64
	UserAgent       string
	SecurityTxt     bool
	IncludeClosed   bool
	MaxHostsPerSpec int

	// OnProgress, when set, receives incremental progress events.
	OnProgress ProgressFunc
	// DisableDNSEnum turns off "*.domain" subdomain enumeration.
	DisableDNSEnum bool
	// Enumerator overrides the default Certificate Transparency enumerator
	// (primarily for testing).
	Enumerator SubdomainEnumerator
	// VerifySubdomains keeps only discovered subdomains that resolve in DNS.
	VerifySubdomains bool
}

// withDefaults fills unset options with sensible values.
func (o Options) withDefaults() Options {
	if o.Mode == "" {
		o.Mode = ModeDetect
	}
	if o.TLSMode == "" {
		o.TLSMode = TLSAuto
	}
	if len(o.Ports) == 0 {
		o.Ports = portspec.DefaultWebPorts
	}
	if o.Timeout <= 0 {
		o.Timeout = 10 * time.Second
	}
	if o.Concurrency <= 0 {
		o.Concurrency = 50
	}
	if o.MaxBodyBytes <= 0 {
		o.MaxBodyBytes = probe.DefaultMaxBodyBytes
	}
	if o.UserAgent == "" {
		o.UserAgent = probe.DefaultUserAgent
	}
	return o
}

var reTitle = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

type job struct {
	ep   target.Endpoint
	port int
}

type schemeChoice struct {
	scheme string
	tls    bool
}

// Scan runs the full pipeline over the given target specs.
func Scan(ctx context.Context, specs []string, opts Options) (*ScanResult, error) {
	opts = opts.withDefaults()
	start := time.Now()

	endpoints, err := expandTargets(ctx, specs, opts)
	if err != nil {
		return nil, err
	}

	// Build jobs and record host order + inputs.
	var jobs []job
	hostOrder := []string{}
	hostSeen := map[string]bool{}
	hostInputs := map[string]map[string]bool{}
	for _, ep := range endpoints {
		if !hostSeen[ep.Host] {
			hostSeen[ep.Host] = true
			hostOrder = append(hostOrder, ep.Host)
			hostInputs[ep.Host] = map[string]bool{}
		}
		hostInputs[ep.Host][ep.Input] = true

		ports := opts.Ports
		if len(ep.Ports) > 0 {
			ports = ep.Ports
		}
		for _, p := range ports {
			jobs = append(jobs, job{ep: ep, port: p})
		}
	}

	fetcher := probe.NewFetcher(probe.FetcherConfig{
		Timeout:         opts.Timeout,
		Insecure:        opts.Insecure,
		FollowRedirects: opts.Follow,
		UserAgent:       opts.UserAgent,
		MaxBodyBytes:    opts.MaxBodyBytes,
	})

	// Worker pool.
	results := make([]ServiceResult, len(jobs))
	total := len(jobs)
	sem := make(chan struct{}, opts.Concurrency)
	var wg sync.WaitGroup
	var progMu sync.Mutex
	doneCount := 0
	for i := range jobs {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int) {
			defer wg.Done()
			defer func() { <-sem }()
			res := scanService(ctx, fetcher, jobs[idx], opts)
			results[idx] = res
			if opts.OnProgress != nil {
				progMu.Lock()
				doneCount++
				opts.OnProgress(serviceEvent(res, doneCount, total))
				progMu.Unlock()
			}
		}(i)
	}
	wg.Wait()

	// Group by host preserving order; drop closed ports unless requested.
	byHost := map[string][]ServiceResult{}
	for _, r := range results {
		if !r.PortOpen && !opts.IncludeClosed {
			continue
		}
		byHost[r.Host] = append(byHost[r.Host], r)
	}

	out := &ScanResult{
		Meta: Meta{
			Tool:       version.Name,
			Version:    version.Version,
			Mode:       opts.Mode,
			StartedAt:  start,
			FinishedAt: time.Now(),
			DurationMS: time.Since(start).Milliseconds(),
			Ports:      opts.Ports,
		},
	}
	for _, h := range hostOrder {
		svcs := byHost[h]
		if len(svcs) == 0 {
			continue
		}
		inputs := make([]string, 0, len(hostInputs[h]))
		for in := range hostInputs[h] {
			inputs = append(inputs, in)
		}
		out.Targets = append(out.Targets, TargetResult{Host: h, Inputs: inputs, Services: svcs})
	}

	out.Summary = summarise(results, hostOrder, opts)
	return out, nil
}

// expandTargets turns raw specs into endpoints, resolving DNS wildcards
// ("*.example.com") via subdomain enumeration. Enumeration failures are
// reported through progress and skipped rather than aborting the whole scan.
func expandTargets(ctx context.Context, specs []string, opts Options) ([]target.Endpoint, error) {
	var eps []target.Endpoint
	for _, spec := range specs {
		if domain, ok := target.IsDNSWildcard(spec); ok {
			if opts.DisableDNSEnum {
				emitEnum(opts, "skipping DNS wildcard "+spec+" (enumeration disabled)")
				continue
			}
			enum := opts.Enumerator
			if enum == nil {
				d := dnsenum.New()
				d.Verify = opts.VerifySubdomains
				if opts.MaxHostsPerSpec > 0 {
					d.MaxHosts = opts.MaxHostsPerSpec
				}
				enum = d
			}
			emitEnum(opts, "enumerating subdomains for "+domain+" via certificate transparency…")
			hosts, err := enum.Enumerate(ctx, domain)
			if err != nil {
				emitEnum(opts, "subdomain enumeration for "+domain+" failed: "+err.Error())
				continue
			}
			emitEnum(opts, fmt.Sprintf("found %d host(s) for %s", len(hosts), domain))
			for _, h := range hosts {
				eps = append(eps, target.Endpoint{Input: spec, Host: h, Path: "/"})
			}
			continue
		}
		e, err := target.Expand(spec, target.ExpandOptions{MaxHosts: opts.MaxHostsPerSpec})
		if err != nil {
			return nil, fmt.Errorf("target %q: %w", spec, err)
		}
		eps = append(eps, e...)
	}
	return eps, nil
}

func emitEnum(opts Options, msg string) {
	if opts.OnProgress != nil {
		opts.OnProgress(ProgressEvent{Phase: "enumerate", Message: msg})
	}
}

func serviceEvent(r ServiceResult, done, total int) ProgressEvent {
	ev := ProgressEvent{
		Phase: "service", Done: done, Total: total,
		Host: r.Host, Port: r.Port, Open: r.PortOpen, Err: r.Error,
	}
	if r.HTTP != nil {
		ev.HTTP = true
	}
	if r.PHP != nil {
		ev.PHPVerdict = string(r.PHP.Verdict)
		ev.Version = r.PHP.Version
	}
	return ev
}

func summarise(results []ServiceResult, hosts []string, opts Options) Summary {
	s := Summary{HostsScanned: len(hosts), ServicesProbed: len(results)}
	for _, r := range results {
		if r.PortOpen {
			s.OpenPorts++
		}
		if r.HTTP != nil {
			s.HTTPServices++
		}
		if r.PHP != nil {
			switch r.PHP.Verdict {
			case php.VerdictConfirmed:
				s.PHPConfirmed++
			case php.VerdictLikely:
				s.PHPLikely++
			case php.VerdictPossible:
				s.PHPPossible++
			}
			s.Vulnerabilities += len(r.PHP.Vulnerabilities)
		}
		if r.SecurityTxt != nil && r.SecurityTxt.Present {
			s.SecurityTxt++
		}
	}
	return s
}

func scanService(ctx context.Context, fetcher *probe.Fetcher, j job, opts Options) ServiceResult {
	start := time.Now()
	res := ServiceResult{Host: j.ep.Host, Port: j.port}

	// TCP connect check first.
	status := probe.CheckPort(ctx, j.ep.Host, j.port, opts.Timeout)
	res.PortOpen = status.Open
	if !status.Open {
		if status.Err != nil {
			res.Error = status.Err.Error()
		}
		res.DurationMS = time.Since(start).Milliseconds()
		return res
	}

	// Try HTTP(S) over the candidate scheme(s).
	schemes := decideSchemes(j.ep, j.port, opts.TLSMode)
	var root *probe.Response
	var chosen schemeChoice
	for _, sc := range schemes {
		url := origin(sc.scheme, j.ep.Host, j.port) + ensureLeadingSlash(j.ep.Path)
		resp := fetcher.Get(ctx, url)
		if resp.Err == "" && resp.Status > 0 {
			root, chosen = resp, sc
			break
		}
		// Keep the last attempt for diagnostics.
		root, chosen = resp, sc
	}

	res.Scheme = chosen.scheme
	res.TLS = chosen.tls
	res.URL = origin(chosen.scheme, j.ep.Host, j.port) + ensureLeadingSlash(j.ep.Path)

	if root == nil || (root.Err != "" && root.Status == 0) {
		if root != nil {
			res.Error = root.Err
		}
		res.DurationMS = time.Since(start).Milliseconds()
		return res
	}

	res.HTTP = buildHTTPInfo(res.URL, root)

	base := origin(chosen.scheme, j.ep.Host, j.port)

	// security.txt (independent of mode unless disabled).
	if opts.SecurityTxt {
		res.SecurityTxt = fetchSecurityTxt(ctx, fetcher, base)
	}

	// Build PHP analysis input.
	in := php.Input{
		TargetURL: res.URL,
		Deep:      opts.Mode == ModeDeep,
		Root:      root,
	}
	if in.Deep {
		in.Extra = map[string]*probe.Response{}
		for _, p := range php.DeepProbePaths() {
			if p == "/" {
				continue
			}
			u := base + ensureLeadingSlash(p)
			in.Extra[u] = fetcher.Get(ctx, u)
		}
		in.EasterCredits = fetcher.Get(ctx, base+"/"+php.EasterEggCredits)
		in.EasterLogo = fetcher.Get(ctx, base+"/"+php.EasterEggLogo)
	}

	res.PHP = php.Analyze(in)
	res.DurationMS = time.Since(start).Milliseconds()
	return res
}

func fetchSecurityTxt(ctx context.Context, fetcher *probe.Fetcher, base string) *securitytxt.SecurityTxt {
	for _, p := range securitytxt.WellKnownPaths {
		u := base + p
		resp := fetcher.Get(ctx, u)
		if resp.Err != "" || resp.Status != 200 {
			continue
		}
		if st, ok := securitytxt.Parse(u, resp.BodyString()); ok {
			return st
		}
	}
	return nil
}

func buildHTTPInfo(url string, resp *probe.Response) *HTTPInfo {
	info := &HTTPInfo{
		URL:         url,
		FinalURL:    resp.FinalURL,
		Status:      resp.Status,
		Proto:       resp.Proto,
		Server:      resp.HeaderGet("Server"),
		PoweredBy:   resp.HeaderGet("X-Powered-By"),
		ContentType: resp.HeaderGet("Content-Type"),
		Redirects:   resp.Hops,
		TLS:         resp.TLS,
	}
	if info.FinalURL == url {
		info.FinalURL = ""
	}
	if m := reTitle.FindStringSubmatch(resp.BodyString()); m != nil {
		info.Title = strings.TrimSpace(collapseSpace(m[1]))
		if len(info.Title) > 160 {
			info.Title = info.Title[:160] + "…"
		}
	}
	info.Headers = selectHeaders(resp)
	return info
}

var interestingHeaders = []string{
	"Server", "X-Powered-By", "X-Generator", "X-Drupal-Cache",
	"X-Drupal-Dynamic-Cache", "X-Redirect-By", "X-Pingback", "X-Debug-Token",
	"Via", "X-AspNet-Version", "X-Runtime", "X-Varnish", "X-Cache",
}

func selectHeaders(resp *probe.Response) map[string]string {
	out := map[string]string{}
	for _, h := range interestingHeaders {
		if v := resp.HeaderGet(h); v != "" {
			out[h] = v
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func decideSchemes(ep target.Endpoint, port int, tlsMode string) []schemeChoice {
	switch ep.Scheme {
	case "https":
		return []schemeChoice{{"https", true}}
	case "http":
		return []schemeChoice{{"http", false}}
	}
	switch tlsMode {
	case TLSOn:
		return []schemeChoice{{"https", true}}
	case TLSOff:
		return []schemeChoice{{"http", false}}
	default: // auto: prefer the port's usual scheme, then fall back.
		if isTLSPort(port) {
			return []schemeChoice{{"https", true}, {"http", false}}
		}
		return []schemeChoice{{"http", false}, {"https", true}}
	}
}

func isTLSPort(port int) bool {
	switch port {
	case 443, 8443, 9443, 4443, 10443:
		return true
	default:
		return false
	}
}

func origin(scheme, host string, port int) string {
	hp := host
	if strings.Contains(host, ":") {
		hp = "[" + host + "]"
	}
	return scheme + "://" + hp + ":" + strconv.Itoa(port)
}

func ensureLeadingSlash(p string) string {
	if p == "" {
		return "/"
	}
	if !strings.HasPrefix(p, "/") {
		return "/" + p
	}
	return p
}

func collapseSpace(s string) string {
	return strings.Join(strings.Fields(s), " ")
}
