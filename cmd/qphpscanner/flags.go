package main

import (
	"flag"
	"fmt"
	"os"
	"time"
)

// flags holds the parsed command-line flag values.
type flags struct {
	configPath    string
	ports         string
	mode          string
	tls           string
	timeout       time.Duration
	concurrency   int
	follow        bool
	insecure      bool
	securityTxt   bool
	includeClosed bool
	format        string
	out           string
	report        string
	reportOut     string
	userAgent     string
	maxHosts      int
	web           bool
	listen        string
	showVersion   bool
	verbose       bool
	quiet         bool
	noDNSEnum     bool
}

func newFlagSet() *flag.FlagSet {
	fs := flag.NewFlagSet("qphpscanner", flag.ContinueOnError)
	fs.Usage = func() {
		w := fs.Output()
		fmt.Fprintf(w, `qphpscanner — detect PHP-backed services, collect evidence, report.

Usage:
  qphpscanner [options] <target> [target ...]
  qphpscanner --web [--listen host:port]
  qphpscanner --config scan.yaml

Targets:
  URL           https://example.com/app.php
  IPv4/IPv6     203.0.113.10        2001:db8::1
  CIDR          10.0.0.0/24         2001:db8::/120
  Range         192.168.1.10-20     10.0.0.1-10.0.0.50
  IP wildcard   192.168.1.*         10.0.*.*
  DNS wildcard  *.example.com       (enumerates subdomains via certificate transparency)

Options:
`)
		fs.PrintDefaults()
		fmt.Fprintf(w, `
Examples:
  qphpscanner example.com
  qphpscanner --mode deep --ports 80,443,8080 --report-out report.pdf example.com
  qphpscanner --tls on --format json --out scan.json 10.0.0.0/28
  qphpscanner --verbose '*.example.com'
  qphpscanner --web --listen 127.0.0.1:8088
`)
	}
	return fs
}

func bindFlags(fs *flag.FlagSet) *flags {
	f := &flags{}
	fs.StringVar(&f.configPath, "config", "", "path to a YAML configuration file")
	fs.StringVar(&f.ports, "ports", "", "ports to check: 80 | 80,443 | 8000-8100 | mix (default: common web ports)")
	fs.StringVar(&f.mode, "mode", "detect", "scan depth: detect (is it PHP?) or deep (version, extensions, vulns)")
	fs.StringVar(&f.tls, "tls", "auto", "TLS handling: auto | on | off")
	fs.DurationVar(&f.timeout, "timeout", 10*time.Second, "per-connection timeout (e.g. 5s, 500ms)")
	fs.IntVar(&f.concurrency, "concurrency", 50, "maximum concurrent service probes")
	fs.BoolVar(&f.follow, "follow", true, "follow HTTP redirects while collecting evidence")
	fs.BoolVar(&f.insecure, "insecure", false, "do not verify TLS certificates")
	fs.BoolVar(&f.securityTxt, "security-txt", true, "look up and parse /.well-known/security.txt")
	fs.BoolVar(&f.includeClosed, "include-closed", false, "include closed/filtered ports in the output")
	fs.StringVar(&f.format, "format", "text", "scan output format: text | json | xml")
	fs.StringVar(&f.out, "out", "", "write scan output to this file instead of stdout")
	fs.StringVar(&f.report, "report", "", "also produce a report: text | rtf | pdf")
	fs.StringVar(&f.reportOut, "report-out", "", "write the report to this file (required for rtf/pdf)")
	fs.StringVar(&f.userAgent, "user-agent", "", "override the HTTP User-Agent header")
	fs.IntVar(&f.maxHosts, "max-hosts", 0, "maximum hosts a single target spec may expand to")
	fs.BoolVar(&f.web, "web", false, "run the web GUI instead of a one-shot scan")
	fs.StringVar(&f.listen, "listen", "127.0.0.1:8088", "web GUI listen address (with --web)")
	fs.BoolVar(&f.showVersion, "version", false, "print version and exit")
	fs.BoolVar(&f.verbose, "verbose", false, "print per-host/service progress detail (open/closed ports, PHP verdicts)")
	fs.BoolVar(&f.verbose, "v", false, "shorthand for --verbose")
	fs.BoolVar(&f.quiet, "quiet", false, "suppress progress output")
	fs.BoolVar(&f.quiet, "q", false, "shorthand for --quiet")
	fs.BoolVar(&f.noDNSEnum, "no-dns-enum", false, "disable '*.domain' subdomain enumeration")

	fs.SetOutput(os.Stderr)
	return f
}
