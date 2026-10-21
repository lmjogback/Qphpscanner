// Command qphpscanner scans network ports and HTTP(S) services to determine
// whether they are backed by PHP, collects supporting evidence and — in deep
// mode — fingerprints the version, variant, extensions/modules and correlates
// known version-based vulnerabilities. It also reports any published
// security.txt. It runs as a CLI or as a small web GUI.
//
// All probing is passive fingerprinting: the tool reads banners, headers,
// cookies and response bodies. It does not attempt to exploit anything. Only
// scan systems you are authorised to test.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/rom/qphpscanner/internal/config"
	"github.com/rom/qphpscanner/internal/portspec"
	"github.com/rom/qphpscanner/internal/report"
	"github.com/rom/qphpscanner/internal/scanner"
	"github.com/rom/qphpscanner/internal/version"
	"github.com/rom/qphpscanner/internal/web"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "qphpscanner: "+err.Error())
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := newFlagSet()
	f := bindFlags(fs)
	positionals, err := parseArgs(fs, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if f.showVersion {
		fmt.Println(version.String())
		return nil
	}

	set := map[string]bool{}
	fs.Visit(func(fl *flag.Flag) { set[fl.Name] = true })

	// Load config, if any.
	var cfg *config.Config
	if f.configPath != "" {
		c, err := config.Load(f.configPath)
		if err != nil {
			return err
		}
		cfg = c
	}

	opts, outFmt, outFile, repFmt, repFile, targets, webEnabled, listen, err := resolve(f, set, cfg, positionals)
	if err != nil {
		return err
	}

	// Web mode.
	if webEnabled {
		srv := web.NewServer(listen)
		fmt.Fprintf(os.Stderr, "qphpscanner web UI listening on http://%s/\n", displayAddr(listen))
		return srv.ListenAndServe()
	}

	if len(targets) == 0 {
		fs.Usage()
		return fmt.Errorf("no targets given (pass targets as arguments, in --config, or use --web)")
	}

	reporter := newProgressReporter(os.Stderr, f.verbose, f.quiet)
	opts.OnProgress = reporter.handle
	opts.DisableDNSEnum = f.noDNSEnum

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	result, err := scanner.Scan(ctx, targets, opts)
	reporter.finish()
	if err != nil {
		return err
	}

	if err := emitOutput(result, outFmt, outFile); err != nil {
		return err
	}
	if repFmt != "" || repFile != "" {
		if err := emitReport(result, repFmt, repFile); err != nil {
			return err
		}
	}

	fmt.Fprintf(os.Stderr, "scanned %d host(s), %d open port(s), %d PHP service(s) in %d ms\n",
		result.Summary.HostsScanned, result.Summary.OpenPorts,
		result.Summary.PHPConfirmed+result.Summary.PHPLikely, result.Meta.DurationMS)
	return nil
}

// resolve merges config file values with explicit CLI flags (flags win).
func resolve(f *flags, set map[string]bool, cfg *config.Config, posArgs []string) (
	opts scanner.Options, outFmt, outFile, repFmt, repFile string,
	targets []string, webEnabled bool, listen string, err error,
) {
	// Start from config defaults.
	if cfg != nil {
		opts.Mode = cfg.Mode
		opts.TLSMode = cfg.TLS
		opts.Concurrency = cfg.Concurrency
		opts.IncludeClosed = boolVal(cfg.IncludeClosed, false)
		opts.Follow = boolVal(cfg.FollowRedirects, true)
		opts.Insecure = boolVal(cfg.Insecure, false)
		opts.SecurityTxt = boolVal(cfg.SecurityTxt, true)
		opts.UserAgent = cfg.UserAgent
		opts.MaxBodyBytes = cfg.MaxBodyBytes
		opts.MaxHostsPerSpec = cfg.MaxHostsPerSpec
		if cfg.Timeout != "" {
			d, perr := time.ParseDuration(cfg.Timeout)
			if perr != nil {
				err = fmt.Errorf("config timeout %q: %w", cfg.Timeout, perr)
				return
			}
			opts.Timeout = d
		}
		outFmt, outFile = cfg.Output.Format, cfg.Output.File
		repFmt, repFile = cfg.Report.Format, cfg.Report.File
		targets = cfg.Targets
		webEnabled = boolVal(cfg.Web.Enabled, false)
		listen = cfg.Web.Listen
	} else {
		opts.Follow = true
		opts.SecurityTxt = true
	}

	// Ports: flag > config > default.
	portStr := ""
	if cfg != nil {
		portStr = cfg.Ports
	}
	if set["ports"] {
		portStr = f.ports
	}
	if strings.TrimSpace(portStr) != "" {
		ports, perr := portspec.Parse(portStr)
		if perr != nil {
			err = perr
			return
		}
		opts.Ports = ports
	}

	// Apply explicitly-set flags.
	if set["mode"] {
		opts.Mode = f.mode
	}
	if set["tls"] {
		opts.TLSMode = f.tls
	}
	if set["timeout"] {
		opts.Timeout = f.timeout
	}
	if set["concurrency"] {
		opts.Concurrency = f.concurrency
	}
	if set["follow"] {
		opts.Follow = f.follow
	}
	if set["insecure"] {
		opts.Insecure = f.insecure
	}
	if set["security-txt"] {
		opts.SecurityTxt = f.securityTxt
	}
	if set["include-closed"] {
		opts.IncludeClosed = f.includeClosed
	}
	if set["user-agent"] {
		opts.UserAgent = f.userAgent
	}
	if set["max-hosts"] {
		opts.MaxHostsPerSpec = f.maxHosts
	}
	if set["format"] {
		outFmt = f.format
	}
	if set["out"] {
		outFile = f.out
	}
	if set["report"] {
		repFmt = f.report
	}
	if set["report-out"] {
		repFile = f.reportOut
	}
	if set["web"] {
		webEnabled = f.web
	}
	if set["listen"] {
		listen = f.listen
	}

	if outFmt == "" {
		outFmt = "text"
	}
	if listen == "" {
		listen = "127.0.0.1:8088"
	}

	// Validate mode/tls early for a friendly error.
	if err = validateMode(opts.Mode); err != nil {
		return
	}
	if err = validateTLS(opts.TLSMode); err != nil {
		return
	}

	// Positional args override config targets.
	if len(posArgs) > 0 {
		targets = posArgs
	}

	// Infer report format from file extension when only a file is given.
	if repFile != "" && repFmt == "" {
		repFmt = inferReportFormat(repFile)
	}
	// Infer output format from file extension when only a file is given.
	if outFile != "" && !set["format"] && (cfg == nil || cfg.Output.Format == "") {
		if ext := inferOutputFormat(outFile); ext != "" {
			outFmt = ext
		}
	}
	return
}

func emitOutput(res *scanner.ScanResult, format, file string) error {
	if file == "" {
		return report.WriteOutput(os.Stdout, res, format)
	}
	fh, err := os.Create(file)
	if err != nil {
		return err
	}
	defer fh.Close()
	if err := report.WriteOutput(fh, res, format); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote %s output to %s\n", format, file)
	return nil
}

func emitReport(res *scanner.ScanResult, format, file string) error {
	if format == "" {
		format = "text"
	}
	if file == "" {
		if format == "text" {
			return report.WriteReport(os.Stdout, res, format)
		}
		return fmt.Errorf("report format %q needs an output file (use --report-out)", format)
	}
	fh, err := os.Create(file)
	if err != nil {
		return err
	}
	defer fh.Close()
	if err := report.WriteReport(fh, res, format); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote %s report to %s\n", format, file)
	return nil
}

func validateMode(m string) error {
	switch m {
	case "", scanner.ModeDetect, scanner.ModeDeep:
		return nil
	default:
		return fmt.Errorf("invalid mode %q (want detect or deep)", m)
	}
}

func validateTLS(t string) error {
	switch t {
	case "", scanner.TLSAuto, scanner.TLSOn, scanner.TLSOff:
		return nil
	default:
		return fmt.Errorf("invalid tls %q (want auto, on or off)", t)
	}
}

func inferReportFormat(file string) string {
	switch strings.ToLower(ext(file)) {
	case "pdf":
		return "pdf"
	case "rtf":
		return "rtf"
	default:
		return "text"
	}
}

func inferOutputFormat(file string) string {
	switch strings.ToLower(ext(file)) {
	case "json":
		return "json"
	case "xml":
		return "xml"
	case "txt", "text":
		return "text"
	default:
		return ""
	}
}

func ext(file string) string {
	if i := strings.LastIndexByte(file, '.'); i >= 0 {
		return file[i+1:]
	}
	return ""
}

// parseArgs parses flags that may appear before, between or after positional
// target arguments. The standard flag package stops at the first non-flag
// argument, so we parse iteratively, collecting positionals between flag runs.
func parseArgs(fs *flag.FlagSet, args []string) ([]string, error) {
	var positionals []string
	rest := args
	for {
		if err := fs.Parse(rest); err != nil {
			return nil, err
		}
		rest = fs.Args()
		if len(rest) == 0 {
			break
		}
		positionals = append(positionals, rest[0])
		rest = rest[1:]
	}
	return positionals, nil
}

func boolVal(p *bool, def bool) bool {
	if p != nil {
		return *p
	}
	return def
}

func displayAddr(listen string) string {
	if strings.HasPrefix(listen, ":") {
		return "localhost" + listen
	}
	return listen
}
