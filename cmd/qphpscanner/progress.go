package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/rom/qphpscanner/internal/scanner"
)

// progressReporter renders scan progress to a writer (stderr). In verbose mode
// it prints a line per service (and per enumeration step); otherwise it shows a
// compact running counter, updated in place on a terminal.
type progressReporter struct {
	w       io.Writer
	verbose bool
	quiet   bool
	tty     bool

	mu        sync.Mutex
	lastLen   int
	openCount int
	phpCount  int
	step      int
}

func newProgressReporter(w *os.File, verbose, quiet bool) *progressReporter {
	tty := false
	if fi, err := w.Stat(); err == nil {
		tty = fi.Mode()&os.ModeCharDevice != 0
	}
	return &progressReporter{w: w, verbose: verbose, quiet: quiet, tty: tty}
}

func (p *progressReporter) handle(ev scanner.ProgressEvent) {
	if p.quiet {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	switch ev.Phase {
	case "enumerate":
		p.clearLine()
		fmt.Fprintln(p.w, "[*] "+ev.Message)
	case "service":
		if ev.Open {
			p.openCount++
		}
		if isPHP(ev.PHPVerdict) {
			p.phpCount++
		}
		if p.verbose {
			p.clearLine()
			fmt.Fprintln(p.w, p.verboseLine(ev))
			return
		}
		p.counter(ev)
	}
}

func (p *progressReporter) verboseLine(ev scanner.ProgressEvent) string {
	if !ev.Open {
		return fmt.Sprintf("[-] %s:%d closed/filtered", ev.Host, ev.Port)
	}
	s := fmt.Sprintf("[+] %s:%d open", ev.Host, ev.Port)
	if ev.HTTP {
		s += " http"
	}
	if isPHP(ev.PHPVerdict) {
		s += " php=" + ev.PHPVerdict
		if ev.Version != "" {
			s += " " + ev.Version
		}
	}
	return s
}

func (p *progressReporter) counter(ev scanner.ProgressEvent) {
	msg := fmt.Sprintf("scanning… %d/%d (open %d, php %d)", ev.Done, ev.Total, p.openCount, p.phpCount)
	if p.tty {
		p.clearLine()
		fmt.Fprint(p.w, msg)
		p.lastLen = len(msg)
		return
	}
	// Non-terminal: emit occasional full lines instead of a redrawn counter.
	if p.step == 0 {
		p.step = ev.Total / 20
		if p.step < 1 {
			p.step = 1
		}
	}
	if ev.Done == 1 || ev.Done == ev.Total || ev.Done%p.step == 0 {
		fmt.Fprintln(p.w, msg)
	}
}

func (p *progressReporter) clearLine() {
	if p.tty && p.lastLen > 0 {
		fmt.Fprint(p.w, "\r"+strings.Repeat(" ", p.lastLen)+"\r")
		p.lastLen = 0
	}
}

// finish clears any in-place counter so following output starts cleanly.
func (p *progressReporter) finish() {
	if p.quiet {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.clearLine()
}

func isPHP(verdict string) bool {
	return verdict != "" && verdict != "none"
}
