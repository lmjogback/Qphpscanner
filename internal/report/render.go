package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/rom/qphpscanner/internal/scanner"
)

// OutputFormats and ReportFormats enumerate what the CLI accepts.
var (
	OutputFormats = []string{"text", "json", "xml", "csv", "sarif", "ndjson"}
	ReportFormats = []string{"text", "rtf", "pdf", "html"}
)

// WriteOutput renders machine-readable scan output in the given format.
func WriteOutput(w io.Writer, res *scanner.ScanResult, format string) error {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "text", "txt":
		return writeText(w, buildDocument(res))
	case "json":
		return writeJSON(w, res)
	case "xml":
		return writeXML(w, res)
	case "csv":
		return writeCSV(w, res)
	case "sarif":
		return writeSARIF(w, res)
	case "ndjson":
		return writeNDJSON(w, res)
	default:
		return fmt.Errorf("unknown output format %q (want text, json, xml, csv, sarif or ndjson)", format)
	}
}

// WriteReport renders a human-readable report in the given format.
func WriteReport(w io.Writer, res *scanner.ScanResult, format string) error {
	doc := buildDocument(res)
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "text", "txt":
		return writeText(w, doc)
	case "rtf":
		return writeRTF(w, doc)
	case "pdf":
		return writePDF(w, doc)
	case "html":
		return writeHTML(w, doc)
	default:
		return fmt.Errorf("unknown report format %q (want text, rtf, pdf or html)", format)
	}
}

const textWidth = 78

func writeText(w io.Writer, d *document) error {
	var b strings.Builder
	for _, blk := range d.blocks {
		switch blk.kind {
		case kindH1:
			t := strings.ToUpper(blk.text)
			b.WriteString(t + "\n")
			b.WriteString(strings.Repeat("=", min(len(t), textWidth)) + "\n")
		case kindH2:
			b.WriteString("\n" + blk.text + "\n")
			b.WriteString(strings.Repeat("-", min(len(blk.text), textWidth)) + "\n")
		case kindH3:
			b.WriteString("\n» " + blk.text + "\n")
		case kindText:
			b.WriteString(wrapIndent(blk.text, "", textWidth) + "\n")
		case kindKV:
			key := blk.key
			pad := 20 - len(key)
			if pad < 1 {
				pad = 1
			}
			b.WriteString(key + strings.Repeat(" ", pad) + ": " + blk.val + "\n")
		case kindBullet:
			b.WriteString(wrapIndent(blk.text, "  - ", textWidth) + "\n")
		case kindSpacer:
			b.WriteString("\n")
		case kindRule:
			b.WriteString(strings.Repeat("─", textWidth) + "\n")
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// wrapIndent wraps text to width, prefixing the first line with prefix and
// continuation lines with matching blank indentation.
func wrapIndent(text, prefix string, width int) string {
	cont := strings.Repeat(" ", len(prefix))
	words := strings.Fields(text)
	if len(words) == 0 {
		return prefix
	}
	var lines []string
	cur := prefix + words[0]
	for _, word := range words[1:] {
		if len(cur)+1+len(word) > width {
			lines = append(lines, cur)
			cur = cont + word
		} else {
			cur += " " + word
		}
	}
	lines = append(lines, cur)
	return strings.Join(lines, "\n")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
