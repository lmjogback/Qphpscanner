package report

import (
	"encoding/json"
	"io"

	"github.com/rom/qphpscanner/internal/scanner"
)

// writeNDJSON emits one JSON object per service (newline-delimited), convenient
// for streaming into other tools. A leading meta line carries scan metadata.
func writeNDJSON(w io.Writer, res *scanner.ScanResult) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(map[string]interface{}{"type": "meta", "meta": res.Meta, "summary": res.Summary}); err != nil {
		return err
	}
	for _, t := range res.Targets {
		for _, s := range t.Services {
			rec := map[string]interface{}{"type": "service", "service": s}
			if len(t.Addresses) > 0 {
				rec["addresses"] = t.Addresses
			}
			if err := enc.Encode(rec); err != nil {
				return err
			}
		}
	}
	return nil
}
