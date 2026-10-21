package report

import (
	"encoding/xml"
	"io"

	"github.com/rom/qphpscanner/internal/scanner"
)

func writeXML(w io.Writer, res *scanner.ScanResult) error {
	if _, err := io.WriteString(w, xml.Header); err != nil {
		return err
	}
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	if err := enc.Encode(res); err != nil {
		return err
	}
	_, err := io.WriteString(w, "\n")
	return err
}
