package report

import (
	"fmt"
	"io"
	"strings"
)

// writeRTF renders the document as Rich Text Format, readable by word
// processors (Word, LibreOffice, TextEdit). It is produced by hand to avoid
// any external dependency.
func writeRTF(w io.Writer, d *document) error {
	var b strings.Builder
	b.WriteString(`{\rtf1\ansi\ansicpg1252\deff0`)
	b.WriteString("\n")
	b.WriteString(`{\fonttbl{\f0\fswiss\fcharset0 Helvetica;}{\f1\fmodern\fcharset0 Courier New;}}`)
	b.WriteString("\n")
	b.WriteString(`\margl1134\margr1134\margt1134\margb1134`)
	b.WriteString("\n")

	for _, blk := range d.blocks {
		switch blk.kind {
		case kindH1:
			b.WriteString(`{\b\fs40 ` + rtfEscape(blk.text) + `}\par`)
			b.WriteString(`\par`)
		case kindH2:
			b.WriteString(`\par{\b\fs30 ` + rtfEscape(blk.text) + `}\par`)
		case kindH3:
			b.WriteString(`\par{\b\fs24 ` + rtfEscape(blk.text) + `}\par`)
		case kindText:
			b.WriteString(`{\fs20 ` + rtfEscape(blk.text) + `}\par`)
		case kindKV:
			b.WriteString(`{\fs20 {\b ` + rtfEscape(blk.key) + `:}  ` + rtfEscape(blk.val) + `}\par`)
		case kindBullet:
			b.WriteString(`{\fs20\li360 \bullet  ` + rtfEscape(blk.text) + `}\par`)
		case kindSpacer:
			b.WriteString(`\par`)
		case kindRule:
			b.WriteString(`{\fs20 ` + strings.Repeat("_", 60) + `}\par`)
		}
		b.WriteString("\n")
	}

	b.WriteString("}\n")
	_, err := io.WriteString(w, b.String())
	return err
}

// rtfEscape escapes RTF control characters and encodes non-ASCII runes using
// the \uN? form.
func rtfEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '{':
			b.WriteString(`\{`)
		case '}':
			b.WriteString(`\}`)
		case '\n':
			b.WriteString(`\line `)
		default:
			if r < 128 {
				b.WriteRune(r)
			} else {
				// RTF signed 16-bit unicode escape with ASCII fallback char.
				u := int(r)
				if u > 32767 {
					u -= 65536
				}
				fmt.Fprintf(&b, `\u%d?`, u)
			}
		}
	}
	return b.String()
}
