package report

import (
	"bytes"
	"fmt"
	"strings"
)

// pdfBuilder is a tiny PDF generator: US-Letter pages of left-aligned text in
// the standard Helvetica fonts (which need no embedding). It supports multiple
// pages, font sizing, bold, horizontal rules and word wrapping. This keeps PDF
// output dependency-free; it is not a general-purpose PDF library.
type pdfBuilder struct {
	pages   []string
	cur     bytes.Buffer
	y       float64
	pageW   float64
	pageH   float64
	marginL float64
	marginR float64
	marginT float64
	marginB float64
}

func newPDF() *pdfBuilder {
	b := &pdfBuilder{
		pageW: 612, pageH: 792,
		marginL: 54, marginR: 54, marginT: 54, marginB: 54,
	}
	b.y = b.pageH - b.marginT
	return b
}

func (b *pdfBuilder) usableWidth() float64 { return b.pageW - b.marginL - b.marginR }

func (b *pdfBuilder) newPage() {
	b.pages = append(b.pages, b.cur.String())
	b.cur.Reset()
	b.y = b.pageH - b.marginT
}

func (b *pdfBuilder) ensure(h float64) {
	if b.y-h < b.marginB {
		b.newPage()
	}
}

func (b *pdfBuilder) gap(h float64) {
	b.y -= h
	if b.y < b.marginB {
		b.newPage()
	}
}

func (b *pdfBuilder) line(text string, size float64, bold bool) {
	leading := size * 1.45
	maxChars := int(b.usableWidth() / (size * 0.5))
	if maxChars < 1 {
		maxChars = 1
	}
	font := "F1"
	if bold {
		font = "F2"
	}
	for _, seg := range wrapWords(text, maxChars) {
		b.ensure(leading)
		fmt.Fprintf(&b.cur, "BT /%s %.1f Tf 1 0 0 1 %.1f %.1f Tm (%s) Tj ET\n",
			font, size, b.marginL, b.y, pdfEscape(seg))
		b.y -= leading
	}
}

func (b *pdfBuilder) rule() {
	b.ensure(8)
	fmt.Fprintf(&b.cur, "0.5 w %.1f %.1f m %.1f %.1f l S\n",
		b.marginL, b.y, b.pageW-b.marginR, b.y)
	b.y -= 8
}

// bytesOut finalises the document and returns the PDF bytes.
func (b *pdfBuilder) bytesOut() []byte {
	// Flush the final page.
	b.pages = append(b.pages, b.cur.String())
	b.cur.Reset()

	numPages := len(b.pages)
	totalObjs := 4 + 2*numPages

	// Page object numbers: 6, 8, 10, ...
	kids := make([]string, numPages)
	for p := 0; p < numPages; p++ {
		kids[p] = fmt.Sprintf("%d 0 R", 6+2*p)
	}

	var buf bytes.Buffer
	offsets := make([]int, totalObjs+1) // 1-indexed

	writeObj := func(num int, body string) {
		offsets[num] = buf.Len()
		fmt.Fprintf(&buf, "%d 0 obj\n%s\nendobj\n", num, body)
	}

	buf.WriteString("%PDF-1.4\n")
	buf.WriteString("%\xe2\xe3\xcf\xd3\n") // binary marker

	writeObj(1, "<< /Type /Catalog /Pages 2 0 R >>")
	writeObj(2, fmt.Sprintf("<< /Type /Pages /Kids [%s] /Count %d >>",
		strings.Join(kids, " "), numPages))
	writeObj(3, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
	writeObj(4, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>")

	for p := 0; p < numPages; p++ {
		contentNum := 5 + 2*p
		pageNum := 6 + 2*p
		content := b.pages[p]

		offsets[contentNum] = buf.Len()
		fmt.Fprintf(&buf, "%d 0 obj\n<< /Length %d >>\nstream\n%s\nendstream\nendobj\n",
			contentNum, len(content), content)

		pageBody := fmt.Sprintf(
			"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %.0f %.0f] "+
				"/Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents %d 0 R >>",
			b.pageW, b.pageH, contentNum)
		writeObj(pageNum, pageBody)
	}

	// Cross-reference table.
	xrefOffset := buf.Len()
	fmt.Fprintf(&buf, "xref\n0 %d\n", totalObjs+1)
	buf.WriteString("0000000000 65535 f \n")
	for i := 1; i <= totalObjs; i++ {
		fmt.Fprintf(&buf, "%010d 00000 n \n", offsets[i])
	}
	fmt.Fprintf(&buf, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n",
		totalObjs+1, xrefOffset)

	return buf.Bytes()
}

func pdfEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '(':
			b.WriteString(`\(`)
		case ')':
			b.WriteString(`\)`)
		default:
			if r < 128 {
				b.WriteRune(r)
			} else {
				// WinAnsi-ish fallback: replace unsupported runes so the text
				// stays readable without font embedding.
				b.WriteByte(asciiFallback(r))
			}
		}
	}
	return b.String()
}

func asciiFallback(r rune) byte {
	switch r {
	case '─', '—', '–':
		return '-'
	case '•':
		return '*'
	case '»':
		return '>'
	case '…':
		return '.'
	case '‘', '’':
		return '\''
	case '“', '”':
		return '"'
	default:
		return '?'
	}
}

func wrapWords(text string, maxChars int) []string {
	words := strings.Fields(text)
	if len(words) == 0 {
		return []string{""}
	}
	var lines []string
	cur := words[0]
	for _, w := range words[1:] {
		if len(cur)+1+len(w) > maxChars {
			lines = append(lines, cur)
			// Hard-break a single word longer than the line.
			for len(w) > maxChars {
				lines = append(lines, w[:maxChars])
				w = w[maxChars:]
			}
			cur = w
		} else {
			cur += " " + w
		}
	}
	lines = append(lines, cur)
	return lines
}
