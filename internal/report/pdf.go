package report

import "io"

func writePDF(w io.Writer, d *document) error {
	b := newPDF()
	for _, blk := range d.blocks {
		switch blk.kind {
		case kindH1:
			b.line(blk.text, 18, true)
			b.gap(4)
		case kindH2:
			b.gap(6)
			b.line(blk.text, 14, true)
			b.gap(2)
		case kindH3:
			b.gap(4)
			b.line(blk.text, 11, true)
		case kindText:
			b.line(blk.text, 9.5, false)
		case kindKV:
			b.line(blk.key+": "+blk.val, 9.5, false)
		case kindBullet:
			b.line("* "+blk.text, 9.5, false)
		case kindSpacer:
			b.gap(5)
		case kindRule:
			b.rule()
		}
	}
	_, err := w.Write(b.bytesOut())
	return err
}
