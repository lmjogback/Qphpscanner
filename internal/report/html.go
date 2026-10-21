package report

import (
	"html"
	"io"
	"strings"
)

// writeHTML renders the report document as a self-contained HTML page.
func writeHTML(w io.Writer, d *document) error {
	var b strings.Builder
	b.WriteString(`<!doctype html><html lang="en"><head><meta charset="utf-8">`)
	b.WriteString(`<meta name="viewport" content="width=device-width, initial-scale=1">`)
	b.WriteString("<title>")
	b.WriteString(html.EscapeString(d.title))
	b.WriteString("</title><style>")
	b.WriteString(htmlCSS)
	b.WriteString("</style></head><body><main>")

	inList := false
	closeList := func() {
		if inList {
			b.WriteString("</ul>")
			inList = false
		}
	}

	for _, blk := range d.blocks {
		switch blk.kind {
		case kindH1:
			closeList()
			b.WriteString("<h1>" + html.EscapeString(blk.text) + "</h1>")
		case kindH2:
			closeList()
			b.WriteString("<h2>" + html.EscapeString(blk.text) + "</h2>")
		case kindH3:
			closeList()
			b.WriteString("<h3>" + html.EscapeString(blk.text) + "</h3>")
		case kindText:
			closeList()
			b.WriteString("<p>" + html.EscapeString(blk.text) + "</p>")
		case kindKV:
			closeList()
			b.WriteString(`<div class="kv"><span class="k">` + html.EscapeString(blk.key) +
				`</span><span class="v">` + html.EscapeString(blk.val) + `</span></div>`)
		case kindBullet:
			if !inList {
				b.WriteString("<ul>")
				inList = true
			}
			b.WriteString("<li>" + html.EscapeString(blk.text) + "</li>")
		case kindSpacer:
			closeList()
			b.WriteString(`<div class="sp"></div>`)
		case kindRule:
			closeList()
			b.WriteString("<hr>")
		}
	}
	closeList()
	b.WriteString("</main></body></html>")
	_, err := io.WriteString(w, b.String())
	return err
}

const htmlCSS = `
:root{--bg:#0f1419;--panel:#171d26;--border:#2a3542;--text:#e6edf3;--dim:#9aa7b4;--accent:#7c6cff}
@media(prefers-color-scheme:light){:root{--bg:#f4f6f9;--panel:#fff;--border:#d9dee6;--text:#1a2029;--dim:#5a6673}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;line-height:1.5}
main{max-width:900px;margin:0 auto;padding:28px 20px}
h1{font-size:1.5rem;border-bottom:2px solid var(--accent);padding-bottom:8px}
h2{font-size:1.15rem;margin-top:28px}
h3{font-size:1rem;color:var(--accent);font-family:ui-monospace,Menlo,Consolas,monospace;word-break:break-all}
p{margin:6px 0}
hr{border:0;border-top:1px solid var(--border);margin:18px 0}
.sp{height:8px}
.kv{display:grid;grid-template-columns:200px 1fr;gap:2px 14px;font-size:.9rem;padding:1px 0}
.kv .k{color:var(--dim)}
.kv .v{word-break:break-word}
ul{margin:6px 0;padding-left:20px;font-size:.88rem}
li{margin:2px 0}
@media(max-width:560px){.kv{grid-template-columns:1fr}}
`
