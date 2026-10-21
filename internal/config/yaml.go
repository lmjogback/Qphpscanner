package config

import (
	"fmt"
	"strings"
)

// This is a deliberately small YAML subset parser, sufficient for the flat
// configuration schema qphpscanner uses. It supports:
//
//   - comments (whole-line `#` and inline ` #`)
//   - nested maps via consistent space indentation (tabs are rejected)
//   - scalar key/value pairs ("key: value")
//   - block lists of scalars ("- item")
//   - single/double quoted scalars
//
// It intentionally does not implement anchors, flow collections, multi-line
// scalars or other advanced YAML. The schema is documented in config.example.yaml.

// Unmarshal parses YAML-subset bytes into a generic tree of
// map[string]interface{}, []interface{} and string values.
func Unmarshal(data []byte) (map[string]interface{}, error) {
	raw := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	var lines []yline
	for i, r := range raw {
		content, ok := stripComment(r)
		if !ok {
			continue // blank or comment-only line
		}
		indent, err := indentOf(r, i+1)
		if err != nil {
			return nil, err
		}
		lines = append(lines, yline{indent: indent, content: content, num: i + 1})
	}

	p := &yparser{lines: lines}
	m, err := p.parseMap(0)
	if err != nil {
		return nil, err
	}
	if p.pos != len(p.lines) {
		return nil, fmt.Errorf("line %d: unexpected indentation", p.lines[p.pos].num)
	}
	return m, nil
}

type yline struct {
	indent  int
	content string
	num     int
}

type yparser struct {
	lines []yline
	pos   int
}

func (p *yparser) parseMap(indent int) (map[string]interface{}, error) {
	m := map[string]interface{}{}
	for p.pos < len(p.lines) {
		ln := p.lines[p.pos]
		if ln.indent < indent {
			break
		}
		if ln.indent > indent {
			return nil, fmt.Errorf("line %d: unexpected indentation", ln.num)
		}
		if strings.HasPrefix(ln.content, "- ") || ln.content == "-" {
			return nil, fmt.Errorf("line %d: unexpected list item", ln.num)
		}
		key, val, ok := splitKV(ln.content)
		if !ok {
			return nil, fmt.Errorf("line %d: expected 'key: value'", ln.num)
		}
		p.pos++

		if val != "" {
			m[key] = parseScalar(val)
			continue
		}
		// Nested block: inspect the next line's indentation.
		if p.pos < len(p.lines) && p.lines[p.pos].indent > indent {
			childIndent := p.lines[p.pos].indent
			if strings.HasPrefix(p.lines[p.pos].content, "- ") || p.lines[p.pos].content == "-" {
				list, err := p.parseList(childIndent)
				if err != nil {
					return nil, err
				}
				m[key] = list
			} else {
				child, err := p.parseMap(childIndent)
				if err != nil {
					return nil, err
				}
				m[key] = child
			}
		} else {
			m[key] = ""
		}
	}
	return m, nil
}

func (p *yparser) parseList(indent int) ([]interface{}, error) {
	var list []interface{}
	for p.pos < len(p.lines) {
		ln := p.lines[p.pos]
		if ln.indent != indent || !(strings.HasPrefix(ln.content, "- ") || ln.content == "-") {
			break
		}
		item := strings.TrimSpace(strings.TrimPrefix(ln.content, "-"))
		list = append(list, parseScalar(item))
		p.pos++
	}
	return list, nil
}

func splitKV(s string) (key, val string, ok bool) {
	if i := strings.Index(s, ": "); i >= 0 {
		return strings.TrimSpace(s[:i]), strings.TrimSpace(s[i+2:]), true
	}
	if strings.HasSuffix(s, ":") {
		return strings.TrimSpace(s[:len(s)-1]), "", true
	}
	return "", "", false
}

func parseScalar(v string) string {
	v = strings.TrimSpace(v)
	if len(v) >= 2 {
		if (v[0] == '"' && v[len(v)-1] == '"') || (v[0] == '\'' && v[len(v)-1] == '\'') {
			return v[1 : len(v)-1]
		}
	}
	return v
}

// stripComment removes an inline/whole-line comment and reports whether any
// content remains. A '#' only starts a comment at the start of the trimmed
// line or when preceded by whitespace (so URLs with fragments survive).
func stripComment(raw string) (string, bool) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return "", false
	}
	inSingle, inDouble := false, false
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		switch c {
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case '#':
			if !inSingle && !inDouble && i > 0 && (raw[i-1] == ' ' || raw[i-1] == '\t') {
				raw = raw[:i]
				goto done
			}
		}
	}
done:
	out := strings.TrimSpace(raw)
	return out, out != ""
}

func indentOf(raw string, lineNum int) (int, error) {
	n := 0
	for _, c := range raw {
		switch c {
		case ' ':
			n++
		case '\t':
			return 0, fmt.Errorf("line %d: tab indentation is not allowed (use spaces)", lineNum)
		default:
			return n, nil
		}
	}
	return n, nil
}
