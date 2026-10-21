# qphpscanner — Usage

`qphpscanner` detects whether network services are backed by PHP, collects the
evidence behind each verdict, and produces reports. It runs as a one-shot CLI
or as a local web GUI.

> **Authorised use only.** Only scan hosts and networks you own or are
> explicitly permitted to test.

## Contents

- [Synopsis](#synopsis)
- [Targets](#targets)
- [Ports](#ports)
- [TLS](#tls)
- [Scan depth](#scan-depth-detect-vs-deep)
- [Output formats](#output-formats)
- [Report formats](#report-formats)
- [Configuration file](#configuration-file)
- [Web GUI](#web-gui)
- [Exit status](#exit-status)
- [Examples](#examples)
- [Interpreting results](#interpreting-results)

## Synopsis

```
qphpscanner [options] <target> [target ...]
qphpscanner --web [--listen host:port]
qphpscanner --config scan.yaml
```

Run `qphpscanner --help` for the full flag list.

## Targets

Targets are given as positional arguments (or in the config file / web form).
Each target may be any of:

| Form | Example |
| --- | --- |
| URL | `https://example.com/app.php` |
| IPv4 literal | `203.0.113.10` |
| IPv6 literal | `2001:db8::1` or `[2001:db8::1]` |
| IPv4 CIDR | `10.0.0.0/24` |
| IPv6 CIDR | `2001:db8::/120` |
| Dashed range (last octet) | `192.168.1.10-20` |
| Dashed range (full) | `10.0.0.1-10.0.0.50` |
| Per-octet wildcard | `192.168.1.*`, `10.0.*.*` |
| Hostname | `example.com` |

When a target is a **URL**, its scheme, port and path are honoured: that exact
endpoint is scanned (and `--ports` is ignored for it). All other target forms
are scanned across the selected port set.

A single spec is capped at `--max-hosts` (default 65 536) expanded hosts to
guard against an accidental huge range.

## Ports

`--ports` accepts single ports, comma-separated lists, inclusive ranges, and
any mixture:

```
--ports 80
--ports 80,443,8080
--ports 8000-8100
--ports 80,443,8000-8010,9000
```

With no `--ports`, a built-in common-web-port set is used:
`80, 443, 8000, 8008, 8080, 8443, 8888, 3000, 5000, 9000`.

## TLS

`--tls` controls whether services are probed over HTTPS:

- `auto` (default) — infer from the port (443/8443/9443/4443/10443 ⇒ HTTPS),
  and fall back to the other scheme if the first attempt yields no HTTP
  response.
- `on` — force HTTPS.
- `off` — force HTTP.

A URL target's own scheme always wins. Use `--insecure` to probe hosts with
self-signed or otherwise invalid certificates.

## Scan depth: detect vs deep

- `--mode detect` (default) — decide **whether** each service is PHP and record
  the evidence. Fast; one request per service (plus security.txt).
- `--mode deep` — additionally fetch a small set of read-only probe paths
  (`/index.php`, `/info.php`, `/phpinfo.php`, `/composer.json`, framework entry
  points, and the `expose_php` easter-egg endpoints) to fingerprint the
  **version**, **variant**, **extensions/modules**, end-of-life status, and to
  correlate **known version-based vulnerabilities**.

All probes are GET requests; nothing is submitted and nothing is exploited.

## Output formats

`--format` selects the machine-readable scan output, written to stdout or to
`--out FILE`:

- `text` (default) — the same layout as the text report.
- `json` — a structured document (see `docs/DESIGN.md` for the schema).
- `xml` — the same data as XML, rooted at `<scan>`.

If `--out` ends in `.json`/`.xml`/`.txt` the format is inferred from the
extension (unless `--format` is given explicitly).

## Report formats

A report is a human-readable write-up (summary, per-host sections, evidence,
vulnerability leads, security.txt). Produce one with `--report` and/or
`--report-out`:

- `--report text` — write to stdout (or to `--report-out`).
- `--report rtf --report-out report.rtf` — Rich Text, opens in Word/LibreOffice.
- `--report pdf --report-out report.pdf` — PDF.

`rtf` and `pdf` require `--report-out`. If only `--report-out` is given, the
format is inferred from the file extension.

The scan output (`--format`) and the report (`--report`) are independent — you
can request both in one run.

## Configuration file

`--config FILE` loads settings from a small YAML file. See
[`../config.example.yaml`](../config.example.yaml) for the full annotated
schema. Precedence, highest first:

1. Explicit command-line flags.
2. Values in the config file.
3. Built-in defaults.

Positional CLI targets override the config's `targets` list.

## Web GUI

```
qphpscanner --web                       # http://127.0.0.1:8088/
qphpscanner --web --listen 0.0.0.0:9000 # bind elsewhere (use with care)
```

The GUI offers a form (targets, ports, depth, TLS, timeout, concurrency and
toggles), renders per-service result cards with colour-coded PHP verdicts,
evidence and vulnerability leads, and provides one-click downloads of the last
scan as JSON, XML, text, RTF or PDF. It is bound to localhost by default;
exposing it to a network makes a scan trigger available to anyone who can reach
it, so do so only on trusted networks.

### HTTP API

The GUI is backed by a tiny JSON API you can script against:

- `POST /api/scan` — body is a JSON object with the same fields as the form
  (`targets` array or `targets_text`, `ports`, `mode`, `tls`,
  `timeout_seconds`, `concurrency`, `follow_redirects`, `insecure`,
  `security_txt`, `include_closed`). Returns `{ "ok": true, "result": {...} }`.
- `GET /api/download?format=json|xml|text|rtf|pdf` — renders the most recent
  scan result.

## Exit status

- `0` — the scan completed (regardless of what was found).
- `1` — a fatal error (bad target/port spec, unreadable config, I/O error).

A one-line summary is printed to stderr after each scan.

## Examples

```sh
# Minimal: is it PHP?
qphpscanner example.com

# Deep scan with a PDF report
qphpscanner --mode deep --report-out audit.pdf https://example.com

# Subnet sweep, HTTPS only, JSON to file, no closed-port noise
qphpscanner --tls on --format json --out results.json 10.0.0.0/24

# Specific ports and a range, text report to stdout
qphpscanner --ports 80,443,8000-8010 --report text example.com

# IPv6 host, deep, ignore cert errors
qphpscanner --mode deep --insecure https://[2001:db8::1]:8443/

# Drive everything from a config file
qphpscanner --config scan.yaml

# Web GUI
qphpscanner --web
```

## Interpreting results

Each service gets a **verdict** derived from a weighted confidence score
(0–100):

| Verdict | Score | Meaning |
| --- | --- | --- |
| `confirmed` | ≥ 70 | strong, usually unambiguous PHP evidence |
| `likely` | 50–69 | multiple corroborating signals |
| `possible` | 25–49 | weak/circumstantial signals |
| `none` | < 25 | no meaningful PHP evidence |

Every contributing signal is listed as **evidence** with its weight and the raw
matched data, so you can audit *why* a verdict was reached.

**Vulnerability leads** are correlated from the detected version alone. They
indicate issues that *affect that version*, not that the host is exploitable —
many require a specific SAPI or configuration (noted in `match_basis`). Always
confirm against the live service before acting.
