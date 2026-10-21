# qphpscanner — Design

This document describes the architecture of `qphpscanner`, the PHP-detection
heuristics it uses, the scoring model, and the data schema shared by all output
formats.

## Goals and non-goals

**Goals**

- Decide, with auditable evidence, whether a network service is backed by PHP.
- Optionally fingerprint the PHP version, variant, extensions and server
  modules, and correlate known version-based vulnerabilities.
- Surface any published `security.txt`.
- Accept flexible targets and ports, emit multiple machine formats, and render
  human reports — from both a CLI and a web GUI.
- Build anywhere with **no external dependencies**.

**Non-goals**

- No exploitation, authentication bypass, fuzzing, or write operations. Every
  probe is a read-only GET.
- No brute force or large-scale untargeted scanning features.

## Package layout

```
cmd/qphpscanner      CLI entrypoint: flags, config merge, output/report wiring
internal/
  version            build metadata (overridable via -ldflags)
  target             target spec parsing/expansion (URL, IP, CIDR, range, wildcard)
  portspec           port spec parsing (single, list, range)
  probe              low-level TCP connect checks and bounded HTTP(S) fetches
  php                PHP detection, fingerprinting, vuln correlation (the core)
  securitytxt        RFC 9116 security.txt discovery and parsing
  scanner            orchestration: expand → connect → probe → analyse → aggregate
  report             rendering: text, JSON, XML, RTF, PDF (from one doc model)
  config             YAML-subset parser and typed configuration
  web                embedded single-page GUI + JSON API over the scanner
```

Dependencies flow one way: `scanner` imports `probe`, `php`, `securitytxt`,
`target`, `portspec`; `report` and `web` import `scanner`; `cmd` wires it all
together. There are no import cycles.

## Pipeline

```
targets ──► target.Expand ──► endpoints (host [+scheme/port/path])
                                   │
                        for each endpoint × port
                                   ▼
                        probe.CheckPort (TCP connect)
                                   │ open
                                   ▼
                 probe.Fetch root (scheme per --tls / URL / port)
                                   │
              ┌────────────────────┼─────────────────────────┐
              ▼                    ▼                          ▼
      php.Analyze(root)     deep: fetch probe paths     securitytxt lookup
                            + easter-egg endpoints
                                   ▼
                        scanner.ServiceResult
                                   ▼
                 aggregate by host ─► ScanResult ─► report.*
```

A bounded worker pool (`--concurrency`) runs the per-service work. Redirects
are followed manually so headers and cookies from **every hop** become
evidence; response bodies are read up to a byte cap.

## Detection model

Detection is **evidence-based and additive**. Each matched signal contributes a
weight; the confidence is the capped sum (0–100), mapped to a verdict band
(`confirmed` ≥ 70, `likely` ≥ 50, `possible` ≥ 25, else `none`). A service is
reported as PHP at confidence ≥ 50. Every signal is retained as an `Evidence`
record (signal id, source, human detail, raw data, weight) so a verdict is
always explainable, and each distinct signal is counted once.

### Signal categories

**Response headers**
- `X-Powered-By` advertising `PHP` (version parsed), `HHVM` (variant), or
  `ZendServer`.
- `Server` banner carrying `PHP/x.y.z` (version) and other tokens
  (`OpenSSL/…`, `mod_*`) reported as server modules.
- CMS/framework headers: `X-Generator: Drupal`, `X-Drupal-Cache`,
  `X-Redirect-By: WordPress`, `X-Pingback …/xmlrpc.php`, `Link: …api.w.org`,
  `X-Debug-Token` (Symfony), etc.

**Cookies** (collected across redirect hops)
- `PHPSESSID` / `PHPSESSION` — the default PHP session cookie.
- Framework session cookies: `laravel_session`, `symfony`, `ci_session`,
  `CAKEPHP`, `MoodleSession`, `wordpress_*`, `XDEBUG_SESSION`, `phpMyAdmin`, …

**URL**
- A `.php` / `.php5` / `.phtml` (etc.) path extension on the target.

**Response body**
- PHP error/stack-trace output (`<b>Fatal error</b> … in <b>…php</b>`,
  `Parse error: … on line N`, `Uncaught Error`, `PHP Warning:` …).
- CMS/framework markers: `wp-content`, `wp-json`, Drupal `/sites/…`, Joomla
  `option=com_`, Magento, `Illuminate\\` (Laravel), `Symfony\\Component`,
  phpBB, MediaWiki, TYPO3, PrestaShop.
- `<meta name="generator" …>` tags.
- Distinctive loader strings (ionCube, Zend Guard, Xdebug).

**Exposed diagnostics** (deep mode)
- `phpinfo()` output — detected by title/`PHP Version`/`Zend Engine`; the PHP
  version, extensions and variant are parsed from it.
- Readable `composer.json` / `composer.lock`.

**expose_php easter eggs** (deep mode)
- The credits GUID (`?=PHPB8B5F2A0-…`) returns a credits page, and the logo
  GUID (`?=PHPE9568F34-…`) returns an embedded image, on installations with
  `expose_php` on. These were removed in PHP 5.5, so a hit also bounds the
  version to `< 5.5`.

### Version, variant, extensions, modules

- **Version** precedence: `phpinfo()` > `X-Powered-By`/`Server` header >
  easter-egg range. Suffixes (`RC1`, `-dev`, `p1`) are tolerated.
- **Variant**: `PHP` (default), `HHVM`, or `Zend Server`.
- **Extensions** (PHP): parsed from `phpinfo()` (a curated catalogue of module
  names) plus loader strings and the "Zend Engine … with …" line.
- **Server modules**: tokens from the `Server` banner (`Apache/…`,
  `OpenSSL/…`, `mod_*`).
- **End of life**: the detected `major.minor` branch is compared against
  PHP.net's published security-support end dates relative to the current date.

### Vulnerability correlation

`internal/php/vulndb.go` holds a curated catalogue of high-signal,
version-correlatable PHP CVEs (e.g. CVE-2024-4577, CVE-2024-1874,
CVE-2023-3824, CVE-2022-31626, CVE-2019-11043, CVE-2012-1823). Each entry has a
predicate over the parsed `major.minor.patch`. Correlation runs only in deep
mode, only for the native PHP (and Zend Server) variant, and every result is
labelled with a `match_basis` noting any required SAPI/configuration (e.g.
"Windows php-cgi deployments only"). These are **leads derived from the version
string**, never confirmed exploited findings.

## Data schema

All formats serialise the same `ScanResult`:

```
ScanResult
├─ meta      { tool, version, mode, started_at, finished_at, duration_ms, ports[] }
├─ targets[] { host, inputs[], services[] }
│    └─ service { host, port, tls, scheme, url, port_open, error,
│                 http   { status, proto, server, powered_by, title,
│                          content_type, redirects, tls{…}, headers{} },
│                 php    { is_php, verdict, confidence, variant, version,
│                          version_source, end_of_life, eol_detail,
│                          frameworks[], extensions[], modules[],
│                          phpinfo_exposed, phpinfo_url,
│                          evidence[]{signal,source,detail,data,weight},
│                          vulnerabilities[]{id,severity,title,
│                              affected_versions,description,reference,match_basis} },
│                 security_txt { present, url, signed, contact[], expires,
│                          expired, encryption[], acknowledgments[],
│                          preferred_languages[], canonical[], policy[],
│                          hiring[], csaf[] } }
└─ summary   { hosts_scanned, services_probed, open_ports, http_services,
               php_confirmed, php_likely, php_possible, vulnerabilities,
               security_txt }
```

JSON and XML emit this directly (XML is rooted at `<scan>`; maps are omitted as
XML cannot represent them). Text, RTF and PDF are produced from a single
intermediate **document model** (`internal/report/doc.go`) of headings, key/
value rows, bullets and rules, so the three human formats stay consistent.

## Self-contained RTF and PDF

To avoid third-party dependencies, both writers are implemented directly:

- **RTF** — emits an `{\rtf1 …}` document with Helvetica, bold headings, sized
  text and bullet paragraphs; control characters are escaped and non-ASCII is
  encoded as `\uN?`.
- **PDF** — a minimal PDF 1.4 generator (`internal/report/pdfwriter.go`): US
  Letter pages of left-aligned text in the standard Helvetica / Helvetica-Bold
  fonts (no embedding), with word wrapping, pagination, horizontal rules and a
  correct cross-reference table and trailer.

## Configuration

`internal/config` includes a deliberately small YAML-subset parser (comments,
space-indented nested maps, scalar key/values, block lists of scalars, quoted
scalars; tabs rejected). It is sufficient for the documented schema and keeps
the tool dependency-free. Booleans are parsed as pointers so the CLI can tell
"unset in config" from "explicitly false" when merging flag precedence.

## Security considerations

- The tool only reads; it never submits forms or attempts exploitation.
- The web GUI binds to localhost by default and inserts all scan-derived text
  into the DOM as text, never HTML, so hostile response content cannot be
  reflected into the operator's browser. Request bodies are size-capped and the
  server-side scan is time-bounded.
- Response bodies are read up to a byte cap to bound memory.
- Target expansion is capped per spec to prevent accidental massive sweeps.
