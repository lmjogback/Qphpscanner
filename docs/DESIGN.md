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
                     — catalog.go (data-driven vuln/EOL catalogue + feed loader),
                     vulndb.go (built-in data), cms.go (CMS version detection),
                     favicon.go (mmh3 favicon hash)
  securitytxt        RFC 9116 security.txt discovery and parsing
  dnsenum            subdomain discovery for "*.domain" via Certificate Transparency
  scanner            orchestration: expand → connect → probe → analyse → aggregate;
                     enrich.go (DNS, jitter, per-host gate), checkpoint.go (resume)
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

**DNS wildcards.** A `*.example.com` target is expanded before scanning by the
`dnsenum` package, which queries Certificate Transparency (crt.sh) for names
issued under the domain, normalises and de-duplicates them, and optionally
filters to names that resolve. The resulting hosts are scanned like any other.

**Progress.** `scanner.Options.OnProgress` receives `ProgressEvent`s: one per
enumeration step and one per completed service probe (carrying a monotonic
`done`/`total` counter, the host/port, open state and any PHP verdict). The
scanner serialises these callbacks. The CLI renders them as an in-place counter
or, with `--verbose`, a line per service; the web server forwards each event to
the browser as a line of NDJSON, ending with the final result.

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

### Vulnerability correlation and feeds

The vulnerability data is a **data-driven catalogue** (`internal/php/catalog.go`
+ `vulndb.go`): each entry is a `FeedEntry` with one or more `RangeSpec`
affected ranges (`branch` / `introduced` / `fixed` / `lt`), matched against the
parsed version. The built-in catalogue holds ~40 high-signal PHP-core CVEs plus
famous CMS-core CVEs (Drupalgeddon2, WordPress/Joomla core), keyed by framework.

External **feeds** (JSON, schema `qphpscanner-vuln-feed/1`) are loaded from a
file or URL and `Merge`d on top of the built-in data, overriding EOL dates by
branch — so the catalogue can be kept current without rebuilding. The feed
format is the same `FeedEntry`/`RangeSpec` model exposed as JSON.

CMS core versions are detected (`cms.go`) from generator meta tags,
`readme.html`, `CHANGELOG.txt` and Joomla manifests, then correlated against
the CMS catalogue. Correlation runs only in deep mode; PHP-core entries apply
only to the native PHP/Zend Server variant. Every result carries a `match_basis`
noting any required SAPI/configuration. These are **leads derived from the
version string**, never confirmed exploited findings.

### Enrichment, politeness and resume

A global token-bucket `Limiter` in the probe layer caps requests per second;
per-host concurrency and jitter are enforced in the scanner's worker loop;
transient failures are retried with backoff. Hosts are optionally resolved
(forward + reverse DNS), and open non-HTTP ports yield a short grabbed banner.
A checkpoint file records each completed service as NDJSON so an interrupted
scan resumes by skipping finished work. Requests can carry custom headers,
Basic/Bearer/cookie auth and a Host override, and route through an http(s) or
SOCKS5 proxy (a minimal dependency-free SOCKS5 client).

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

(Per-service results also carry `banner`, and the PHP block adds
`framework_versions` and `favicon_hash`; targets carry resolved `addresses` and
`ptr` names.)

JSON and XML emit this directly (XML is rooted at `<scan>`; maps are omitted as
XML cannot represent them). CSV flattens one row per service; SARIF 2.1.0
exposes findings (CVEs, EOL, exposed phpinfo) as results with rules for CI
ingestion; NDJSON streams one object per service. Text, RTF, PDF and HTML are
produced from a single intermediate **document model**
(`internal/report/doc.go`) of headings, key/value rows, bullets and rules, so
the human formats stay consistent. `report.Diff` compares two results, and
`report.FailOn` powers `--fail-on` severity/EOL gating.

## Self-contained RTF, PDF and HTML

To avoid third-party dependencies, the writers are implemented directly (HTML
is rendered from the same document model with inline, theme-aware CSS):

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
- Subdomain enumeration reads only public Certificate Transparency data; it
  does not brute-force DNS or probe the target during discovery.
