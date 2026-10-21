# qphpscanner

A command-line and web tool, written in Go, that scans network ports and
HTTP(S) services to determine whether they are **built on PHP**, collects the
supporting **evidence**, and produces **reports**.

It is a passive fingerprinting and reporting tool in the spirit of
WhatWeb / Wappalyzer / httpx, focused specifically on PHP: it reads banners,
headers, cookies and response bodies and reasons about them. In **deep** mode
it also fingerprints the PHP version and variant, enumerates extensions and
server modules, flags end-of-life branches, and correlates **known
version-based vulnerabilities**. It never attempts to exploit anything.

> **Authorised use only.** Scan only hosts and networks you own or have
> explicit permission to test. Port scanning and service fingerprinting may be
> regulated where you operate.

## Features

- **PHP detection** from many signals: `X-Powered-By` / `Server` banners,
  `PHPSESSID` and framework session cookies, `.php`/`.phtml` URL extensions,
  PHP error/stack-trace output, CMS/framework markers (WordPress, Drupal,
  Joomla, Laravel, Symfony, Magento, TYPO3, phpBB, MediaWiki, …), exposed
  `phpinfo()`, exposed Composer manifests, and the classic `expose_php`
  easter-egg endpoints.
- **Version, variant, extensions & modules** (deep mode): PHP vs HHVM vs Zend
  Server; version from headers or `phpinfo()`; extensions (OPcache, Xdebug,
  ionCube, mysqli, curl, gd, …); web-server modules from the `Server` banner;
  end-of-life evaluation per release branch.
- **Vulnerability leads** (deep mode): a curated, version-correlated CVE
  catalogue (e.g. CVE-2024-4577, CVE-2019-11043, CVE-2012-1823). Leads are
  informational — correlated from the detected version, not confirmed by
  exploitation.
- **security.txt** (RFC 9116): discovers and parses `/.well-known/security.txt`
  and surfaces it in every output and report.
- **Flexible targets**: single URL, IPv4/IPv6 literal, CIDR block, dashed
  ranges (`1.2.3.4-9`, `1.2.3.4-1.2.3.9`), per-octet wildcards (`1.2.3.*`), and
  **DNS wildcards** (`*.example.com`) that enumerate subdomains via
  Certificate Transparency.
- **Flexible ports**: single, comma lists and ranges, mixable
  (`80,443,8000-8100`).
- **TLS control**: `auto` (infer from port), `on`, or `off`.
- **Two scan depths**: `detect` (is it PHP?) and `deep` (full fingerprint).
- **Live progress**: a running counter by default (updated in place on a
  terminal) and a `--verbose` mode that reports every host/port outcome;
  the web GUI shows a progress bar and a live feed.
- **Output formats**: plain **text**, **JSON**, **XML**.
- **Report formats**: **text**, **RTF**, **PDF** (both RTF and PDF are written
  by hand — see below).
- **YAML config file** support.
- **CLI *and* a web GUI** with a clean, usable interface and a collapsible
  history of previous scans.
- **Zero external dependencies** — the entire tool builds from the Go standard
  library, including the YAML parser and the RTF/PDF writers.

## Install

```sh
# from source (Go 1.24+)
git clone https://github.com/rom/qphpscanner
cd qphpscanner
make build          # produces bin/qphpscanner
# or install system-wide (binary + man page):
sudo make install
```

## Quick start

```sh
# Is this service PHP?
qphpscanner example.com

# Deep fingerprint a few ports, write a PDF report:
qphpscanner --mode deep --ports 80,443,8080 --report-out report.pdf example.com

# Scan a subnet, force HTTPS, emit JSON to a file:
qphpscanner --tls on --format json --out scan.json 10.0.0.0/28

# Enumerate subdomains of a domain and scan them, with per-host detail:
qphpscanner --verbose '*.example.com'

# Launch the web GUI:
qphpscanner --web           # then open http://127.0.0.1:8088/
```

## Usage overview

```
qphpscanner [options] <target> [target ...]
qphpscanner --web [--listen host:port]
qphpscanner --config scan.yaml
```

| Option | Description |
| --- | --- |
| `--mode detect\|deep` | scan depth (default `detect`) |
| `--ports SPEC` | `80` · `80,443` · `8000-8100` · mixed (default: common web ports) |
| `--tls auto\|on\|off` | TLS handling (default `auto`) |
| `--format text\|json\|xml` | scan output format (default `text`) |
| `--out FILE` | write scan output to a file |
| `--report text\|rtf\|pdf` | also produce a report |
| `--report-out FILE` | report destination (required for rtf/pdf) |
| `--timeout DUR` | per-connection timeout (e.g. `5s`) |
| `--concurrency N` | max concurrent probes (default 50) |
| `--follow` | follow redirects (default true) |
| `--insecure` | skip TLS verification |
| `--security-txt` | fetch security.txt (default true) |
| `--include-closed` | include closed ports in output |
| `--verbose` / `-v` | per-host/port progress detail |
| `--quiet` / `-q` | suppress progress output |
| `--no-dns-enum` | disable `*.domain` subdomain enumeration |
| `--config FILE` | load a YAML config |
| `--web` / `--listen` | run the web GUI / its address |
| `--version` | print version |

See [`docs/USAGE.md`](docs/USAGE.md) for the full reference and
[`docs/DESIGN.md`](docs/DESIGN.md) for architecture and detection internals.
A man page is in [`docs/qphpscanner.1`](docs/qphpscanner.1).

## Web GUI

`qphpscanner --web` serves a single-page interface (bound to localhost by
default) for configuring and running scans, browsing per-service results with
colour-coded PHP verdicts, evidence and vulnerability leads, and downloading
the results as JSON/XML/text or a RTF/PDF report. While a scan runs it shows a
**progress bar and a live feed** (the scan endpoint streams NDJSON), and each
completed scan is kept **below the current one as a collapsible entry** so you
can revisit earlier runs. All scan-derived text is inserted into the DOM as
text (never HTML), so hostile response data cannot be reflected into the page.

## Output & report formats

- **Scan output** (`--format`): `text`, `json`, `xml` — machine-readable
  records of every probed service.
- **Report** (`--report` / `--report-out`): `text`, `rtf`, `pdf` — a
  human-readable write-up with a summary, per-host sections, evidence and
  vulnerability leads. The RTF and PDF writers are self-contained (no external
  libraries), so reports work in any build environment.

## Development

```sh
make check      # gofmt check + go vet + tests
make test-race  # tests under the race detector
make dist       # cross-compile release binaries into dist/
```

## License

MIT — see [LICENSE](LICENSE).
