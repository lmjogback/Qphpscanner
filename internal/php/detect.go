package php

import (
	"sort"
	"strings"

	"github.com/rom/qphpscanner/internal/probe"
)

// Input bundles everything Analyze needs about one HTTP(S) service.
type Input struct {
	// TargetURL is the primary scheme://host:port/path that was requested.
	TargetURL string
	// Deep enables version/extension/module fingerprinting and vuln
	// correlation. When false, Analyze stops at the PHP yes/no verdict.
	Deep bool
	// Root is the response to the primary request. Required.
	Root *probe.Response
	// Extra holds deep-mode probe responses keyed by requested URL.
	Extra map[string]*probe.Response
	// Easter* are the expose_php easter-egg probe responses (deep mode).
	EasterCredits *probe.Response
	EasterLogo    *probe.Response
}

const maxDataLen = 200

// Analyze turns collected responses into a PHP Detection.
func Analyze(in Input) *Detection {
	if in.Root == nil {
		return nil
	}

	d := &Detection{}
	seen := map[string]bool{}
	fwSet := map[string]bool{}
	extSet := map[string]bool{}
	modSet := map[string]bool{}
	var versionRank int // 3 phpinfo, 2 header, 1 easter/body

	addEv := func(ev Evidence) {
		// De-duplicate by signal: the same signal seen on several deep-mode
		// probe URLs should count and display only once.
		if seen[ev.Signal] {
			return
		}
		seen[ev.Signal] = true
		if len(ev.Data) > maxDataLen {
			ev.Data = ev.Data[:maxDataLen] + "…"
		}
		d.Evidence = append(d.Evidence, ev)
		d.Confidence += ev.Weight
	}
	addFw := func(f string) {
		if f == "" || fwSet[f] {
			return
		}
		fwSet[f] = true
		d.Frameworks = append(d.Frameworks, f)
	}
	addExt := func(e string) {
		key := strings.ToLower(e)
		if e == "" || extSet[key] {
			return
		}
		extSet[key] = true
		d.Extensions = append(d.Extensions, e)
	}
	addMod := func(m string) {
		if m == "" || modSet[m] {
			return
		}
		modSet[m] = true
		d.Modules = append(d.Modules, m)
	}
	setVersion := func(v, source string, rank int) {
		if v == "" || rank <= versionRank {
			return
		}
		d.Version = v
		d.VersionSource = source
		versionRank = rank
	}
	setVariant := func(v string) {
		if v != "" && d.Variant == "" {
			d.Variant = v
		}
	}

	// --- Primary response ---------------------------------------------------
	analyzeResponse(in.Root, in.TargetURL, addEv, addFw, addExt, addMod, setVersion, setVariant)

	// --- URL extension hint -------------------------------------------------
	if u := strings.ToLower(in.TargetURL); hasPHPExtension(u) {
		addEv(Evidence{
			Signal: "url.php-extension", Source: in.TargetURL, Weight: 40,
			Detail: "Requested path uses a PHP file extension",
		})
	}

	// --- Deep probes --------------------------------------------------------
	for url, resp := range in.Extra {
		if resp == nil || resp.Err != "" {
			continue
		}
		analyzeResponse(resp, url, addEv, addFw, addExt, addMod, setVersion, setVariant)

		body := resp.BodyString()
		if resp.Status == 200 && isPHPInfo(body) {
			d.PHPInfoExposed = true
			d.PHPInfoURL = url
			addEv(Evidence{
				Signal: "diag.phpinfo", Source: url, Weight: 90,
				Detail: "phpinfo() output is publicly exposed",
			})
			if m := rePHPInfoVersion.FindStringSubmatch(body); m != nil {
				setVersion(m[1], "phpinfo()", 3)
			}
			parsePHPInfoModules(body, addExt, setVariant)
		}
		if resp.Status == 200 && isComposerManifest(url, body) {
			addEv(Evidence{
				Signal: "diag.composer", Source: url, Weight: 45,
				Detail: "Composer manifest/lock is publicly readable (PHP project)",
			})
		}
	}

	// --- Easter eggs --------------------------------------------------------
	analyzeEasterEggs(in, addEv, setVersion)

	// --- Finalise -----------------------------------------------------------
	if d.Confidence > 100 {
		d.Confidence = 100
	}
	d.Verdict = scoreToVerdict(d.Confidence)
	d.IsPHP = d.Confidence >= 50
	if d.IsPHP && d.Variant == "" {
		d.Variant = "PHP"
	}

	sort.Strings(d.Frameworks)
	sort.Strings(d.Extensions)
	sort.Strings(d.Modules)
	sortEvidence(d.Evidence)

	if in.Deep && d.IsPHP {
		d.EndOfLife, d.EOLDetail = evaluateEOL(d.Variant, d.Version)
		d.Vulnerabilities = CorrelateVulns(d.Variant, d.Version)
	}

	return d
}

// analyzeResponse extracts header, cookie and body evidence from one response.
func analyzeResponse(
	resp *probe.Response,
	source string,
	addEv func(Evidence),
	addFw func(string),
	addExt func(string),
	addMod func(string),
	setVersion func(string, string, int),
	setVariant func(string),
) {
	if resp == nil || resp.Err != "" {
		return
	}

	// Header-based signatures.
	for _, sig := range headerSigs {
		for _, val := range resp.HeaderValues(sig.header) {
			if sig.contains == "" || containsFold(val, sig.contains) {
				addEv(Evidence{
					Signal: "header." + strings.ToLower(sig.header),
					Source: source, Weight: sig.weight, Detail: sig.detail, Data: val,
				})
				addFw(sig.framework)
				if sig.variant != "" {
					setVariant(sig.variant)
				}
				break
			}
		}
	}

	// Version from X-Powered-By / Server.
	for _, h := range []string{"X-Powered-By", "Server"} {
		for _, val := range resp.HeaderValues(h) {
			if m := reVersion.FindStringSubmatch(val); m != nil {
				setVersion(m[1], h+" header", 2)
				setVariant("PHP")
			}
			if m := reHHVM.FindStringSubmatch(val); m != nil {
				setVersion(m[1], h+" header (HHVM)", 2)
				setVariant("HHVM")
			}
		}
	}

	// Server header modules (mod_php, OpenSSL/..., PHP/...).
	for _, val := range resp.HeaderValues("Server") {
		for _, tok := range strings.Fields(val) {
			if strings.HasPrefix(tok, "mod_") || strings.Contains(tok, "/") {
				tok = strings.Trim(tok, "()")
				if tok != "" {
					addMod(tok)
				}
			}
		}
	}

	// Cookie-based signatures.
	for _, c := range resp.Cookies {
		for _, sig := range cookieSigs {
			if cookieMatch(c.Name, sig) {
				addEv(Evidence{
					Signal: "cookie." + strings.ToLower(strings.Trim(sig.name, "_-")),
					Source: source, Weight: sig.weight, Detail: sig.detail, Data: c.Name,
				})
				addFw(sig.framework)
			}
		}
	}

	// Body-based signatures.
	body := resp.BodyString()
	if body != "" {
		for _, sig := range bodySigs {
			if loc := sig.re.FindString(body); loc != "" {
				addEv(Evidence{
					Signal: sig.id, Source: source, Weight: sig.weight,
					Detail: sig.detail, Data: strings.TrimSpace(loc),
				})
				addFw(sig.framework)
			}
		}
		for _, lt := range loaderBodyTokens {
			if containsFold(body, lt.token) {
				addExt(lt.module)
			}
		}
		if m := reGenerator.FindStringSubmatch(body); m != nil {
			gen := m[1]
			addEv(Evidence{
				Signal: "body.generator", Source: source, Weight: 20,
				Detail: "HTML generator meta tag", Data: gen,
			})
			addFw(frameworkFromGenerator(gen))
		}
	}
}

func analyzeEasterEggs(in Input, addEv func(Evidence), setVersion func(string, string, int)) {
	if c := in.EasterCredits; c != nil && c.Err == "" && c.Status == 200 {
		b := c.BodyString()
		if containsFold(b, "PHP Credits") || containsFold(b, "Zend Engine") || containsFold(b, "PHP Group") {
			addEv(Evidence{
				Signal: "easter-egg.credits", Source: c.FinalURL, Weight: 85,
				Detail: "expose_php easter-egg credits page served (PHP < 5.5, expose_php On)",
			})
		}
	}
	if l := in.EasterLogo; l != nil && l.Err == "" && l.Status == 200 {
		ct := strings.ToLower(l.HeaderGet("Content-Type"))
		if strings.HasPrefix(ct, "image/") && len(l.Body) > 0 && len(l.Body) < 20000 {
			addEv(Evidence{
				Signal: "easter-egg.logo", Source: l.FinalURL, Weight: 80,
				Detail: "expose_php easter-egg logo image served (PHP < 5.5, expose_php On)",
				Data:   "Content-Type: " + l.HeaderGet("Content-Type"),
			})
		}
	}
}

func parsePHPInfoModules(body string, addExt func(string), setVariant func(string)) {
	lower := strings.ToLower(body)
	for _, mod := range phpInfoModules {
		if strings.Contains(lower, strings.ToLower(mod)) {
			addExt(mod)
		}
	}
	if containsFold(body, "HipHop") || containsFold(body, "HHVM") {
		setVariant("HHVM")
	} else if containsFold(body, "Zend Server") {
		setVariant("Zend Server")
	}
	if m := reWithLoaders.FindAllStringSubmatch(body, -1); m != nil {
		for _, g := range m {
			addExt(strings.TrimSpace(g[1]))
		}
	}
}

func cookieMatch(name string, sig cookieSig) bool {
	switch sig.kind {
	case matchPrefix:
		return strings.HasPrefix(strings.ToLower(name), strings.ToLower(sig.name))
	default:
		return strings.EqualFold(name, sig.name)
	}
}

func frameworkFromGenerator(gen string) string {
	g := strings.ToLower(gen)
	switch {
	case strings.Contains(g, "wordpress"):
		return "WordPress"
	case strings.Contains(g, "joomla"):
		return "Joomla"
	case strings.Contains(g, "drupal"):
		return "Drupal"
	case strings.Contains(g, "mediawiki"):
		return "MediaWiki"
	case strings.Contains(g, "typo3"):
		return "TYPO3"
	case strings.Contains(g, "prestashop"):
		return "PrestaShop"
	default:
		return ""
	}
}

func isComposerManifest(url, body string) bool {
	u := strings.ToLower(url)
	if !strings.Contains(u, "composer.json") && !strings.Contains(u, "composer.lock") {
		return false
	}
	return strings.Contains(body, "\"require\"") ||
		strings.Contains(body, "\"packages\"") ||
		strings.Contains(body, "\"name\"")
}

func hasPHPExtension(u string) bool {
	// Trim query/fragment.
	if i := strings.IndexAny(u, "?#"); i >= 0 {
		u = u[:i]
	}
	for _, ext := range []string{".php", ".php3", ".php4", ".php5", ".php7", ".phtml", ".phps"} {
		if strings.HasSuffix(u, ext) {
			return true
		}
	}
	return false
}

func contains(haystack, needle string) bool { return strings.Contains(haystack, needle) }

func containsFold(haystack, needle string) bool {
	return strings.Contains(strings.ToLower(haystack), strings.ToLower(needle))
}

func sortEvidence(ev []Evidence) {
	sort.SliceStable(ev, func(i, j int) bool {
		if ev[i].Weight != ev[j].Weight {
			return ev[i].Weight > ev[j].Weight
		}
		return ev[i].Signal < ev[j].Signal
	})
}
