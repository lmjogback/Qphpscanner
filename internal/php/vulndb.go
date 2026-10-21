package php

// vulnEntry is one known issue plus a predicate over a parsed version.
type vulnEntry struct {
	ID          string
	Severity    string
	Title       string
	Affected    string
	Description string
	Reference   string
	Note        string // appended to MatchBasis when set
	match       func(maj, min, pat int) bool
}

// lessThan reports whether (maj.min.pat) < (a.b.c).
func lessThan(a, b, c int) func(maj, min, pat int) bool {
	return func(maj, min, pat int) bool {
		if maj != a {
			return maj < a
		}
		if min != b {
			return min < b
		}
		return pat < c
	}
}

// inBranchBelow reports whether the version is in branch a.b and its patch is
// below fix (i.e. a.b.x with x < fix).
func inBranchBelow(a, b, fix int) func(maj, min, pat int) bool {
	return func(maj, min, pat int) bool {
		return maj == a && min == b && pat < fix
	}
}

func anyOf(fns ...func(int, int, int) bool) func(int, int, int) bool {
	return func(maj, min, pat int) bool {
		for _, f := range fns {
			if f(maj, min, pat) {
				return true
			}
		}
		return false
	}
}

// vulnDB is a curated, non-exhaustive catalogue of high-signal, version-
// correlatable PHP CVEs. Matches are informational leads derived purely from a
// detected version string — not confirmed, exploited findings.
var vulnDB = []vulnEntry{
	{
		ID: "CVE-2024-4577", Severity: "critical",
		Title:    "PHP-CGI argument injection (regression of CVE-2012-1823)",
		Affected: "< 8.1.29, < 8.2.20, < 8.3.8 (Windows PHP-CGI; best-fit codepages)",
		Description: "Argument injection in php-cgi on Windows allows passing options to the PHP " +
			"interpreter, leading to source disclosure or remote code execution.",
		Reference: "https://nvd.nist.gov/vuln/detail/CVE-2024-4577",
		Note:      "Windows php-cgi deployments only",
		match: anyOf(
			inBranchBelow(8, 1, 29), inBranchBelow(8, 2, 20), inBranchBelow(8, 3, 8),
			lessThan(8, 1, 0),
		),
	},
	{
		ID: "CVE-2024-1874", Severity: "high",
		Title:    "proc_open() command injection via bat/cmd on Windows",
		Affected: "< 8.1.28, < 8.2.18, < 8.3.6",
		Description: "Arguments to proc_open() with bat/cmd wrappers on Windows can inject commands " +
			"when the program name is quoted.",
		Reference: "https://nvd.nist.gov/vuln/detail/CVE-2024-1874",
		Note:      "Windows only",
		match:     anyOf(inBranchBelow(8, 1, 28), inBranchBelow(8, 2, 18), inBranchBelow(8, 3, 6)),
	},
	{
		ID: "CVE-2024-3096", Severity: "medium",
		Title:    "password_verify() accepts strings with null bytes",
		Affected: "< 8.1.28, < 8.2.18, < 8.3.6",
		Description: "A password string with a leading null byte may be erroneously verified against " +
			"certain BCrypt hashes.",
		Reference: "https://nvd.nist.gov/vuln/detail/CVE-2024-3096",
		match:     anyOf(inBranchBelow(8, 1, 28), inBranchBelow(8, 2, 18), inBranchBelow(8, 3, 6)),
	},
	{
		ID: "CVE-2023-3824", Severity: "critical",
		Title:    "Buffer overflow in phar directory parsing",
		Affected: "< 8.0.30, < 8.1.22, < 8.2.8",
		Description: "A length-check error while loading phar files can cause a stack buffer overflow " +
			"leading to memory corruption or RCE.",
		Reference: "https://nvd.nist.gov/vuln/detail/CVE-2023-3824",
		match:     anyOf(inBranchBelow(8, 0, 30), inBranchBelow(8, 1, 22), inBranchBelow(8, 2, 8)),
	},
	{
		ID: "CVE-2023-0568", Severity: "medium",
		Title:       "Core path-resolution one-byte buffer overread",
		Affected:    "< 8.0.28, < 8.1.16, < 8.2.3",
		Description: "A one-byte out-of-bounds read in the path-resolution code.",
		Reference:   "https://nvd.nist.gov/vuln/detail/CVE-2023-0568",
		match:       anyOf(inBranchBelow(8, 0, 28), inBranchBelow(8, 1, 16), inBranchBelow(8, 2, 3)),
	},
	{
		ID: "CVE-2022-31626", Severity: "critical",
		Title:    "pdo_mysql buffer overflow (RCE)",
		Affected: "< 7.4.30, < 8.0.20, < 8.1.7",
		Description: "A buffer overflow in the pdo_mysql extension with an untrusted/malicious MySQL " +
			"server can lead to remote code execution.",
		Reference: "https://nvd.nist.gov/vuln/detail/CVE-2022-31626",
		match:     anyOf(inBranchBelow(7, 4, 30), inBranchBelow(8, 0, 20), inBranchBelow(8, 1, 7)),
	},
	{
		ID: "CVE-2022-31625", Severity: "high",
		Title:    "pgsql/pdo_pgsql memory corruption via parameter arrays",
		Affected: "< 7.4.30, < 8.0.20, < 8.1.7",
		Description: "Improper handling of parameter arrays in the pgsql/pdo_pgsql extensions can cause " +
			"memory corruption.",
		Reference: "https://nvd.nist.gov/vuln/detail/CVE-2022-31625",
		match:     anyOf(inBranchBelow(7, 4, 30), inBranchBelow(8, 0, 20), inBranchBelow(8, 1, 7)),
	},
	{
		ID: "CVE-2019-11043", Severity: "critical",
		Title:    "PHP-FPM underflow RCE (env_path_info)",
		Affected: "< 7.1.33, < 7.2.24, < 7.3.11",
		Description: "An underflow in fpm_main.c with certain nginx + PHP-FPM configurations allows " +
			"remote code execution (exploited in the wild).",
		Reference: "https://nvd.nist.gov/vuln/detail/CVE-2019-11043",
		Note:      "nginx + PHP-FPM with a vulnerable fastcgi_split_path_info config",
		match:     anyOf(inBranchBelow(7, 1, 33), inBranchBelow(7, 2, 24), inBranchBelow(7, 3, 11)),
	},
	{
		ID: "CVE-2018-17082", Severity: "medium",
		Title:       "XSS via Transfer-Encoding in the bundled Apache SAPI",
		Affected:    "< 5.6.38, < 7.0.32, < 7.1.22, < 7.2.10",
		Description: "The Apache2 component mishandles Transfer-Encoding allowing cross-site scripting.",
		Reference:   "https://nvd.nist.gov/vuln/detail/CVE-2018-17082",
		match: anyOf(
			inBranchBelow(5, 6, 38), inBranchBelow(7, 0, 32),
			inBranchBelow(7, 1, 22), inBranchBelow(7, 2, 10),
		),
	},
	{
		ID: "CVE-2015-4024", Severity: "high",
		Title:       "Multipart/form-data denial of service",
		Affected:    "< 5.4.41, < 5.5.25, < 5.6.9",
		Description: "Algorithmic complexity in multipart/form-data parsing enables a denial-of-service.",
		Reference:   "https://nvd.nist.gov/vuln/detail/CVE-2015-4024",
		match:       anyOf(inBranchBelow(5, 4, 41), inBranchBelow(5, 5, 25), inBranchBelow(5, 6, 9)),
	},
	{
		ID: "CVE-2012-1823", Severity: "critical",
		Title:    "php-cgi query-string argument injection (RCE/source disclosure)",
		Affected: "< 5.3.12, < 5.4.2 (php-cgi SAPI)",
		Description: "When run as a CGI, PHP treats query-string parameters without '=' as command-line " +
			"arguments, enabling source disclosure and remote code execution.",
		Reference: "https://nvd.nist.gov/vuln/detail/CVE-2012-1823",
		Note:      "php-cgi SAPI only",
		match:     anyOf(lessThan(5, 3, 12), inBranchBelow(5, 4, 2)),
	},
}

// eolBranch records the end of security support for a major.minor branch.
type eolBranch struct {
	securityEnd string // YYYY-MM-DD
}

// eolTable is indexed by "major.minor". Dates are PHP.net's published
// end-of-life dates for each release branch.
var eolTable = map[string]eolBranch{
	"5.4": {"2015-09-14"},
	"5.5": {"2016-07-21"},
	"5.6": {"2018-12-31"},
	"7.0": {"2019-01-10"},
	"7.1": {"2019-12-01"},
	"7.2": {"2020-11-30"},
	"7.3": {"2021-12-06"},
	"7.4": {"2022-11-28"},
	"8.0": {"2023-11-26"},
	"8.1": {"2025-12-31"},
	"8.2": {"2026-12-31"},
	"8.3": {"2027-12-31"},
	"8.4": {"2028-12-31"},
}
