package php

import "regexp"

var (
	reVersion        = regexp.MustCompile(`(?i)php/(\d+\.\d+(?:\.\d+)?)`)
	reHHVM           = regexp.MustCompile(`(?i)hhvm/(\d+\.\d+(?:\.\d+)?)`)
	rePHPInfoVersion = regexp.MustCompile(`(?i)PHP Version (\d+\.\d+\.\d+[A-Za-z0-9.\-]*)`)
	reGenerator      = regexp.MustCompile(`(?is)<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']`)
	reZendEngineLine = regexp.MustCompile(`(?i)Zend Engine v[\d.]+(?:,\s*(?:with|Copyright)[^<\n]*)?`)
	// Loader/engine add-on line fragments that phpinfo prints.
	reWithLoaders = regexp.MustCompile(`(?i)with (the ionCube PHP Loader|Zend OPcache|Xdebug|Zend Guard Loader|Suhosin[- ]Patch|eAccelerator)[^,<\n]*`)
)

type matchKind int

const (
	matchExact matchKind = iota
	matchPrefix
)

// cookieSig maps a cookie name to the technology it implies.
type cookieSig struct {
	name      string
	kind      matchKind
	framework string // "" means it only implies PHP generally
	weight    int
	detail    string
}

var cookieSigs = []cookieSig{
	{"PHPSESSID", matchExact, "", 70, "default PHP session cookie"},
	{"PHPSESSION", matchExact, "", 60, "PHP session cookie"},
	{"laravel_session", matchExact, "Laravel", 65, "Laravel session cookie"},
	{"laravel_token", matchExact, "Laravel", 55, "Laravel token cookie"},
	{"remember_web_", matchPrefix, "Laravel", 45, "Laravel remember-me cookie"},
	{"symfony", matchExact, "Symfony", 55, "Symfony session cookie"},
	{"sf_redirect", matchExact, "Symfony", 45, "Symfony redirect cookie"},
	{"ci_session", matchExact, "CodeIgniter", 60, "CodeIgniter session cookie"},
	{"CAKEPHP", matchExact, "CakePHP", 60, "CakePHP session cookie"},
	{"yii", matchPrefix, "Yii", 45, "Yii framework cookie"},
	{"_identity", matchPrefix, "Yii", 35, "Yii identity cookie"},
	{"wordpress_", matchPrefix, "WordPress", 55, "WordPress auth cookie"},
	{"wp-settings-", matchPrefix, "WordPress", 55, "WordPress settings cookie"},
	{"wordpress_logged_in_", matchPrefix, "WordPress", 60, "WordPress logged-in cookie"},
	{"MoodleSession", matchExact, "Moodle", 60, "Moodle session cookie"},
	{"fuel_csrf_token", matchExact, "FuelPHP", 55, "FuelPHP CSRF cookie"},
	{"frontend", matchExact, "Magento", 35, "Magento frontend cookie"},
	{"XDEBUG_SESSION", matchExact, "", 40, "Xdebug session cookie (debugger enabled)"},
	{"adminer_", matchPrefix, "Adminer", 40, "Adminer database tool cookie"},
	{"phpMyAdmin", matchExact, "phpMyAdmin", 55, "phpMyAdmin session cookie"},
	{"pmaUser-", matchPrefix, "phpMyAdmin", 55, "phpMyAdmin user cookie"},
}

// headerSig matches a header value, optionally by substring.
type headerSig struct {
	header     string
	contains   string // case-insensitive substring; "" means "present at all"
	framework  string
	phpImplied bool
	variant    string
	weight     int
	detail     string
}

var headerSigs = []headerSig{
	{"X-Powered-By", "php", "", true, "PHP", 80, "X-Powered-By advertises PHP"},
	{"X-Powered-By", "hhvm", "", true, "HHVM", 80, "X-Powered-By advertises HHVM (PHP-compatible runtime)"},
	{"X-Powered-By", "zendserver", "", true, "Zend Server", 70, "Zend Server runtime"},
	{"X-Powered-By", "w3 total cache", "WordPress", true, "", 55, "W3 Total Cache (WordPress plugin)"},
	{"X-Powered-By", "shopware", "Shopware", true, "", 60, "Shopware e-commerce (PHP)"},
	{"X-Powered-By", "nette", "Nette", true, "", 55, "Nette Framework (PHP)"},
	{"X-Generator", "drupal", "Drupal", true, "", 60, "Drupal generator header"},
	{"X-Drupal-Cache", "", "Drupal", true, "", 55, "Drupal page cache header"},
	{"X-Drupal-Dynamic-Cache", "", "Drupal", true, "", 55, "Drupal dynamic cache header"},
	{"X-Redirect-By", "wordpress", "WordPress", true, "", 55, "WordPress redirect header"},
	{"X-Pingback", "xmlrpc.php", "WordPress", true, "", 50, "WordPress XML-RPC pingback endpoint"},
	{"X-Powered-CMS", "", "", false, "", 25, "CMS advertised via X-Powered-CMS"},
	{"Link", "api.w.org", "WordPress", true, "", 45, "WordPress REST API link relation"},
	{"X-Debug-Token", "", "Symfony", true, "", 45, "Symfony web profiler debug token"},
	{"X-Debug-Token-Link", "", "Symfony", true, "", 45, "Symfony web profiler link"},
	{"X-Powered-By", "ioncube", "", true, "", 40, "ionCube PHP Loader advertised"},
	{"Set-Cookie", "phpsessid", "", true, "PHP", 70, "PHP session cookie in Set-Cookie"},
}

// bodySig matches distinctive content in a response body.
type bodySig struct {
	id         string
	re         *regexp.Regexp
	framework  string
	phpImplied bool
	weight     int
	detail     string
}

var bodySigs = []bodySig{
	{"body.php-fatal", regexp.MustCompile(`(?i)<b>Fatal error</b>:.*?in <b>.*?\.php</b>`), "", true, 65, "PHP fatal error with .php source path"},
	{"body.php-warning", regexp.MustCompile(`(?i)<b>Warning</b>:.*?in <b>.*?\.php</b>`), "", true, 55, "PHP warning with .php source path"},
	{"body.php-notice", regexp.MustCompile(`(?i)<b>(Notice|Deprecated)</b>:.*?in <b>.*?\.php</b>`), "", true, 50, "PHP notice/deprecation with .php source path"},
	{"body.php-parse", regexp.MustCompile(`(?i)Parse error:.*?in .*?\.php on line \d+`), "", true, 55, "PHP parse error"},
	{"body.php-uncaught", regexp.MustCompile(`(?i)(Uncaught (Error|Exception)|Stack trace:).*?\.php`), "", true, 50, "PHP uncaught exception / stack trace"},
	{"body.php-undefined-fn", regexp.MustCompile(`(?i)Call to undefined (function|method) .*?\(\)`), "", true, 45, "PHP undefined function/method error"},
	{"body.php-call-stack", regexp.MustCompile(`(?i)PHP (Warning|Notice|Fatal error|Deprecated):`), "", true, 50, "PHP log-style diagnostic line"},
	{"body.wp-content", regexp.MustCompile(`(?i)/wp-(content|includes)/`), "WordPress", true, 50, "WordPress asset paths"},
	{"body.wp-json", regexp.MustCompile(`(?i)/wp-json/`), "WordPress", true, 45, "WordPress REST route"},
	{"body.drupal", regexp.MustCompile(`(?i)/sites/(default|all)/(files|modules|themes)/`), "Drupal", true, 50, "Drupal site paths"},
	{"body.joomla", regexp.MustCompile(`(?i)/media/(jui|system)/js/|option=com_`), "Joomla", true, 50, "Joomla media/component paths"},
	{"body.magento", regexp.MustCompile(`(?i)/(skin/frontend|static/version\d+)/|Magento_`), "Magento", true, 50, "Magento asset paths"},
	{"body.laravel", regexp.MustCompile(`(?i)Illuminate\\|laravel_session|window\.Laravel`), "Laravel", true, 45, "Laravel runtime markers"},
	{"body.symfony", regexp.MustCompile(`(?i)Symfony\\Component|sf-toolbar`), "Symfony", true, 45, "Symfony runtime markers"},
	{"body.phpbb", regexp.MustCompile(`(?i)Powered by phpBB`), "phpBB", true, 55, "phpBB forum"},
	{"body.mediawiki", regexp.MustCompile(`(?i)<meta name="generator" content="MediaWiki`), "MediaWiki", true, 50, "MediaWiki generator"},
	{"body.prestashop", regexp.MustCompile(`(?i)PrestaShop|/themes/.*?/assets/`), "PrestaShop", true, 40, "PrestaShop markers"},
	{"body.typo3", regexp.MustCompile(`(?i)/typo3(conf|temp)/|TYPO3 CMS`), "TYPO3", true, 50, "TYPO3 CMS paths"},
}

// loaderBodyTokens are distinctive enough to detect in any body, not just
// phpinfo output.
var loaderBodyTokens = []struct {
	token  string
	module string
	detail string
}{
	{"ionCube", "ionCube Loader", "ionCube encoder/loader present"},
	{"Zend Guard", "Zend Guard Loader", "Zend Guard protected code"},
	{"Xdebug", "xdebug", "Xdebug diagnostic output"},
}

// phpInfoModules is the extension/module catalogue scanned inside phpinfo
// output, where these short names are unambiguous.
var phpInfoModules = []string{
	"bcmath", "bz2", "calendar", "ctype", "curl", "dom", "exif", "fileinfo",
	"filter", "ftp", "gd", "gettext", "gmp", "hash", "iconv", "igbinary",
	"imap", "intl", "json", "ldap", "mbstring", "mysqli", "mysqlnd",
	"openssl", "pcntl", "pcre", "pdo_mysql", "pdo_pgsql", "pdo_sqlite",
	"pgsql", "Phar", "posix", "readline", "redis", "Reflection", "session",
	"shmop", "SimpleXML", "soap", "sockets", "sodium", "SPL", "sqlite3",
	"tokenizer", "xml", "xmlreader", "xmlrpc", "xmlwriter", "xsl", "zip",
	"zlib", "Zend OPcache", "opcache", "xdebug", "ionCube Loader", "Suhosin",
	"imagick", "memcached", "memcache", "apcu", "mongodb", "amqp", "swoole",
	"ssh2", "yaml", "maxminddb", "protobuf", "grpc",
}

// phpExtensions returns the subset of module names considered "extensions"
// for reporting; here modules and extensions are reported from the same scan,
// but kept as separate output fields for clarity and future divergence.
