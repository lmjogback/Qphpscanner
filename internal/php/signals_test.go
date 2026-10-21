package php

import (
	"testing"

	"github.com/rom/qphpscanner/internal/probe"
)

func TestApacheSignatureVersion(t *testing.T) {
	body := `<html><body><h1>Not Found</h1><hr>` +
		`<address>Apache/2.4.29 (Ubuntu) PHP/7.2.34 Server at example.com Port 80</address>` +
		`</body></html>`
	d := Analyze(Input{TargetURL: "http://h/missing", Root: resp(404, nil, nil, body)})
	if !d.IsPHP {
		t.Fatalf("Apache signature should indicate PHP (conf %d)", d.Confidence)
	}
	if d.Version != "7.2.34" {
		t.Fatalf("version from signature: %q", d.Version)
	}
}

func TestPHPSourceLeak(t *testing.T) {
	d := Analyze(Input{TargetURL: "http://h/", Root: resp(200, nil, nil, "<?php echo 'hi'; ?>")})
	if !d.IsPHP {
		t.Fatal("leaked PHP source should indicate PHP")
	}
	if !hasEvidence(d, "body.php-source-leak") {
		t.Fatalf("source-leak evidence missing: %+v", d.Evidence)
	}
}

func TestPoweredByFooter(t *testing.T) {
	d := Analyze(Input{TargetURL: "http://h/", Root: resp(200, nil, nil, "<footer>Powered by Discuz! X3.4</footer>")})
	if !hasStr(d.Frameworks, "Discuz") {
		t.Fatalf("expected Discuz framework: %v", d.Frameworks)
	}
}

func TestTYPO3Cookie(t *testing.T) {
	d := Analyze(Input{TargetURL: "http://h/", Root: resp(200, nil, []string{"fe_typo_user"}, "")})
	if !hasStr(d.Frameworks, "TYPO3") {
		t.Fatalf("expected TYPO3: %v", d.Frameworks)
	}
}

func TestStatusDashboards(t *testing.T) {
	in := Input{
		TargetURL: "http://h/",
		Deep:      true,
		Root:      resp(200, map[string]string{"X-Powered-By": "PHP/8.2.0"}, nil, ""),
		Extra: map[string]*probe.Response{
			"http://h/opcache.php": resp(200, nil, nil, "<html>OPcache statistics: opcache_get_status()</html>"),
			"http://h/apcu.php":    resp(200, nil, nil, "APCu Version 5.1.0 apcu_cache_info"),
			"http://h/adminer.php": resp(200, nil, nil, "<html><title>Adminer</title><form>Login</form></html>"),
			"http://h/phpmyadmin/": resp(200, nil, nil, "<html>phpMyAdmin pma_ welcome</html>"),
		},
	}
	d := Analyze(in)
	if !hasStr(d.Extensions, "Zend OPcache") || !hasStr(d.Extensions, "apcu") {
		t.Fatalf("expected opcache+apcu extensions: %v", d.Extensions)
	}
	if !hasStr(d.Addons, "Adminer") || !hasStr(d.Addons, "phpMyAdmin") {
		t.Fatalf("expected Adminer+phpMyAdmin addons: %v", d.Addons)
	}
}

func TestPathInfoSignal(t *testing.T) {
	in := Input{
		TargetURL: "http://h/",
		Deep:      true,
		Root:      resp(200, map[string]string{"X-Powered-By": "PHP/8.2.0"}, nil, ""),
		PathInfo:  resp(200, nil, nil, "handled"),
	}
	d := Analyze(in)
	if !hasEvidence(d, "behavior.path-info") {
		t.Fatalf("expected path-info evidence: %+v", d.Evidence)
	}
}

func TestSAPIInference(t *testing.T) {
	apache := Analyze(Input{TargetURL: "http://h/", Root: resp(200, map[string]string{
		"Server": "Apache/2.4.41 (Ubuntu) PHP/7.4.3", "X-Powered-By": "PHP/7.4.3",
	}, []string{"PHPSESSID"}, "")})
	if apache.SAPI != "apache (mod_php)" {
		t.Fatalf("apache SAPI: %q", apache.SAPI)
	}
	nginx := Analyze(Input{TargetURL: "http://h/", Root: resp(200, map[string]string{
		"Server": "nginx/1.25.3", "X-Powered-By": "PHP/8.2.0",
	}, []string{"PHPSESSID"}, "")})
	if nginx.SAPI != "php-fpm (behind nginx)" {
		t.Fatalf("nginx SAPI: %q", nginx.SAPI)
	}
}

func TestAddonPartition(t *testing.T) {
	d := Analyze(Input{TargetURL: "http://h/", Root: resp(200, map[string]string{"X-Powered-By": "PHP/8.2.0"}, nil,
		`<script src="/vendor/phpdebugbar/debugbar.js"></script>`)})
	if !hasStr(d.Addons, "Laravel Debugbar") {
		t.Fatalf("debugbar should be an addon: addons=%v frameworks=%v", d.Addons, d.Frameworks)
	}
	if hasStr(d.Frameworks, "Laravel Debugbar") {
		t.Fatal("addon should not also be listed as a framework")
	}
}
