package config

import (
	"os"
	"path/filepath"
	"testing"
)

func loadString(t *testing.T, content string) (*Config, error) {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "c.yaml")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return Load(p)
}

func TestInlineTargetsAndBoolVariants(t *testing.T) {
	c, err := loadString(t, "targets: a.com, b.com\ninsecure: yes\nsecurity_txt: off\nweb:\n  enabled: 1\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Targets) != 2 {
		t.Fatalf("inline targets: %v", c.Targets)
	}
	if c.Insecure == nil || !*c.Insecure {
		t.Fatal("insecure yes => true")
	}
	if c.SecurityTxt == nil || *c.SecurityTxt {
		t.Fatal("security_txt off => false")
	}
	if c.Web.Enabled == nil || !*c.Web.Enabled {
		t.Fatal("web.enabled 1 => true")
	}
}

func TestLoadErrors(t *testing.T) {
	if _, err := Load("/no/such/file.yaml"); err == nil {
		t.Fatal("missing file should error")
	}
	if _, err := loadString(t, "concurrency: notanumber\n"); err == nil {
		t.Fatal("bad int should error")
	}
	if _, err := loadString(t, "insecure: maybe\n"); err == nil {
		t.Fatal("bad bool should error")
	}
	if _, err := loadString(t, "max_body_bytes: xyz\n"); err == nil {
		t.Fatal("bad int64 should error")
	}
	if _, err := loadString(t, "output:\n\tformat: json\n"); err == nil {
		t.Fatal("tab indentation should error")
	}
}

func TestUnmarshalListAndNesting(t *testing.T) {
	m, err := Unmarshal([]byte("a: 1\nlist:\n  - x\n  - y\nnested:\n  k: v\n"))
	if err != nil {
		t.Fatal(err)
	}
	if m["a"] != "1" {
		t.Fatalf("scalar: %v", m["a"])
	}
	lst, ok := m["list"].([]interface{})
	if !ok || len(lst) != 2 {
		t.Fatalf("list: %v", m["list"])
	}
	nested, ok := m["nested"].(map[string]interface{})
	if !ok || nested["k"] != "v" {
		t.Fatalf("nested: %v", m["nested"])
	}
}

func TestUnmarshalErrors(t *testing.T) {
	if _, err := Unmarshal([]byte("- just a list at top\n")); err == nil {
		t.Fatal("top-level list should error")
	}
	if _, err := Unmarshal([]byte("noColonHere\n")); err == nil {
		t.Fatal("missing colon should error")
	}
}

func TestQuotedScalars(t *testing.T) {
	m, err := Unmarshal([]byte(`a: "hello world"` + "\n" + `b: 'single'` + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	if m["a"] != "hello world" || m["b"] != "single" {
		t.Fatalf("quoted scalars: %v", m)
	}
}
