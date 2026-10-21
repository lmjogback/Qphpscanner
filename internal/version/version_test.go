package version

import "testing"

func TestString(t *testing.T) {
	s := String()
	if s == "" {
		t.Fatal("empty version string")
	}
	if !contains(s, Name) || !contains(s, Version) {
		t.Fatalf("version string %q missing name/version", s)
	}
}

func contains(haystack, needle string) bool {
	return len(needle) == 0 || (len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
