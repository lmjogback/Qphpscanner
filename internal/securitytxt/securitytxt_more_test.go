package securitytxt

import "testing"

func TestParseSignedAndExtraFields(t *testing.T) {
	body := `-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

Contact: mailto:sec@example.com
Expires: 2099-01-01T00:00:00Z
Canonical: https://example.com/.well-known/security.txt
Acknowledgements: https://example.com/thanks
Hiring: https://example.com/jobs
CSAF: https://example.com/csaf/provider-metadata.json
Custom-Field: hello
-----BEGIN PGP SIGNATURE-----
junk
-----END PGP SIGNATURE-----
`
	st, ok := Parse("u", body)
	if !ok {
		t.Fatal("expected valid signed security.txt")
	}
	if !st.Signed {
		t.Fatal("should be marked signed")
	}
	if len(st.Canonical) != 1 || len(st.Acknowledgments) != 1 || len(st.Hiring) != 1 || len(st.CSAF) != 1 {
		t.Fatalf("extra fields not captured: %+v", st)
	}
	if st.Other == nil || len(st.Other["custom-field"]) != 1 {
		t.Fatalf("custom field not captured: %+v", st.Other)
	}
}

func TestParseEmpty(t *testing.T) {
	if _, ok := Parse("u", "   \n  \n"); ok {
		t.Fatal("blank body should not parse")
	}
}

func TestParseExpiresOnly(t *testing.T) {
	// Expires with no Contact is still a recognisable (if non-compliant) file.
	st, ok := Parse("u", "Expires: 2099-01-01T00:00:00Z\n")
	if !ok || st.Expires == "" {
		t.Fatalf("expires-only should parse: %v %+v", ok, st)
	}
}
