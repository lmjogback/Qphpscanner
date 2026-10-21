package securitytxt

import "testing"

func TestParseValid(t *testing.T) {
	body := `# Our policy
Contact: mailto:security@example.com
Contact: https://example.com/report
Expires: 2099-12-31T23:59:59Z
Encryption: https://example.com/pgp.txt
Preferred-Languages: en, de
Policy: https://example.com/policy
`
	st, ok := Parse("https://example.com/.well-known/security.txt", body)
	if !ok || st == nil || !st.Present {
		t.Fatal("expected a valid security.txt")
	}
	if len(st.Contact) != 2 {
		t.Fatalf("want 2 contacts, got %v", st.Contact)
	}
	if st.Expired {
		t.Fatal("future expiry should not be expired")
	}
	if len(st.PreferredLanguages) != 2 {
		t.Fatalf("want 2 languages, got %v", st.PreferredLanguages)
	}
}

func TestParseExpired(t *testing.T) {
	body := "Contact: mailto:sec@example.com\nExpires: 2000-01-01T00:00:00Z\n"
	st, ok := Parse("u", body)
	if !ok {
		t.Fatal("expected valid parse")
	}
	if !st.Expired {
		t.Fatal("past expiry should be flagged expired")
	}
}

func TestRejectHTML(t *testing.T) {
	if _, ok := Parse("u", "<!DOCTYPE html><html><body>404 Not Found</body></html>"); ok {
		t.Fatal("HTML error page must not parse as security.txt")
	}
}

func TestRejectNoRecognisedFields(t *testing.T) {
	if _, ok := Parse("u", "hello world\nthis is not a policy\n"); ok {
		t.Fatal("random text must not parse as security.txt")
	}
}
