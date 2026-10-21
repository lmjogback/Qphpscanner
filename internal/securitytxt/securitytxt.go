// Package securitytxt locates and parses RFC 9116 "security.txt" policy files.
package securitytxt

import (
	"strings"
	"time"
)

// WellKnownPaths lists the candidate locations in RFC 9116 preference order.
// The /.well-known/ location is canonical; the root location is legacy.
var WellKnownPaths = []string{
	"/.well-known/security.txt",
	"/security.txt",
}

// SecurityTxt is a parsed security.txt file.
type SecurityTxt struct {
	Present            bool                `json:"present"`
	URL                string              `json:"url,omitempty"`
	Signed             bool                `json:"signed,omitempty"`
	Contact            []string            `json:"contact,omitempty"`
	Expires            string              `json:"expires,omitempty"`
	Expired            bool                `json:"expired,omitempty"`
	Encryption         []string            `json:"encryption,omitempty"`
	Acknowledgments    []string            `json:"acknowledgments,omitempty"`
	PreferredLanguages []string            `json:"preferred_languages,omitempty"`
	Canonical          []string            `json:"canonical,omitempty"`
	Policy             []string            `json:"policy,omitempty"`
	Hiring             []string            `json:"hiring,omitempty"`
	CSAF               []string            `json:"csaf,omitempty"`
	Other              map[string][]string `json:"other,omitempty" xml:"-"`
	Raw                string              `json:"raw,omitempty"`
}

// Parse reads a candidate body. The second return value reports whether the
// content actually looks like a security.txt file (to avoid treating an HTML
// 404 page as a policy document).
func Parse(url, body string) (*SecurityTxt, bool) {
	if strings.TrimSpace(body) == "" {
		return nil, false
	}
	// Reject obvious HTML error pages.
	lower := strings.ToLower(body)
	if strings.Contains(lower, "<html") || strings.Contains(lower, "<!doctype html") {
		return nil, false
	}

	st := &SecurityTxt{URL: url, Raw: body, Other: map[string][]string{}}
	st.Signed = strings.Contains(body, "BEGIN PGP SIGNED MESSAGE")

	recognised := 0
	for _, rawLine := range strings.Split(body, "\n") {
		line := strings.TrimRight(rawLine, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		// Skip PGP armor lines.
		if strings.HasPrefix(trimmed, "-----") || strings.HasPrefix(trimmed, "Hash:") ||
			strings.HasPrefix(trimmed, "Version:") && st.Signed {
			continue
		}
		idx := strings.Index(trimmed, ":")
		if idx <= 0 {
			continue
		}
		field := strings.ToLower(strings.TrimSpace(trimmed[:idx]))
		value := strings.TrimSpace(trimmed[idx+1:])
		if value == "" {
			continue
		}

		switch field {
		case "contact":
			st.Contact = append(st.Contact, value)
			recognised++
		case "expires":
			st.Expires = value
			recognised++
		case "encryption":
			st.Encryption = append(st.Encryption, value)
			recognised++
		case "acknowledgments", "acknowledgements":
			st.Acknowledgments = append(st.Acknowledgments, value)
			recognised++
		case "preferred-languages":
			for _, l := range strings.Split(value, ",") {
				if l = strings.TrimSpace(l); l != "" {
					st.PreferredLanguages = append(st.PreferredLanguages, l)
				}
			}
			recognised++
		case "canonical":
			st.Canonical = append(st.Canonical, value)
			recognised++
		case "policy":
			st.Policy = append(st.Policy, value)
			recognised++
		case "hiring":
			st.Hiring = append(st.Hiring, value)
			recognised++
		case "csaf":
			st.CSAF = append(st.CSAF, value)
			recognised++
		default:
			st.Other[field] = append(st.Other[field], value)
		}
	}

	// A legitimate security.txt must carry at least one recognised field;
	// RFC 9116 requires Contact.
	if recognised == 0 || len(st.Contact) == 0 && st.Expires == "" {
		return nil, false
	}

	st.Present = true
	if st.Expires != "" {
		if t, err := time.Parse(time.RFC3339, st.Expires); err == nil {
			st.Expired = time.Now().After(t)
		}
	}
	if len(st.Other) == 0 {
		st.Other = nil
	}
	return st, true
}
