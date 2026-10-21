package dnsenum

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"
)

func TestMain(m *testing.M) {
	os.Setenv("NO_PROXY", "*")
	os.Setenv("HTTP_PROXY", "")
	os.Setenv("http_proxy", "")
	os.Exit(m.Run())
}

const ctJSON = `[
 {"common_name":"www.foo.com","name_value":"www.foo.com\n*.foo.com"},
 {"common_name":"api.foo.com","name_value":"api.foo.com\nfoo.com"},
 {"common_name":"evil.com","name_value":"evil.com"},
 {"common_name":"","name_value":"shop.foo.com"}
]`

func ctServer(t *testing.T, body string, status int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if status != 0 {
			w.WriteHeader(status)
		}
		_, _ = w.Write([]byte(body))
	}))
}

func TestEnumerate(t *testing.T) {
	ts := ctServer(t, ctJSON, 0)
	defer ts.Close()

	e := New()
	e.CTLogURL = ts.URL
	e.Client = ts.Client()

	hosts, err := e.Enumerate(context.Background(), "foo.com")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"api.foo.com", "foo.com", "shop.foo.com", "www.foo.com"}
	if !reflect.DeepEqual(hosts, want) {
		t.Fatalf("got %v, want %v", hosts, want)
	}
}

type fakeResolver struct{ ok map[string]bool }

func (f fakeResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	if f.ok[host] {
		return []string{"192.0.2.1"}, nil
	}
	return nil, errors.New("no such host")
}

func TestEnumerateVerify(t *testing.T) {
	ts := ctServer(t, ctJSON, 0)
	defer ts.Close()

	e := New()
	e.CTLogURL = ts.URL
	e.Client = ts.Client()
	e.Verify = true
	e.Resolver = fakeResolver{ok: map[string]bool{"www.foo.com": true, "api.foo.com": true}}

	hosts, err := e.Enumerate(context.Background(), "foo.com")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"api.foo.com", "www.foo.com"}
	if !reflect.DeepEqual(hosts, want) {
		t.Fatalf("got %v, want %v", hosts, want)
	}
}

func TestEnumerateMaxHosts(t *testing.T) {
	ts := ctServer(t, ctJSON, 0)
	defer ts.Close()
	e := New()
	e.CTLogURL = ts.URL
	e.Client = ts.Client()
	e.MaxHosts = 2
	hosts, err := e.Enumerate(context.Background(), "foo.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 2 {
		t.Fatalf("want 2 hosts capped, got %d", len(hosts))
	}
}

func TestEnumerateErrors(t *testing.T) {
	if _, err := New().Enumerate(context.Background(), ""); err == nil {
		t.Fatal("empty domain should error")
	}

	ts := ctServer(t, "nope", http.StatusInternalServerError)
	e := New()
	e.CTLogURL = ts.URL
	e.Client = ts.Client()
	if _, err := e.Enumerate(context.Background(), "foo.com"); err == nil {
		t.Fatal("HTTP 500 should error")
	}
	ts.Close()

	ts2 := ctServer(t, "not json", 0)
	defer ts2.Close()
	e2 := New()
	e2.CTLogURL = ts2.URL
	e2.Client = ts2.Client()
	if _, err := e2.Enumerate(context.Background(), "foo.com"); err == nil {
		t.Fatal("invalid JSON should error")
	}
}
