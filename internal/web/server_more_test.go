package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBasicAuthMiddleware(t *testing.T) {
	s := NewServer("x")
	s.SetAuth("admin", "pw")
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	resp, _ := http.Get(srv.URL + "/")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no creds => %d", resp.StatusCode)
	}
	resp.Body.Close()

	req, _ := http.NewRequest("GET", srv.URL+"/", nil)
	req.SetBasicAuth("admin", "pw")
	resp2, _ := http.DefaultClient.Do(req)
	if resp2.StatusCode != 200 {
		t.Fatalf("valid creds => %d", resp2.StatusCode)
	}
	resp2.Body.Close()

	req3, _ := http.NewRequest("GET", srv.URL+"/", nil)
	req3.SetBasicAuth("admin", "wrong")
	resp3, _ := http.DefaultClient.Do(req3)
	if resp3.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong creds => %d", resp3.StatusCode)
	}
	resp3.Body.Close()
}

func TestHistoryAndScopedDownload(t *testing.T) {
	target := phpTarget()
	defer target.Close()
	s := NewServer("x")
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	body := `{"targets":["` + target.URL + `"],"mode":"detect","tls":"off"}`
	resp, err := http.Post(srv.URL+"/api/scan", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	// Drain the stream so the result is stored.
	_, _ = http.MaxBytesReader(nil, resp.Body, 1<<20).Read(make([]byte, 1<<20))
	resp.Body.Close()

	hr, err := http.Get(srv.URL + "/api/history")
	if err != nil {
		t.Fatal(err)
	}
	var hist struct {
		Scans []struct {
			ID string `json:"id"`
		} `json:"scans"`
	}
	_ = json.NewDecoder(hr.Body).Decode(&hist)
	hr.Body.Close()
	if len(hist.Scans) == 0 {
		t.Fatal("history should list the scan")
	}

	// Download a specific scan by id, in a new format.
	id := hist.Scans[0].ID
	dr, err := http.Get(srv.URL + "/api/download?scan=" + id + "&format=csv")
	if err != nil {
		t.Fatal(err)
	}
	if dr.StatusCode != 200 {
		t.Fatalf("scoped download => %d", dr.StatusCode)
	}
	dr.Body.Close()

	// Unknown scan id => 400.
	br, _ := http.Get(srv.URL + "/api/download?scan=nope&format=json")
	if br.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown scan => %d", br.StatusCode)
	}
	br.Body.Close()
}
