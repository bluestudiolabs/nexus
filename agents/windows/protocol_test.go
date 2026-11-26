package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOrigin(t *testing.T) {
	for _, s := range []string{"http://a", "https://user@a", "https://a/path", "https://a?q=1", "https://a/#f", ""} {
		if _, e := origin(s); e == nil {
			t.Fatalf("accepted %q", s)
		}
	}
	if b, e := origin("https://nexus.example:3010/"); e != nil || b != "https://nexus.example:3010" {
		t.Fatal(b, e)
	}
}
func TestTLSAndProtocol(t *testing.T) {
	var called int
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
		if r.Header.Get("Origin") != "" || r.Header.Get("Content-Type") != "application/json" {
			t.Error("unexpected headers")
		}
		var data map[string]any
		if json.NewDecoder(r.Body).Decode(&data) != nil {
			t.Error("invalid JSON")
		}
		if r.URL.Path == "/api/pair" {
			if data["code"] != "test-code" {
				t.Error(data)
			}
			w.Write([]byte(`{"token":"test-token","id":"test-id"}`))
			return
		}
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/api/ingest", 307)
			return
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			w.WriteHeader(401)
			return
		}
		if data["cpu"] != float64(25) {
			t.Error(data)
		}
		w.Write([]byte(`{"ok":true}`))
	}))
	defer s.Close()
	cert := s.Certificate()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	h, _ := client(Config{})
	if _, e := pair(h, s.URL, "test-code"); e == nil || called != 0 {
		t.Fatal("accepted untrusted TLS")
	}
	h, _ = client(Config{CA: string(ca)})
	p, e := pair(h, s.URL, "test-code")
	if e != nil || p.ID != "test-id" {
		t.Fatal(p, e)
	}
	if e = ingest(h, s.URL, p.Token, map[string]any{"cpu": 25}); e != nil {
		t.Fatal(e)
	}
	if e = ingest(h, s.URL, "wrong", map[string]any{"cpu": 25}); e != HTTPError(401) {
		t.Fatal(e)
	}
	var v any
	if e = post(h, s.URL, "/redirect", p.Token, map[string]any{}, &v); e == nil {
		t.Fatal("redirect accepted")
	}
	if cert.IsCA {
		sum := sha256.Sum256(cert.Raw)
		f, e := caFingerprint(ca)
		if e != nil || f != strings.ToUpper(hex.EncodeToString(sum[:])) {
			t.Fatal(f, e)
		}
	}
	if _, e := x509.ParseCertificate(cert.Raw); e != nil {
		t.Fatal(e)
	}
}
