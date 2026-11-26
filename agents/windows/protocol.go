package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Config struct {
	Server string `json:"server"`
	CA     string `json:"ca,omitempty"`
	Token  []byte `json:"token"`
	ID     string `json:"id"`
	GPU    bool   `json:"gpu"`
}

func origin(raw string) (string, error) {
	u, e := url.Parse(strings.TrimSpace(raw))
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || u.ForceQuery {
		return "", errors.New("Enter an HTTPS server address only, e.g. https://nexus.example:3010")
	}
	return "https://" + u.Host, nil
}
func caFingerprint(data []byte) (string, error) {
	p, rest := pem.Decode(data)
	if p == nil || p.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return "", errors.New("Choose a PEM file containing one CA certificate")
	}
	c, e := x509.ParseCertificate(p.Bytes)
	if e != nil || !c.IsCA {
		return "", errors.New("Not a CA certificate")
	}
	sum := sha256.Sum256(c.Raw)
	return strings.ToUpper(hex.EncodeToString(sum[:])), nil
}
func client(c Config) (*http.Client, error) {
	roots := (*x509.CertPool)(nil)
	if c.CA != "" {
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM([]byte(c.CA)) {
			return nil, errors.New("Invalid saved CA")
		}
	}
	t := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}, Proxy: nil, MaxIdleConns: 2, IdleConnTimeout: 30 * time.Second}
	return &http.Client{Transport: t, Timeout: 12 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("Server redirects are not allowed") }}, nil
}

type HTTPError int

func (e HTTPError) Error() string { return fmt.Sprintf("NEXUS returned HTTP %d", e) }
func post(h *http.Client, base, path, token string, data any, out any) error {
	b, e := json.Marshal(data)
	if e != nil {
		return e
	}
	r, e := http.NewRequest("POST", base+path, bytes.NewReader(b))
	if e != nil {
		return e
	}
	r.Header.Set("Content-Type", "application/json")
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	resp, e := h.Do(r)
	if e != nil {
		return e
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return HTTPError(resp.StatusCode)
	}
	raw, e := io.ReadAll(io.LimitReader(resp.Body, 65537))
	if e != nil || len(raw) > 65536 {
		return errors.New("Invalid response")
	}
	return json.Unmarshal(raw, out)
}

type PairReply struct {
	Token string `json:"token"`
	ID    string `json:"id"`
}

func pair(h *http.Client, base, code string) (PairReply, error) {
	var p PairReply
	e := post(h, base, "/api/pair", "", map[string]string{"code": strings.TrimSpace(code)}, &p)
	if e == nil && (p.Token == "" || p.ID == "") {
		e = errors.New("Invalid pairing response")
	}
	return p, e
}
func ingest(h *http.Client, base, token string, sample map[string]any) error {
	var out struct {
		OK bool `json:"ok"`
	}
	e := post(h, base, "/api/ingest", token, sample, &out)
	if e == nil && !out.OK {
		return errors.New("Sample not accepted")
	}
	return e
}
