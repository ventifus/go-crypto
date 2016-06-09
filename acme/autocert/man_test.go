// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package autocert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"html/template"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/crypto/acme/internal/acme"
)

var discoTmpl = template.Must(template.New("disco").Parse(`{
	"new-reg": "{{.}}/new-reg",
	"new-authz": "{{.}}/new-authz",
	"new-cert": "{{.}}/new-cert"
}`))

var authzTmpl = template.Must(template.New("authz").Parse(`{
	"status": "pending",
	"challenges": [
		{
			"uri": "{{.}}/challenge/1",
			"type": "tls-sni-01",
			"token": "token-01"
		},
		{
			"uri": "{{.}}/challenge/2",
			"type": "tls-sni-02",
			"token": "token-02"
		}
	]
}`))

func dummyCert(san ...string) ([]byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	t := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageKeyEncipherment,
		DNSNames:              san,
	}
	return x509.CreateCertificate(rand.Reader, t, t, &key.PublicKey, key)
}

func TestGetCertificate(t *testing.T) {
	const domain = "example.org"
	man := &Manager{}

	verifyTokenCert := func() {
		// echo token-02 | shasum -a 256
		// then divide result in 2 parts separated by dot
		name := "4e8eb87631187e9ff2153b56b13a4dec.13a35d002e485d60ff37354b32f665d9.token.acme.invalid"
		hello := &tls.ClientHelloInfo{ServerName: name}
		_, err := man.GetCertificate(hello)
		if err != nil {
			t.Errorf("verifyTokenCert: GetCertificate(%q): %v", name, err)
			return
		}
	}

	// ACME CA server stub
	var ca *httptest.Server
	ca = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("replay-nonce", "nonce")
		switch r.URL.Path {
		// discovery
		case "/":
			if err := discoTmpl.Execute(w, ca.URL); err != nil {
				t.Fatalf("discoTmpl: %v", err)
			}
		// client key registration
		case "/new-reg":
			w.Write([]byte("{}"))
		// domain authorization
		case "/new-authz":
			w.Header().Set("location", ca.URL+"/authz/1")
			w.WriteHeader(http.StatusCreated)
			if err := authzTmpl.Execute(w, ca.URL); err != nil {
				t.Fatalf("authzTmpl: %v", err)
			}
		// accept tls-sni-02 challenge
		case "/challenge/2":
			verifyTokenCert()
			w.Write([]byte("{}"))
		// authorization status
		case "/authz/1":
			w.Write([]byte(`{"status": "valid"}`))
		// cert request
		case "/new-cert":
			der, err := dummyCert(domain)
			if err != nil {
				t.Fatalf("new-cert: dummyCert: %v", err)
			}
			chainUp := fmt.Sprintf("<%s/ca-cert>; rel=up", ca.URL)
			w.Header().Set("link", chainUp)
			w.WriteHeader(http.StatusCreated)
			w.Write(der)
		// CA chain cert
		case "/ca-cert":
			der, err := dummyCert("ca")
			if err != nil {
				t.Fatalf("ca-cert: dummyCert: %v", err)
			}
			w.Write(der)
		default:
			t.Errorf("unrecognized r.URL.Path: %s", r.URL.Path)
		}
	}))
	defer ca.Close()
	man.Client = &acme.Client{DirectoryURL: ca.URL}

	// simulate tls.Config.GetCertificate
	var (
		tlscert *tls.Certificate
		err     error
		done    = make(chan struct{})
	)
	go func() {
		hello := &tls.ClientHelloInfo{ServerName: domain}
		tlscert, err = man.GetCertificate(hello)
		close(done)
	}()
	select {
	case <-time.After(10 * time.Second):
		t.Fatal("man.GetCertificate took too long to return")
	case <-done:
	}
	if err != nil {
		t.Fatalf("man.GetCertificate: %v", err)
	}

	// verify the tlscert is the same we responded with from the CA stub
	if len(tlscert.Certificate) == 0 {
		t.Fatal("len(tlscert.Certificate) is 0")
	}
	cert, err := x509.ParseCertificate(tlscert.Certificate[0])
	if err != nil {
		t.Fatalf("x509.ParseCertificate: %v", err)
	}
	if len(cert.DNSNames) == 0 || cert.DNSNames[0] != domain {
		t.Errorf("cert.DNSNames = %v; want %q", cert.DNSNames, domain)
	}
}
