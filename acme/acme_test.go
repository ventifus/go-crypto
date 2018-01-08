// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package acme

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

// Decodes a JWS-encoded request and unmarshals the decoded JSON into a provided
// interface.
func decodeJWSRequest(t *testing.T, v interface{}, r *http.Request) {
	// Decode request
	var req struct{ Payload string }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		t.Fatal(err)
	}
	payload, err := base64.RawURLEncoding.DecodeString(req.Payload)
	if err != nil {
		t.Fatal(err)
	}
	err = json.Unmarshal(payload, v)
	if err != nil {
		t.Fatal(err)
	}
}

type jwsHead struct {
	Alg   string
	Nonce string
	JWK   map[string]string `json:"jwk"`
}

func decodeJWSHead(r *http.Request) (*jwsHead, error) {
	var req struct{ Protected string }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, err
	}
	b, err := base64.RawURLEncoding.DecodeString(req.Protected)
	if err != nil {
		return nil, err
	}
	var head jwsHead
	if err := json.Unmarshal(b, &head); err != nil {
		return nil, err
	}
	return &head, nil
}

func TestDiscover(t *testing.T) {
	const (
		keyChange  = "https://example.com/acme/key-change"
		newAccount = "https://example.com/acme/new-account"
		newNonce   = "https://example.com/acme/new-nonce"
		newOrder   = "https://example.com/acme/new-order"
		revokeCert = "https://example.com/acme/revoke-cert"
		terms      = "https://example.com/acme/terms"
	)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{
			"keyChange": %q,
			"newAccount": %q,
			"newNonce": %q,
			"newOrder": %q,
			"revokeCert": %q,
			"meta": {
				"termsOfService": %q
			}
		}`, keyChange, newAccount, newNonce, newOrder, revokeCert, terms)
	}))
	defer ts.Close()
	c := Client{DirectoryURL: ts.URL}
	dir, err := c.Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if dir.KeyChangeURL != keyChange {
		t.Errorf("dir.KeyChangeURL = %q; want %q", dir.KeyChangeURL, keyChange)
	}
	if dir.NewAccountURL != newAccount {
		t.Errorf("dir.NewAccountURL = %q; want %q", dir.NewAccountURL, newAccount)
	}
	if dir.NewNonceURL != newNonce {
		t.Errorf("dir.NewNonceURL = %q; want %q", dir.NewNonceURL, newNonce)
	}
	if dir.RevokeCertURL != revokeCert {
		t.Errorf("dir.RevokeCertURL = %q; want %q", dir.RevokeCertURL, revokeCert)
	}
	if dir.Terms != terms {
		t.Errorf("dir.Terms = %q; want %q", dir.Terms, terms)
	}
}

func TestCreateAccount(t *testing.T) {
	contacts := []string{"mailto:admin@example.com"}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" {
			w.Header().Set("Replay-Nonce", "test-nonce")
			return
		}
		if r.Method != "POST" {
			t.Errorf("r.Method = %q; want POST", r.Method)
		}

		var j struct {
			Contact              []string
			TermsOfServiceAgreed bool
		}
		decodeJWSRequest(t, &j, r)

		if !reflect.DeepEqual(j.Contact, contacts) {
			t.Errorf("j.Contact = %v; want %v", j.Contact, contacts)
		}
		if !j.TermsOfServiceAgreed {
			t.Error("j.TermsOfServiceAgreed = false; want true")
		}

		w.Header().Set("Location", "https://example.com/acme/account/1")
		w.WriteHeader(http.StatusCreated)
		b, _ := json.Marshal(contacts)
		fmt.Fprintf(w, `{"status":"valid","orders":"https://example.com/acme/orders","contact":%s}`, b)
	}))
	defer ts.Close()

	c := Client{Key: testKeyEC, dir: &Directory{NewAccountURL: ts.URL, NewNonceURL: ts.URL}}
	a := &Account{Contact: contacts, TermsAgreed: true}
	var err error
	if a, err = c.CreateAccount(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	if a.URL != "https://example.com/acme/account/1" {
		t.Errorf("a.URL = %q; want https://example.com/acme/account/1", a.URL)
	}
	if a.OrdersURL != "https://example.com/acme/orders" {
		t.Errorf("a.OrdersURL = %q; want https://example.com/acme/orders", a.OrdersURL)
	}
	if a.Status != StatusValid {
		t.Errorf("a.Status = %q; want valid", a.Status)
	}
	if !reflect.DeepEqual(a.Contact, contacts) {
		t.Errorf("a.Contact = %v; want %v", a.Contact, contacts)
	}
}

func TestUpdateAccount(t *testing.T) {
	contacts := []string{"mailto:admin@example.com"}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" {
			w.Header().Set("Replay-Nonce", "test-nonce")
			return
		}
		if r.Method != "POST" {
			t.Errorf("r.Method = %q; want POST", r.Method)
		}

		var j struct {
			Contact []string
		}
		decodeJWSRequest(t, &j, r)

		if !reflect.DeepEqual(j.Contact, contacts) {
			t.Errorf("j.Contact = %v; want %v", j.Contact, contacts)
		}
		b, _ := json.Marshal(contacts)
		fmt.Fprintf(w, `{"status":"valid","orders":"https://example.com/acme/orders","contact":%s}`, b)
	}))
	defer ts.Close()

	c := Client{Key: testKeyEC, dir: &Directory{NewNonceURL: ts.URL}}
	a := &Account{URL: ts.URL, Contact: contacts}
	var err error
	if a, err = c.UpdateAccount(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	if a.OrdersURL != "https://example.com/acme/orders" {
		t.Errorf("a.OrdersURL = %q; want https://example.com/acme/orders", a.OrdersURL)
	}
	if a.Status != StatusValid {
		t.Errorf("a.Status = %q; want valid", a.Status)
	}
	if !reflect.DeepEqual(a.Contact, contacts) {
		t.Errorf("a.Contact = %v; want %v", a.Contact, contacts)
	}
	if a.URL != ts.URL {
		t.Errorf("a.URL = %q; want %q", a.URL, ts.URL)
	}
}

func TestGetAccount(t *testing.T) {
	contacts := []string{"mailto:admin@example.com"}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" {
			w.Header().Set("Replay-Nonce", "test-nonce")
			return
		}
		if r.Method != "POST" {
			t.Errorf("r.Method = %q; want POST", r.Method)
		}

		decodeJWSRequest(t, &struct{}{}, r)
		w.WriteHeader(http.StatusOK)
		b, _ := json.Marshal(contacts)
		fmt.Fprintf(w, `{"status":"valid","orders":"https://example.com/acme/orders","contact":%s}`, b)
	}))
	defer ts.Close()

	c := Client{Key: testKeyEC, dir: &Directory{NewNonceURL: ts.URL}, AccountURL: ts.URL}
	a, err := c.GetAccount(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if a.OrdersURL != "https://example.com/acme/orders" {
		t.Errorf("a.OrdersURL = %q; want https://example.com/acme/orders", a.OrdersURL)
	}
	if a.Status != StatusValid {
		t.Errorf("a.Status = %q; want valid", a.Status)
	}
	if !reflect.DeepEqual(a.Contact, contacts) {
		t.Errorf("a.Contact = %v; want %v", a.Contact, contacts)
	}
	if a.URL != ts.URL {
		t.Errorf("a.URL = %q; want %q", a.URL, ts.URL)
	}
}

func TestCreateOrder(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" {
			w.Header().Set("Replay-Nonce", "test-nonce")
			return
		}
		if r.Method != "POST" {
			t.Errorf("r.Method = %q; want POST", r.Method)
		}

		var j struct {
			Identifiers []struct {
				Type  string
				Value string
			}
		}
		decodeJWSRequest(t, &j, r)

		// Test request
		if len(j.Identifiers) != 1 {
			t.Errorf("len(j.Identifiers) = %d; want 1", len(j.Identifiers))
		}
		if j.Identifiers[0].Type != "dns" {
			t.Errorf("j.Identifier.Type = %q; want dns", j.Identifiers[0].Type)
		}
		if j.Identifiers[0].Value != "example.com" {
			t.Errorf("j.Identifier.Value = %q; want example.com", j.Identifiers[0].Value)
		}

		w.Header().Set("Location", "https://example.com/acme/order/1")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, `{
			"identifiers": [{"type":"dns","value":"example.com"}],
			"status":"pending",
			"authorizations":["https://example.com/acme/order/1/1"],
			"finalize":"https://example.com/acme/order/1/finalize"
		}`)
	}))
	defer ts.Close()

	cl := Client{Key: testKeyEC, AccountURL: "https://example.com/acme/account", dir: &Directory{NewOrderURL: ts.URL, NewNonceURL: ts.URL}}
	o, err := cl.CreateOrder(context.Background(), NewOrderWithDomains("example.com"))
	if err != nil {
		t.Fatal(err)
	}

	if o.URL != "https://example.com/acme/order/1" {
		t.Errorf("URL = %q; want https://example.com/acme/order/1", o.URL)
	}
	if o.Status != "pending" {
		t.Errorf("Status = %q; want pending", o.Status)
	}
	if o.FinalizeURL != "https://example.com/acme/order/1/finalize" {
		t.Errorf("FinalizeURL = %q; want https://example.com/acme/order/1/finalize", o.FinalizeURL)
	}

	if n := len(o.Identifiers); n != 1 {
		t.Fatalf("len(o.Identifiers) = %d; want 1", n)
	}
	if o.Identifiers[0].Type != "dns" {
		t.Errorf("Identifiers[0].Type = %q; want dns", o.Identifiers[0].Type)
	}
	if o.Identifiers[0].Value != "example.com" {
		t.Errorf("Identifiers[0].Value = %q; want example.com", o.Identifiers[0].Value)
	}

	if n := len(o.Authorizations); n != 1 {
		t.Fatalf("len(o.Authorizations) = %d; want 1", n)
	}
	if o.Authorizations[0] != "https://example.com/acme/order/1/1" {
		t.Errorf("o.Authorizations[0] = %q; https://example.com/acme/order/1/1", o.Authorizations[0])
	}
}

func TestGetAuthorization(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("r.Method = %q; want GET", r.Method)
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{
			"identifier": {"type":"dns","value":"example.com"},
			"status":"pending",
			"challenges":[
				{
					"type":"http-01",
					"status":"pending",
					"url":"https://example.com/acme/challenge/publickey/id1",
					"token":"token1"
				},
				{
					"type":"tls-sni-02",
					"status":"pending",
					"url":"https://example.com/acme/challenge/publickey/id2",
					"token":"token2"
				}
			]
		}`)
	}))
	defer ts.Close()

	cl := Client{Key: testKeyEC, dir: &Directory{NewNonceURL: ts.URL}}
	auth, err := cl.GetAuthorization(context.Background(), ts.URL)
	if err != nil {
		t.Fatal(err)
	}

	if auth.Status != "pending" {
		t.Errorf("Status = %q; want pending", auth.Status)
	}
	if auth.Identifier.Type != "dns" {
		t.Errorf("Identifier.Type = %q; want dns", auth.Identifier.Type)
	}
	if auth.Identifier.Value != "example.com" {
		t.Errorf("Identifier.Value = %q; want example.com", auth.Identifier.Value)
	}

	if n := len(auth.Challenges); n != 2 {
		t.Fatalf("len(set.Challenges) = %d; want 2", n)
	}

	c := auth.Challenges[0]
	if c.Type != "http-01" {
		t.Errorf("c.Type = %q; want http-01", c.Type)
	}
	if c.URL != "https://example.com/acme/challenge/publickey/id1" {
		t.Errorf("c.URI = %q; want https://example.com/acme/challenge/publickey/id1", c.URL)
	}
	if c.Token != "token1" {
		t.Errorf("c.Token = %q; want token1", c.Token)
	}

	c = auth.Challenges[1]
	if c.Type != "tls-sni-02" {
		t.Errorf("c.Type = %q; want tls-sni-02", c.Type)
	}
	if c.URL != "https://example.com/acme/challenge/publickey/id2" {
		t.Errorf("c.URI = %q; want https://example.com/acme/challenge/publickey/id2", c.URL)
	}
	if c.Token != "token2" {
		t.Errorf("c.Token = %q; want token2", c.Token)
	}
}

func TestWaitAuthorization(t *testing.T) {
	var count int
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count++
		w.Header().Set("Retry-After", "0")
		if count > 1 {
			fmt.Fprintf(w, `{"status":"valid"}`)
			return
		}
		fmt.Fprintf(w, `{"status":"pending"}`)
	}))
	defer ts.Close()

	type res struct {
		authz *Authorization
		err   error
	}
	done := make(chan res)
	defer close(done)
	go func() {
		var client Client
		a, err := client.WaitAuthorization(context.Background(), ts.URL)
		done <- res{a, err}
	}()

	select {
	case <-time.After(5 * time.Second):
		t.Fatal("WaitAuthz took too long to return")
	case res := <-done:
		if res.err != nil {
			t.Fatalf("res.err =  %v", res.err)
		}
		if res.authz == nil {
			t.Fatal("res.authz is nil")
		}
	}
}

func TestWaitAuthorizationInvalid(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"status":"invalid"}`)
	}))
	defer ts.Close()

	res := make(chan error)
	defer close(res)
	go func() {
		var client Client
		_, err := client.WaitAuthorization(context.Background(), ts.URL)
		res <- err
	}()

	select {
	case <-time.After(3 * time.Second):
		t.Fatal("WaitAuthz took too long to return")
	case err := <-res:
		if err == nil {
			t.Error("err is nil")
		}
		if _, ok := err.(AuthorizationError); !ok {
			t.Errorf("err is %T; want *AuthorizationError", err)
		}
	}
}

func TestWaitAuthorizationCancel(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "60")
		fmt.Fprintf(w, `{"status":"pending"}`)
	}))
	defer ts.Close()

	res := make(chan error)
	defer close(res)
	go func() {
		var client Client
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		_, err := client.WaitAuthorization(ctx, ts.URL)
		res <- err
	}()

	select {
	case <-time.After(time.Second):
		t.Fatal("WaitAuthz took too long to return")
	case err := <-res:
		if err == nil {
			t.Error("err is nil")
		}
	}
}

func TestDeactivateAuthorization(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" {
			w.Header().Set("Replay-Nonce", "nonce")
			return
		}
		switch r.URL.Path {
		case "/1":
			var req struct {
				Status string
			}
			decodeJWSRequest(t, &req, r)
			if req.Status != "deactivated" {
				t.Errorf("req.Status = %q; want deactivated", req.Status)
			}
		case "/2":
			w.WriteHeader(http.StatusInternalServerError)
		case "/account":
			w.Header().Set("Location", "https://example.com/acme/account/0")
			w.Write([]byte("{}"))
		}
	}))
	defer ts.Close()
	client := &Client{Key: testKey, dir: &Directory{NewNonceURL: ts.URL, NewAccountURL: ts.URL + "/account"}}
	ctx := context.Background()
	if err := client.DeactivateAuthorization(ctx, ts.URL+"/1"); err != nil {
		t.Errorf("err = %v", err)
	}
	if client.DeactivateAuthorization(ctx, ts.URL+"/2") == nil {
		t.Error("nil error")
	}
}

func TestPollChallenge(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("r.Method = %q; want GET", r.Method)
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{
			"type":"http-01",
			"status":"pending",
			"url":"https://example.com/acme/challenge/publickey/id1",
			"token":"token1"}`)
	}))
	defer ts.Close()

	cl := Client{Key: testKeyEC}
	chall, err := cl.GetChallenge(context.Background(), ts.URL)
	if err != nil {
		t.Fatal(err)
	}

	if chall.Status != "pending" {
		t.Errorf("Status = %q; want pending", chall.Status)
	}
	if chall.Type != "http-01" {
		t.Errorf("c.Type = %q; want http-01", chall.Type)
	}
	if chall.URL != "https://example.com/acme/challenge/publickey/id1" {
		t.Errorf("c.URI = %q; want https://example.com/acme/challenge/publickey/id1", chall.URL)
	}
	if chall.Token != "token1" {
		t.Errorf("c.Token = %q; want token1", chall.Token)
	}
}

func TestAcceptChallenge(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" {
			w.Header().Set("Replay-Nonce", "test-nonce")
			return
		}
		if r.Method != "POST" {
			t.Errorf("r.Method = %q; want POST", r.Method)
		}

		var j struct {
			Auth string `json:"keyAuthorization"`
		}
		decodeJWSRequest(t, &j, r)

		keyAuth := "token1." + testKeyECThumbprint
		if j.Auth != keyAuth {
			t.Errorf(`keyAuthorization = %q; want %q`, j.Auth, keyAuth)
		}

		// Respond to request
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{
			"type":"http-01",
			"status":"pending",
			"url":"https://example.com/acme/challenge/publickey/id1",
			"token":"token1",
			"keyAuthorization":%q
		}`, keyAuth)
	}))
	defer ts.Close()

	cl := Client{Key: testKeyEC, AccountURL: "https://example.com/acme/account", dir: &Directory{NewNonceURL: ts.URL}}
	c, err := cl.AcceptChallenge(context.Background(), &Challenge{
		URL:   ts.URL,
		Token: "token1",
	})
	if err != nil {
		t.Fatal(err)
	}

	if c.Type != "http-01" {
		t.Errorf("c.Type = %q; want http-01", c.Type)
	}
	if c.URL != "https://example.com/acme/challenge/publickey/id1" {
		t.Errorf("c.URL = %q; want https://example.com/acme/challenge/publickey/id1", c.URL)
	}
	if c.Token != "token1" {
		t.Errorf("c.Token = %q; want token1", c.Token)
	}
}

func TestFinalizeOrder(t *testing.T) {
	notBefore := time.Now()
	notAfter := notBefore.AddDate(0, 2, 0)
	timeNow = func() time.Time { return notBefore }
	var sampleCert []byte

	var ts *httptest.Server
	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" {
			w.Header().Set("Replay-Nonce", "test-nonce")
			return
		}
		if r.URL.Path == "/cert" && r.Method == "GET" {
			pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: sampleCert})
			return
		}
		if r.Method != "POST" {
			t.Errorf("r.Method = %q; want POST", r.Method)
		}

		var j struct {
			CSR string `json:"csr"`
		}
		decodeJWSRequest(t, &j, r)

		template := x509.Certificate{
			SerialNumber: big.NewInt(int64(1)),
			Subject: pkix.Name{
				Organization: []string{"goacme"},
			},
			NotBefore: notBefore,
			NotAfter:  notAfter,

			KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
		}

		var err error
		sampleCert, err = x509.CreateCertificate(rand.Reader, &template, &template, &testKeyEC.PublicKey, testKeyEC)
		if err != nil {
			t.Fatalf("Error creating certificate: %v", err)
		}

		w.Header().Set("Location", "https://ca.tld/acme/cert/1")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{
			"identifiers": [{"type":"dns","value":"example.com"}],
			"status":"valid",
			"authorizations":["https://example.com/acme/order/1/1"],
			"finalize":"https://example.com/acme/order/1/finalize",
			"certificate":%q
		}`, ts.URL+"/cert")
	}))
	defer ts.Close()

	csr := x509.CertificateRequest{
		Version: 0,
		Subject: pkix.Name{
			CommonName:   "example.com",
			Organization: []string{"goacme"},
		},
	}
	csrb, err := x509.CreateCertificateRequest(rand.Reader, &csr, testKeyEC)
	if err != nil {
		t.Fatal(err)
	}

	c := Client{Key: testKeyEC, AccountURL: "https://example.com/acme/account", dir: &Directory{NewNonceURL: ts.URL}}
	cert, err := c.FinalizeOrder(context.Background(), ts.URL, csrb)
	if err != nil {
		t.Fatal(err)
	}
	if cert == nil {
		t.Errorf("cert is nil")
	}
}

func TestRevokeCert(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" {
			w.Header().Set("Replay-Nonce", "nonce")
			return
		}

		var req struct {
			Certificate string
			Reason      int
		}
		decodeJWSRequest(t, &req, r)
		if req.Reason != 1 {
			t.Errorf("req.Reason = %d; want 1", req.Reason)
		}
		// echo -n cert | base64 | tr -d '=' | tr '/+' '_-'
		cert := "Y2VydA"
		if req.Certificate != cert {
			t.Errorf("req.Certificate = %q; want %q", req.Certificate, cert)
		}
	}))
	defer ts.Close()
	client := &Client{
		Key: testKeyEC,
		dir: &Directory{RevokeCertURL: ts.URL, NewNonceURL: ts.URL},
	}
	ctx := context.Background()
	if err := client.RevokeCert(ctx, nil, []byte("cert"), CRLReasonKeyCompromise); err != nil {
		t.Fatal(err)
	}
}

func TestNonce_add(t *testing.T) {
	var c Client
	c.addNonce(http.Header{"Replay-Nonce": {"nonce"}})
	c.addNonce(http.Header{"Replay-Nonce": {}})
	c.addNonce(http.Header{"Replay-Nonce": {"nonce"}})

	nonces := map[string]struct{}{"nonce": {}}
	if !reflect.DeepEqual(c.nonces, nonces) {
		t.Errorf("c.nonces = %q; want %q", c.nonces, nonces)
	}
}

func TestNonce_addMax(t *testing.T) {
	c := &Client{nonces: make(map[string]struct{})}
	for i := 0; i < maxNonces; i++ {
		c.nonces[fmt.Sprintf("%d", i)] = struct{}{}
	}
	c.addNonce(http.Header{"Replay-Nonce": {"nonce"}})
	if n := len(c.nonces); n != maxNonces {
		t.Errorf("len(c.nonces) = %d; want %d", n, maxNonces)
	}
}

func TestNonce_fetch(t *testing.T) {
	tests := []struct {
		code  int
		nonce string
	}{
		{http.StatusOK, "nonce1"},
		{http.StatusBadRequest, "nonce2"},
		{http.StatusOK, ""},
	}
	var i int
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "HEAD" {
			t.Errorf("%d: r.Method = %q; want HEAD", i, r.Method)
		}
		w.Header().Set("Replay-Nonce", tests[i].nonce)
		w.WriteHeader(tests[i].code)
	}))
	defer ts.Close()
	for ; i < len(tests); i++ {
		test := tests[i]
		c := &Client{dir: &Directory{NewNonceURL: ts.URL}}
		n, err := c.fetchNonce(context.Background())
		if n != test.nonce {
			t.Errorf("%d: n=%q; want %q", i, n, test.nonce)
		}
		switch {
		case err == nil && test.nonce == "":
			t.Errorf("%d: n=%q, err=%v; want non-nil error", i, n, err)
		case err != nil && test.nonce != "":
			t.Errorf("%d: n=%q, err=%v; want %q", i, n, err, test.nonce)
		}
	}
}

func TestNonce_fetchError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer ts.Close()
	c := &Client{dir: &Directory{NewNonceURL: ts.URL}}
	_, err := c.fetchNonce(context.Background())
	e, ok := err.(*Error)
	if !ok {
		t.Fatalf("err is %T; want *Error", err)
	}
	if e.StatusCode != http.StatusTooManyRequests {
		t.Errorf("e.StatusCode = %d; want %d", e.StatusCode, http.StatusTooManyRequests)
	}
}

func TestNonce_postJWS(t *testing.T) {
	var count int
	seen := make(map[string]bool)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count++
		w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce%d", count))
		if r.Method == "HEAD" {
			// We expect the client do a HEAD request
			// but only to fetch the first nonce.
			return
		}
		// Make client.CreateOrder happy; we're not testing its result.
		defer func() {
			w.Header().Set("Location", "https://example.com/acme/order/1")
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(`{"status":"valid"}`))
		}()

		head, err := decodeJWSHead(r)
		if err != nil {
			t.Errorf("decodeJWSHead: %v", err)
			return
		}
		if head.Nonce == "" {
			t.Error("head.Nonce is empty")
			return
		}
		if seen[head.Nonce] {
			t.Errorf("nonce is already used: %q", head.Nonce)
		}
		seen[head.Nonce] = true
	}))
	defer ts.Close()

	client := Client{Key: testKey, AccountURL: "https://example.com/acme/account", dir: &Directory{NewOrderURL: ts.URL, NewNonceURL: ts.URL}}
	if _, err := client.CreateOrder(context.Background(), NewOrderWithDomains("example.com")); err != nil {
		t.Errorf("client.CreateOrder 1: %v", err)
	}
	// The second call should not generate another extra HEAD request.
	if _, err := client.CreateOrder(context.Background(), NewOrderWithDomains("example.com")); err != nil {
		t.Errorf("client.CreateOrder 2: %v", err)
	}

	if count != 3 {
		t.Errorf("total requests count: %d; want 3", count)
	}
	if n := len(client.nonces); n != 1 {
		t.Errorf("len(client.nonces) = %d; want 1", n)
	}
	for k := range seen {
		if _, exist := client.nonces[k]; exist {
			t.Errorf("used nonce %q in client.nonces", k)
		}
	}
}

func TestRetryPostJWS(t *testing.T) {
	var count int
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count++
		w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce%d", count))
		if r.Method == "HEAD" {
			// We expect the client to do 2 head requests to fetch
			// nonces, one to start and another after getting badNonce
			return
		}

		head, err := decodeJWSHead(r)
		if err != nil {
			t.Errorf("decodeJWSHead: %v", err)
		} else if head.Nonce == "" {
			t.Error("head.Nonce is empty")
		} else if head.Nonce == "nonce1" {
			// return a badNonce error to force the call to retry
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"type":"urn:ietf:params:acme:error:badNonce"}`))
			return
		}
		// Make client.CreateOrder happy; we're not testing its result.
		w.Header().Set("Location", "https://example.com/acme/order/1")
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"status":"valid"}`))
	}))
	defer ts.Close()

	client := Client{Key: testKey, AccountURL: "https://example.com/acme/account", dir: &Directory{NewOrderURL: ts.URL, NewNonceURL: ts.URL}}
	// This call will fail with badNonce, causing a retry
	if _, err := client.CreateOrder(context.Background(), NewOrderWithDomains("example.com")); err != nil {
		t.Errorf("client.CreateOrder 1: %v", err)
	}
	if count != 4 {
		t.Errorf("total requests count: %d; want 4", count)
	}
}

func TestErrorResponse(t *testing.T) {
	s := `{
		"status": 400,
		"type": "urn:acme:error:xxx",
		"detail": "text"
	}`
	res := &http.Response{
		StatusCode: 400,
		Status:     "400 Bad Request",
		Body:       ioutil.NopCloser(strings.NewReader(s)),
		Header:     http.Header{"X-Foo": {"bar"}},
	}
	err := responseError(res)
	v, ok := err.(*Error)
	if !ok {
		t.Fatalf("err = %+v (%T); want *Error type", err, err)
	}
	if v.StatusCode != 400 {
		t.Errorf("v.StatusCode = %v; want 400", v.StatusCode)
	}
	if v.ProblemType != "urn:acme:error:xxx" {
		t.Errorf("v.ProblemType = %q; want urn:acme:error:xxx", v.ProblemType)
	}
	if v.Detail != "text" {
		t.Errorf("v.Detail = %q; want text", v.Detail)
	}
	if !reflect.DeepEqual(v.Header, res.Header) {
		t.Errorf("v.Header = %+v; want %+v", v.Header, res.Header)
	}
}

func TestTLSSNI02ChallengeCert(t *testing.T) {
	const (
		token = "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA"
		// echo -n evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA | shasum -a 256
		sanA = "7ea0aaa69214e71e02cebb18bb867736.09b730209baabf60e43d4999979ff139.token.acme.invalid"
		// echo -n <token.testKeyECThumbprint> | shasum -a 256
		sanB = "dbbd5eefe7b4d06eb9d1d9f5acb4c7cd.a27d320e4b30332f0b6cb441734ad7b0.ka.acme.invalid"
	)

	client := &Client{Key: testKeyEC}
	tlscert, name, err := client.TLSSNI02ChallengeCert(token)
	if err != nil {
		t.Fatal(err)
	}

	if n := len(tlscert.Certificate); n != 1 {
		t.Fatalf("len(tlscert.Certificate) = %d; want 1", n)
	}
	cert, err := x509.ParseCertificate(tlscert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	names := []string{sanA, sanB}
	if !reflect.DeepEqual(cert.DNSNames, names) {
		t.Fatalf("cert.DNSNames = %v;\nwant %v", cert.DNSNames, names)
	}
	sort.Strings(cert.DNSNames)
	i := sort.SearchStrings(cert.DNSNames, name)
	if i >= len(cert.DNSNames) || cert.DNSNames[i] != name {
		t.Errorf("%v doesn't have %q", cert.DNSNames, name)
	}
	if cn := cert.Subject.CommonName; cn != sanA {
		t.Errorf("CommonName = %q; want %q", cn, sanA)
	}
}

func TestTLSChallengeCertOpt(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 512)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{Organization: []string{"Test"}},
		DNSNames:     []string{"should-be-overwritten"},
	}
	opts := []CertOption{WithKey(key), WithTemplate(tmpl)}

	client := &Client{Key: testKeyEC}
	tlscert, _, err := client.TLSSNI02ChallengeCert("token", opts...)
	if err != nil {
		t.Fatal(err)
	}

	// verify generated cert private key
	tlskey, ok := tlscert.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		t.Errorf("tlscert.PrivateKey is %T; want *rsa.PrivateKey", tlscert.PrivateKey)
	}
	if tlskey.D.Cmp(key.D) != 0 {
		t.Errorf("tlskey.D = %v; want %v", tlskey.D, key.D)
	}
	// verify generated cert public key
	x509Cert, err := x509.ParseCertificate(tlscert.Certificate[0])
	if err != nil {
		t.Errorf("%v", err)
	}
	tlspub, ok := x509Cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		t.Errorf("x509Cert.PublicKey is %T; want *rsa.PublicKey", x509Cert.PublicKey)
	}
	if tlspub.N.Cmp(key.N) != 0 {
		t.Errorf("tlspub.N = %v; want %v", tlspub.N, key.N)
	}
	// verify template option
	sn := big.NewInt(2)
	if x509Cert.SerialNumber.Cmp(sn) != 0 {
		t.Errorf("SerialNumber = %v; want %v", x509Cert.SerialNumber, sn)
	}
	org := []string{"Test"}
	if !reflect.DeepEqual(x509Cert.Subject.Organization, org) {
		t.Errorf("Subject.Organization = %+v; want %+v", x509Cert.Subject.Organization, org)
	}
	for _, v := range x509Cert.DNSNames {
		if !strings.HasSuffix(v, ".acme.invalid") {
			t.Errorf("invalid DNSNames element: %q", v)
		}
	}

}

func TestHTTP01Challenge(t *testing.T) {
	const (
		token = "xxx"
		// thumbprint is precomputed for testKeyEC in jws_test.go
		value   = token + "." + testKeyECThumbprint
		urlpath = "/.well-known/acme-challenge/" + token
	)
	client := &Client{Key: testKeyEC}
	val, err := client.HTTP01ChallengeResponse(token)
	if err != nil {
		t.Fatal(err)
	}
	if val != value {
		t.Errorf("val = %q; want %q", val, value)
	}
	if path := client.HTTP01ChallengePath(token); path != urlpath {
		t.Errorf("path = %q; want %q", path, urlpath)
	}
}

func TestDNS01ChallengeRecord(t *testing.T) {
	// echo -n xxx.<testKeyECThumbprint> | \
	//      openssl dgst -binary -sha256 | \
	//      base64 | tr -d '=' | tr '/+' '_-'
	const value = "8DERMexQ5VcdJ_prpPiA0mVdp7imgbCgjsG4SqqNMIo"

	client := &Client{Key: testKeyEC}
	val, err := client.DNS01ChallengeRecord("xxx")
	if err != nil {
		t.Fatal(err)
	}
	if val != value {
		t.Errorf("val = %q; want %q", val, value)
	}
}

func TestBackoff(t *testing.T) {
	tt := []struct{ min, max time.Duration }{
		{time.Second, 2 * time.Second},
		{2 * time.Second, 3 * time.Second},
		{4 * time.Second, 5 * time.Second},
		{8 * time.Second, 9 * time.Second},
	}
	for i, test := range tt {
		d := backoff(i, time.Minute)
		if d < test.min || test.max < d {
			t.Errorf("%d: d = %v; want between %v and %v", i, d, test.min, test.max)
		}
	}

	min, max := time.Second, 2*time.Second
	if d := backoff(-1, time.Minute); d < min || max < d {
		t.Errorf("d = %v; want between %v and %v", d, min, max)
	}

	bound := 10 * time.Second
	if d := backoff(100, bound); d != bound {
		t.Errorf("d = %v; want %v", d, bound)
	}
}
