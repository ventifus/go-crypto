// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package autocert provides automatic access to certificates from Let's Encrypt
// and any other ACME-based CA.
package autocert

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme/internal/acme"
	"golang.org/x/net/context"
)

// AcceptTOS always returns true to indicate the acceptance of a CA Terms of Service
// during account registration.
func AcceptTOS(tosURL string) bool { return true }

// Manager is a stateful certificate manager built on top of acme.Client.
// It obtains and refreshes certificates automatically,
// as well as providing them to a TLS server via tls.Config.
//
// A simple usage example:
//
//	m := autocert.Manager{Prompt: autocert.AcceptTOS}
//	s := &http.Server{
//		Addr: ":https",
//		TLSConfig: &tls.Config{GetCertificate: m.GetCertificate},
//	}
//	s.ListenAndServeTLS("", "")
//
// To preserve issued certificates and improve overall performance,
// use a cache implementation of Cache. For instance, DirCache.
type Manager struct {
	// Prompt specifies a callback function to conditionally accept a CA's Terms of Service (TOS).
	// The registration may require the caller to agree to the CA's TOS.
	// If so, Manager calls Prompt with a TOS URL provided by the CA. Prompt should report
	// whether the caller agrees to the terms.
	//
	// To always accept the terms, the callers can use AcceptTOS.
	Prompt func(tosURL string) bool

	// Cache optionally stores and retrieves previously-obtained certificates.
	// If nil, certs will only be cached for the lifetime of the Manager.
	Cache Cache

	// Client is used to perform low-level operations, such as account registration
	// and requesting new certificates.
	// If Client is nil, a zero-value acme.Client is used with acme.LetsEncryptURL
	// directory endpoint and a newly-generated 2048-bit RSA key.
	//
	// Mutating the field after the first call of GetCertificate method will have no effect.
	Client *acme.Client

	// Email optionally specifies a contact email address.
	// This is used by CAs, such as Let's Encrypt, to notify about problems
	// with issued certificates.
	//
	// If the Client's account key is already registered, Email is not used.
	Email string

	clientMu sync.Mutex
	client   *acme.Client // initialized by acmeClient method

	stateMu sync.Mutex
	state   map[string]*certState // keyed by domain name

	// tokenCert is keyed by token domain name, which matches server name
	// of ClientHello. Keys always have ".acme.invalid" suffix.
	tokenCertMu sync.RWMutex
	tokenCert   map[string]*tls.Certificate
}

// GetCertificate implements the tls.Config.GetCertificate hook.
// It provides a TLS certificate for hello.ServerName host, including answering
// *.acme.invalid (TLS-SNI) challenges. All other fields of hello are ignored.
//
// A simple usage can be shown as follows:
//
//	s := &http.Server{
//		Addr: ":https",
//		TLSConfig: &tls.Config{
//			GetCertificate: m.GetCertificate,
//		},
//	}
//	s.ListenAndServeTLS("", "")
//
func (m *Manager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	name := hello.ServerName
	if name == "" {
		return nil, errors.New("acme/autocert: missing server name")
	}

	// check whether this is a token cert requested for TLS-SNI challenge
	if strings.HasSuffix(name, ".acme.invalid") {
		m.tokenCertMu.RLock()
		defer m.tokenCertMu.RUnlock()
		if cert := m.tokenCert[name]; cert != nil {
			return cert, nil
		}
		if cert, err := m.cacheGet(name); err == nil {
			return cert, nil
		}
		return nil, fmt.Errorf("acme/autocert: no token cert for %q", name)
	}

	// a regular domain name:
	// try cache first or request a new cert otherwise
	cert, err := m.cacheGet(name)
	if err == nil {
		return cert, nil
	}
	cert, err = m.cert(name)
	if err != nil {
		return nil, err
	}
	m.cachePut(name, cert)
	return cert, nil
}

func (m *Manager) cacheGet(domain string) (*tls.Certificate, error) {
	if m.Cache == nil {
		return nil, ErrCacheMiss
	}
	pubDER, privDER, err := m.Cache.Get(context.Background(), domain)
	if err != nil {
		return nil, err
	}
	// parse public part(s) and verify the leaf is not expired
	// and corresponds to the private key
	x509Cert, err := x509.ParseCertificates(pubDER)
	if len(x509Cert) == 0 {
		return nil, errors.New("acme/autocert: no public key found in cache")
	}
	leaf := x509Cert[0]
	if leaf.NotAfter.After(time.Now()) {
		return nil, errors.New("acme/autocert: expired certificate")
	}
	pkey, err := parsePrivateKey(privDER)
	if err != nil {
		return nil, err
	}
	switch pub := leaf.PublicKey.(type) {
	case *rsa.PublicKey:
		priv, ok := pkey.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("acme/autocert: private key type does not match public key type")
		}
		if pub.N.Cmp(priv.N) != 0 {
			return nil, errors.New("acme/autocert: private key does not match public key")
		}
	case *ecdsa.PublicKey:
		priv, ok := pkey.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("acme/autocert: private key type does not match public key type")
		}
		if pub.X.Cmp(priv.X) != 0 || pub.Y.Cmp(priv.Y) != 0 {
			return nil, errors.New("acme/autocert: private key does not match public key")
		}
	default:
		return nil, errors.New("acme/autocert: unknown public key algorithm")
	}

	tlscert := &tls.Certificate{
		Certificate: make([][]byte, len(x509Cert)),
		PrivateKey:  pkey,
		Leaf:        leaf,
	}
	for i, crt := range x509Cert {
		tlscert.Certificate[i] = crt.Raw
	}
	return tlscert, nil
}

func (m *Manager) cachePut(domain string, tlscert *tls.Certificate) error {
	if m.Cache == nil {
		return nil
	}

	// private
	var prv []byte
	switch key := tlscert.PrivateKey.(type) {
	case *ecdsa.PrivateKey:
		var err error
		if prv, err = x509.MarshalECPrivateKey(key); err != nil {
			return err
		}
	case *rsa.PrivateKey:
		prv = x509.MarshalPKCS1PrivateKey(key)
	default:
		return errors.New("acme/autocert: unknown private key type")
	}

	// public
	var n int
	for _, b := range tlscert.Certificate {
		n += len(b)
	}
	pub := make([]byte, n)
	n = 0
	for _, b := range tlscert.Certificate {
		n += copy(pub[n:], b)
	}

	return m.Cache.Put(context.Background(), domain, pub, prv)
}

func (m *Manager) cert(domain string) (*tls.Certificate, error) {
	state, ok, err := m.certState(domain)
	if err != nil {
		return nil, err
	}
	// state exists if another goroutine is already working on it.
	// There are two cases for the state to exist:
	// (a) either cache is failing or no cache at all;
	// (b) multiple cert requests for the same domain, before we're able to cache the cert
	if ok {
		state.RLock()
		defer state.RUnlock()
		return state.tlscert()
	}

	// We are the first.
	// Unblock the readers when domain ownership is verified
	// and the we got the cert or the process failed.
	defer state.Unlock()
	// TODO: make m.verify retry or retry m.verify calls here
	if err := m.verify(domain); err != nil {
		return nil, err
	}
	client, err := m.acmeClient()
	if err != nil {
		return nil, err
	}
	csr, err := certRequest(state.key, domain)
	if err != nil {
		return nil, err
	}
	ctx := context.Background() // TODO: use deadline?
	der, _, err := client.CreateCert(ctx, csr, 0, true)
	if err != nil {
		return nil, err
	}
	state.cert = der
	return state.tlscert()
}

func (m *Manager) verify(domain string) error {
	client, err := m.acmeClient()
	if err != nil {
		return err
	}

	// start domain authorization and get the challenge
	authz, err := client.Authorize(domain)
	if err != nil {
		return err
	}
	// pick a challenge: prefer tls-sni-02 over tls-sni-01
	// TODO: consider authz.Combinations
	var chal *acme.Challenge
	for _, c := range authz.Challenges {
		if c.Type == "tls-sni-02" {
			chal = c
			break
		}
		if c.Type == "tls-sni-01" {
			chal = c
		}
	}
	if chal == nil {
		return errors.New("acme/autocert: no supported challenge type found")
	}

	// create a token cert for the challenge response
	var (
		cert tls.Certificate
		name string
	)
	switch chal.Type {
	case "tls-sni-01":
		cert, name, err = client.TLSSNI01ChallengeCert(chal.Token)
	case "tls-sni-02":
		cert, name, err = client.TLSSNI02ChallengeCert(chal.Token)
	default:
		err = fmt.Errorf("acme/autocert: unknown challenge type %q", chal.Type)
	}
	if err != nil {
		return err
	}
	m.putTokenCert(name, &cert)
	defer func() {
		// verification has ended at this point
		// don't need token cert anymore
		go m.deleteTokenCert(name)
	}()

	// ready to fulfill the challenge
	if _, err := client.Accept(chal); err != nil {
		return err
	}
	// wait for the CA to validate
	for {
		a, err := client.GetAuthz(authz.URI)
		if err != nil || a.Status != acme.StatusValid {
			if a.Status == acme.StatusInvalid {
				return fmt.Errorf("acme/autocert: validation for domain %q failed", domain)
			}
			// TODO: use Retry-After header value for back-off
			time.Sleep(time.Second)
			continue
		}
		break
	}
	return nil
}

// certState returns existing state or creates a new one locked for read/write.
// The boolean return value indicates whether the state was found in m.state.
func (m *Manager) certState(domain string) (*certState, bool, error) {
	m.stateMu.Lock()
	defer m.stateMu.Unlock()
	if m.state == nil {
		m.state = make(map[string]*certState)
	}
	// existing state
	if state, ok := m.state[domain]; ok {
		return state, true, nil
	}
	// new locked state
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, false, err
	}
	state := &certState{key: key}
	state.Lock()
	m.state[domain] = state
	return state, false, nil
}

// putTokenCert stores the cert under the named key in both m.tokenCert map
// and m.Cache.
func (m *Manager) putTokenCert(name string, cert *tls.Certificate) {
	m.tokenCertMu.Lock()
	defer m.tokenCertMu.Unlock()
	if m.tokenCert == nil {
		m.tokenCert = make(map[string]*tls.Certificate)
	}
	m.tokenCert[name] = cert
	m.cachePut(name, cert)
}

// deleteTokenCert removes the token certificate for the specified domain name
// from both m.tokenCert map and m.Cache.
func (m *Manager) deleteTokenCert(name string) {
	m.tokenCertMu.Lock()
	defer m.tokenCertMu.Unlock()
	delete(m.tokenCert, name)
	if m.Cache != nil {
		m.Cache.Delete(context.Background(), name)
	}
}

func (m *Manager) acmeClient() (*acme.Client, error) {
	m.clientMu.Lock()
	defer m.clientMu.Unlock()
	if m.client != nil {
		return m.client, nil
	}

	client := m.Client
	if client == nil {
		client = &acme.Client{DirectoryURL: acme.LetsEncryptURL}
	}
	if client.Key == nil {
		var err error
		client.Key, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
	}
	var contact []string
	if m.Email != "" {
		contact = []string{"mailto:" + m.Email}
	}
	a := &acme.Account{Contact: contact}
	_, err := client.Register(a, m.Prompt)
	if ae, ok := err.(*acme.Error); err == nil || ok && ae.StatusCode == http.StatusConflict {
		// conflict indicates the key is already registered
		m.client = client
		err = nil
	}
	return m.client, err
}

// certState is ready when its mutex is unlocked for reading.
type certState struct {
	sync.RWMutex
	key  crypto.Signer
	cert [][]byte // DER encoding
}

// tlscert creates a tls.Certificate from s.key and s.cert.
// Callers should wrap it in s.RLock() and s.RUnlock().
func (s *certState) tlscert() (*tls.Certificate, error) {
	if s.key == nil {
		return nil, errors.New("acme/autocert: missing signer")
	}
	if len(s.cert) == 0 {
		return nil, errors.New("acme/autocert: missing certificate")
	}
	// TODO: compare pub.N with key.N or pub.{X,Y} for ECDSA?
	return &tls.Certificate{
		Certificate: s.cert,
		PrivateKey:  s.key,
	}, nil
}

// certRequest creates a certificate request for the given common name cn
// and optional SANs.
func certRequest(key crypto.Signer, cn string, san ...string) ([]byte, error) {
	req := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: cn},
		DNSNames: san,
	}
	return x509.CreateCertificateRequest(rand.Reader, req, key)
}

// Attempt to parse the given private key DER block. OpenSSL 0.9.8 generates
// PKCS#1 private keys by default, while OpenSSL 1.0.0 generates PKCS#8 keys.
// OpenSSL ecparam generates SEC1 EC private keys for ECDSA. We try all three.
//
// Copied from crypto/tls/tls.go.
func parsePrivateKey(der []byte) (crypto.PrivateKey, error) {
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey:
			return key, nil
		default:
			return nil, errors.New("acme/autocert: found unknown private key type in PKCS#8 wrapping")
		}
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}

	return nil, errors.New("acme/autocert: failed to parse private key")
}
