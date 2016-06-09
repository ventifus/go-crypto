// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package manager provides high-level ACME-based certificates management,
// built on top of the acme package.
package manager

import (
	"crypto"
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

// Manager is a stateful certificate manager built on top of acme.Client.
// It obtains and refreshes certificates automatically,
// as well as providing them to a TLS server via tls.Config.
//
// A zero value Manager is a valid state, in which case Let's Encrypt CA is used
// with a newly-generated RSA account key of 2048 bit size.
type Manager struct {
	Cache Cache

	clientMu  sync.Mutex // guards both clientReg and Client
	clientReg bool       // true if Client.Key is registered with the CA
	Client    *acme.Client

	certStateMu sync.Mutex
	certState   map[string]*certState

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

	// check whether this is a token cert requested for TLS-SNI challenge
	if strings.HasSuffix(name, ".acme.invalid") {
		m.tokenCertMu.RLock()
		defer m.tokenCertMu.RUnlock()
		cert := m.tokenCert[name]
		if cert == nil {
			return nil, fmt.Errorf("no token cert for %q", name)
		}
		return cert, nil
	}

	// a regular domain name:
	// try cache first or request a new cert otherwise
	if m.Cache != nil {
		cert, err := m.Cache.Get(name)
		if err == nil {
			return &cert, nil
		}
	}

	cert, err := m.cert(name)
	if err != nil {
		return nil, err
	}
	if m.Cache != nil {
		m.Cache.Put(*cert)
	}
	return cert, nil
}

func (m *Manager) cert(domain string) (*tls.Certificate, error) {
	m.certStateMu.Lock()
	if m.certState == nil {
		m.certState = make(map[string]*certState)
	}

	cert := m.certState[domain]
	// cert is not nil if another goroutine is already working on it
	// there are two cases when state is not nil:
	// (a) either cache is failing (or no cache at all);
	// (b) multiple cert requests for the same domain, before we're able to cache the cert
	if cert != nil {
		m.certStateMu.Unlock() // let others access the cert
		cert.RLock()
		defer cert.RUnlock()
		return cert.tlscert()
	}

	// we are the first
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	// let others access the now-locked cert and wait
	// while we're verifying domain ownership
	cert = &certState{key: key}
	cert.Lock()
	defer cert.Unlock()
	m.certState[domain] = cert
	m.certStateMu.Unlock()

	// verify domain ownership and get the cert
	// TODO: make m.verify retry or retry m.verify calls here
	if err := m.verify(domain); err != nil {
		return nil, err
	}
	client, err := m.client()
	if err != nil {
		return nil, err
	}
	csr, err := certRequest(cert.key, domain)
	if err != nil {
		return nil, err
	}
	ctx := context.Background() // TODO: use deadline?
	der, _, err := client.CreateCert(ctx, csr, 0, true)
	if err != nil {
		return nil, err
	}
	cert.cert = der
	return cert.tlscert()
}

func (m *Manager) verify(domain string) error {
	client, err := m.client()
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
		return errors.New("manager: no supported challenge type found")
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
		err = fmt.Errorf("manager: unknown challenge type %q", chal.Type)
	}
	if err != nil {
		return err
	}
	m.tokenCertMu.Lock()
	if m.tokenCert == nil {
		m.tokenCert = make(map[string]*tls.Certificate)
	}
	m.tokenCert[name] = &cert
	m.tokenCertMu.Unlock()
	// TODO: delete(m.tokenCert, name) at some point

	// ready to fulfill the challenge
	if _, err := client.Accept(chal); err != nil {
		return err
	}
	// wait for the CA to validate
	for {
		a, err := client.GetAuthz(authz.URI)
		if err != nil || a.Status != acme.StatusValid {
			if a.Status == acme.StatusInvalid {
				return fmt.Errorf("validation for domain %q failed", domain)
			}
			// TODO: use Retry-After header value for back-off
			time.Sleep(time.Second)
			continue
		}
		break
	}
	return nil
}

func (m *Manager) client() (*acme.Client, error) {
	m.clientMu.Lock()
	defer m.clientMu.Unlock()
	if m.clientReg {
		return m.Client, nil
	}

	if m.Client == nil {
		m.Client = &acme.Client{DirectoryURL: acme.LetsEncryptURL}
	}
	if m.Client.Key == nil {
		var err error
		m.Client.Key, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
	}
	_, err := m.Client.Register(&acme.Account{}, acme.AcceptTOS)
	if ae, ok := err.(*acme.Error); err == nil || ok && ae.StatusCode == http.StatusConflict {
		// conflict indicates the key is already registered
		m.clientReg = true
		err = nil
	}
	return m.Client, err
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
		return nil, errors.New("missing signer")
	}
	if len(s.cert) == 0 {
		return nil, errors.New("missing certificate")
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
