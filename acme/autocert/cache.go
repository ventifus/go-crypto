// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package autocert

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"sort"
)

// ErrCacheMiss is returned when a certificate is not found in cache.
var ErrCacheMiss = errors.New("certificate cache miss")

// Cache is used by Manager to store and retrieve previously obtained certificates.
type Cache interface {
	// Get returns a TLS certificate valid for the specified domain name.
	// If the certificate is not cached, Get returns ErrCacheMiss.
	Get(name string) (tls.Certificate, error)

	// Put stores the TLS certificate in the cache.
	// It's up to the implementations how much to store, as long as
	// the reverse result of Get is valid.
	Put(tls.Certificate) error
}

// DirCache implements Cache using a directory on the local filesystem.
type DirCache string

// Get returns a TLS certificate valid for the specified domain name.
// It reads public/private key pair from a pair of files matching the name,
// with file extensions .crt and .key, respectively.
func (d DirCache) Get(name string) (tls.Certificate, error) {
	crt := filepath.Join(string(d), name+".crt")
	key := filepath.Join(string(d), name+".key")
	tlscert, err := tls.LoadX509KeyPair(crt, key)
	if os.IsNotExist(err) {
		err = ErrCacheMiss
	}
	if err != nil {
		return tls.Certificate{}, err
	}
	return tlscert, nil
}

// Put stores the TLS certificate's public/private key pair to a pair of files in PEM format.
// It writes a pair for each domain name so that the certificate can be retrieved
// by any of the names independently.
func (d DirCache) Put(tlscert tls.Certificate) error {
	if err := os.MkdirAll(string(d), 0600); err != nil {
		return err
	}

	// compute all the names tlscert should be Get-able by
	if len(tlscert.Certificate) == 0 {
		return errors.New("no certificate to cache")
	}
	cert, err := x509.ParseCertificate(tlscert.Certificate[0])
	if err != nil {
		return err
	}
	names := cert.DNSNames
	sort.Strings(names)
	i := sort.SearchStrings(names, cert.Subject.CommonName)
	if i >= len(names) || names[i] != cert.Subject.CommonName {
		names = append(names, cert.Subject.CommonName)
	}

	// marshal private key
	var pemKey *pem.Block
	switch k := tlscert.PrivateKey.(type) {
	case *rsa.PrivateKey:
		b := x509.MarshalPKCS1PrivateKey(k)
		pemKey = &pem.Block{Type: "RSA PRIVATE KEY", Bytes: b}
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return err
		}
		pemKey = &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
	default:
		return errors.New("DirCache: only RSA and ECDSA private keys are supported")
	}

	// public blocks
	var pemCert []*pem.Block
	for _, b := range tlscert.Certificate {
		pemCert = append(pemCert, &pem.Block{Type: "CERTIFICATE", Bytes: b})
	}

	// write everything to disk
	for _, name := range names {
		keyfile := filepath.Join(string(d), name+".key")
		w, err := os.OpenFile(keyfile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			return err
		}
		if err := pem.Encode(w, pemKey); err != nil {
			return err
		}
		if err := w.Close(); err != nil {
			return err
		}

		certfile := filepath.Join(string(d), name+".crt")
		w, err = os.Create(certfile)
		if err != nil {
			return err
		}
		for _, pb := range pemCert {
			if err := pem.Encode(w, pb); err != nil {
				return err
			}
		}
		if err := w.Close(); err != nil {
			return err
		}
	}
	return nil
}
