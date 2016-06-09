// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package manager

import (
	"crypto/tls"
	"errors"
)

// ErrCacheMiss is returned when a certificate is not found in cache.
var ErrCacheMiss = errors.New("certificate cache miss")

// Cache is used by Manager to store and retrieve previously obtained certificates.
type Cache interface {
	// Get returns a TLS certificate valid for the specified domain name.
	// If the certificate is not in cache, Get returns ErrCacheMiss error.
	Get(name string) (tls.Certificate, error)

	// Put stores the TLS certificate in cache.
	// It's up to the implementations how much to store, as long as
	// the reverse result of Get is valid.
	Put(tls.Certificate) error
}

// DirCache implements Cache using a directory on the local filesystem.
type DirCache string

// Get returns a TLS certificate valid for the specified domain name.
func (d DirCache) Get(name string) (tls.Certificate, error) {
	return tls.Certificate{}, errors.New("not implemented")
}

// Put stores the TLS certificate in cache.
func (d DirCache) Put(tls.Certificate) error {
	return errors.New("not implemented")
}
