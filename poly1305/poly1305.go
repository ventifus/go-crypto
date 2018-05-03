// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package poly1305 implements Poly1305 one-time message authentication code as
// specified in https://cr.yp.to/mac/poly1305-20050329.pdf.
//
// Poly1305 is a fast, one-time authentication function. It is infeasible for an
// attacker to generate an authenticator for a message without the key. However, a
// key must only be used for a single message. Authenticating two different
// messages with the same key allows an attacker to forge authenticators for other
// messages with the same key.
//
// Poly1305 was originally coupled with AES in order to make Poly1305-AES. AES was
// used with a fixed key in order to generate one-time keys from an nonce.
// However, in this package AES isn't used and the one-time key is specified
// directly.
package poly1305 // import "golang.org/x/crypto/poly1305"

import "crypto/subtle"

// TagSize is the size, in bytes, of a poly1305 authenticator.
const TagSize = 16

// Verify returns true if mac is a valid authenticator for m with the given
// key.
func Verify(mac *[16]byte, m []byte, key *[32]byte) bool {
	var tmp [16]byte
	Sum(&tmp, m, key)
	return subtle.ConstantTimeCompare(tmp[:], mac[:]) == 1
}

// New returns a new Hash computing an authentication
// tag of all data written to it with the given key.
func New(key *[32]byte) *Hash {
	return &Hash{
		hash:      newHash(key),
		finalized: false,
	}
}

// Hash is an io.Writer computing an authentication tag
// of the data written to it.
//
// Hash cannot be used like common hash.Hash implementations,
// because using a poly1305 key twice breaks its security.
// Therefore writing data to a running Hash after calling
// Sum causes it to panic.
type Hash struct {
	hash // platform-dependent implementation

	finalized bool
}

// Write adds more data to the running message-authentication-code.
// It never returns an error.
//
// It must not be called after the first call of Sum.
func (h *Hash) Write(p []byte) (n int, err error) {
	if h.finalized {
		panic("poly1305: write to Hash after sum")
	}
	return h.hash.Write(p)
}

// Sum computes the authenticator of all data written to the
// message-authentication-code.
func (h *Hash) Sum(out *[16]byte) {
	h.hash.Sum(out)
	h.finalized = true
}
