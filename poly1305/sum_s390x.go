// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build go1.8,s390x,!gccgo,!appengine

package poly1305

// hasVectorFacility reports whether the machine supports
// the vector facility (vx).
func hasVectorFacility() bool

var hasVX = hasVectorFacility()

// poly1305z196 is an assembly implementation of Poly1305 that uses z196
// instructions.
//go:noescape
func poly1305z196(out *[16]byte, m *byte, mlen uint64, key *[32]byte)

// poly1305vx is an assembly implementation of Poly1305 that uses vector
// instructions. It must only be called if the vector facility (vx) is
// available.
//go:noescape
func poly1305vx(out *[16]byte, m *byte, mlen uint64, key *[32]byte)

// mvc is the target of an execute instruction. It should not be called
// directly.
func mvc()

// Sum generates an authenticator for m using a one-time key and puts the
// 16-byte result into out. Authenticating two different messages with the same
// key allows an attacker to forge messages at will.
func Sum(out *[16]byte, m []byte, key *[32]byte) {
	var mPtr *byte
	if len(m) > 0 {
		mPtr = &m[0]
	}
	if hasVX {
		poly1305vx(out, mPtr, uint64(len(m)), key)
		return
	}
	poly1305z196(out, mPtr, uint64(len(m)), key)
}
