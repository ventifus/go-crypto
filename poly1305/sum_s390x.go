// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build go1.8,s390x,!gccgo,!appengine

package poly1305

// hasVectorFacility reports whether the machine supports
// the vector facility (vx).
// This function is implemented in sum_s390x.s
func hasVectorFacility() bool

var hasVX = hasVectorFacility()

// This function is implemented in sum_s390x.s
//go:noescape
func poly1305z196(out *[16]byte, m *byte, mlen uint64, key *[32]byte)

// This function is implemented in sum_s390x.s
//go:noescape
func poly1305vx(out *[16]byte, m *byte, mlen uint64, key *[32]byte)

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
