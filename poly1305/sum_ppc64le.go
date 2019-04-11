// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package poly1305

// poly1305vx is an assembly implementation of Poly1305 that uses vector
// instructions.
//go:noescape
func poly1305vx(out *[16]byte, m *byte, mlen uint64, key *[32]byte)

// If >= power8 this will be true.
var hasVX = true

// Sum generates an authenticator for m using a one-time key and puts the
// 16-byte result into out. Authenticating two different messages with the same
// key allows an attacker to forge messages at will.
func Sum(out *[16]byte, m []byte, key *[32]byte) {
	if hasVX {
		var mPtr *byte
		if len(m) > 0 {
			mPtr = &m[0]
		}
		poly1305vx(out, mPtr, uint64(len(m)), key)
	} else {
		sumGeneric(out, m, key)
	}
}
