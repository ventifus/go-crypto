// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !amd64,!arm

package poly1305

// Sum generates an authenticator for m using a one-time key and puts the
// 16-byte result into out. Authenticating two different messages with the same
// key allows an attacker to forge messages at will.
func Sum(out *[16]byte, m []byte, key *[32]byte) {
	poly1305Generic(out, m, key)
}
