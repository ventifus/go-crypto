// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build ppc64le

// Package ChaCha20 implements the core ChaCha20 function as specified in https://tools.ietf.org/html/rfc7539#section-2.3.
package chacha20

//go:noescape
func ChaCha20_ctr32_vmx(out, inp *byte, len int, key *[32]byte, counter *[16]byte)

// XORKeyStream crypts bytes from in to out using the given key and counters.
// In and out may be the same slice but otherwise should not overlap. Counter
// contains the raw ChaCha20 counter bytes (i.e. block counter followed by
// nonce).
func XORKeyStream(out, in []byte, counter *[16]byte, key *[32]byte) {
	ChaCha20_ctr32_vmx(&out[0], &in[0], len(in), key, counter)
}
