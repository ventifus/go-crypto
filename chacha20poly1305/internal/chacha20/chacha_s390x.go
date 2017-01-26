// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package chacha20

// hasVectorFacility reports whether the machine supports the vector
// facility (vx).
// Implementation in asm_s390x.s.
func hasVectorFacility() bool

var hasVX = hasVectorFacility()

// xorKeyStreamVX is an assembly implementation of XORKeyStream. It must only
// be called when the vector facility is available.
// Implementation in asm_s390x.s.
//go:noescape
func xorKeyStreamVX(out, in []byte, counter *[16]byte, key *[32]byte)

// XORKeyStream crypts bytes from in to out using the given key and counters.
// In and out may be the same slice but otherwise should not overlap. Counter
// contains the raw ChaCha20 counter bytes (i.e. block counter followed by
// nonce).
func XORKeyStream(out, in []byte, counter *[16]byte, key *[32]byte) {
	if len(in) == 0 {
		return
	}
	if hasVX {
		_ = out[len(in)-1] // bounds check
		xorKeyStreamVX(out, in, counter, key)
		return
	}
	var block [64]byte
	var counterCopy [16]byte
	copy(counterCopy[:], counter[:])

	for len(in) >= 64 {
		core(&block, &counterCopy, key)
		for i, x := range block {
			out[i] = in[i] ^ x
		}
		u := uint32(1)
		for i := 0; i < 4; i++ {
			u += uint32(counterCopy[i])
			counterCopy[i] = byte(u)
			u >>= 8
		}
		in = in[64:]
		out = out[64:]
	}

	if len(in) > 0 {
		core(&block, &counterCopy, key)
		for i, v := range in {
			out[i] = v ^ block[i]
		}
	}
}
