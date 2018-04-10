// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build s390x,!gccgo,!appengine

package chacha20

// hasVectorFacility reports whether the machine supports the vector
// facility (vx).
// Implementation in asm_s390x.s.
func hasVectorFacility() bool

var hasAsm = hasVectorFacility()

const bufSize = 256

// xorKeyStreamVX is an assembly implementation of XORKeyStream. It must only
// be called when the vector facility is available.
// Implementation in asm_s390x.s.
//go:noescape
func xorKeyStreamVX(dst, src []byte, counter *[4]uint32, key *[8]uint32, buf *[bufSize]byte)

// XORKeyStream crypts bytes from in to out using the given key and counters.
// In and out may be the same slice but otherwise should not overlap. Counter
// contains the raw ChaCha20 counter bytes (i.e. block counter followed by
// nonce).
func (s *State) coreAsm(dst, src []byte) {
	if len(src) == 0 {
		return
	}
	for i := 0; i < len(s.buf); i++ {
		s.buf[i] = 0
	}
	tail := len(src) % 256
	if tail != 0 {
		copy(s.buf[:], src[len(src)-tail:])
	}
	s.len = bufSize - tail
	xorKeyStreamVX(dst, src, &s.counter, &s.key, &s.buf)
	copy(dst[len(src)-tail:len(src)], s.buf[:])
}
