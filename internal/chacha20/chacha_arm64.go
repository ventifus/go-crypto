// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build go1.11
// +build !gccgo,!appengine

package chacha20

const (
	haveAsm = true
	bufSize = 256
)

//go:noescape
func xorKeyStreamVX(dst, src []byte, key *[8]uint32, nonce *[3]uint32, counter *uint32, buf *[256]byte)

func (c *Cipher) xorKeyStreamAsm(dst, src []byte) {

	if len(src) >= bufSize {
		xorKeyStreamVX(dst, src, &c.key, &c.nonce, &c.counter, &c.buf)
	}

	if len(src)%bufSize != 0 {
		i := len(src) &^ (bufSize - 1)
		copy(c.buf[:], src[i:])
		xorKeyStreamVX(c.buf[:], c.buf[:], &c.key, &c.nonce, &c.counter, &c.buf)
		c.len = bufSize - copy(dst[i:], c.buf[:])
	}
}
