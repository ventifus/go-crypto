// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build go1.11

package chacha20

const (
	haveAsm = true
	bufSize = 256
)

//go:noescape
func xorKeyStream64(dst, src []byte, c *Cipher, counter *uint32, buf *[bufSize]byte, tail bool)

//go:noescape
func xorKeyStream256(dst, src []byte, c *Cipher, counter *uint32, buf *[bufSize]byte, tail bool)

func (c *Cipher) xorKeyStreamAsm(dst, src []byte) {

	if len(src) < bufSize {

		if len(src) >= 64 {
			xorKeyStream64(dst, src, c, &c.counter, &c.buf, false)
		}

		if len(src)%64 != 0 {
			ret := [64]byte{}
			i := len(src) &^ 63
			copy(ret[:], src[i:])
			xorKeyStream64(ret[:], ret[:], c, &c.counter, &c.buf, true)
			c.len = 64 - copy(dst[i:], ret[:])
		}

	} else {

		xorKeyStream256(dst, src, c, &c.counter, &c.buf, false)

		if len(src)%bufSize != 0 {
			ret := [bufSize]byte{}
			i := len(src) &^ (bufSize - 1)
			copy(ret[:], src[i:])
			xorKeyStream256(ret[:], ret[:], c, &c.counter, &c.buf, true)
			c.len = bufSize - copy(dst[i:], ret[:])
		}
	}
}
