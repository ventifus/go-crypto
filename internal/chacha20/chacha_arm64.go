// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package chacha20

const (
	haveAsm = true
	bufSize = 256
)

//go:noescape
func xorKeyStreamChunk(dst, src []byte, c *Cipher, counter *uint32, buf *[bufSize]byte, tail bool)

func (c *Cipher) xorKeyStreamAsm(dst, src []byte) {

	if len(src) >= bufSize {
		xorKeyStreamChunk(dst, src, c, &c.counter, &c.buf, false) // handle >= 256 byte only
	}

	if len(src)%bufSize != 0 {
		ret := [bufSize]byte{}
		i := len(src) &^ (bufSize - 1)
		copy(ret[:], src[i:])
		xorKeyStreamChunk(ret[:], ret[:], c, &c.counter, &c.buf, true)
		c.len = bufSize - copy(dst[i:], ret[:])
	}
}
