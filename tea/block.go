// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/*
	Implementation adapted from Needham and Wheeler's paper:
	http://www.cix.co.uk/~klockstone/tea.pdf
	http://en.wikipedia.org/wiki/Tiny_Encryption_Algorithm#Reference_code
*/

package tea

import "encoding/binary"

// TEA is based on 64 rounds.
const numRounds = 64

// encryptBlock encrypts a single 8 byte block using TEA.
func encryptBlock(c *Cipher, dst, src []byte) {
	encryptBlockFlexible(c, dst, src, numRounds)
}

// encryptBlockFlexible encrypts a single 8 byte block using TEA, using configurable rounds.
func encryptBlockFlexible(c *Cipher, dst, src []byte, rounds int) {
	e := binary.BigEndian
	v0, v1 := e.Uint32(src), e.Uint32(src[4:])
	var sum uint32 = 0
	var delta uint32 = 0x9e3779b9
	k0, k1, k2, k3 := e.Uint32(c.key[0:]), e.Uint32(c.key[4:]),
		e.Uint32(c.key[8:]), e.Uint32(c.key[12:])

	for i := 0; i < rounds/2; i++ {
		sum += delta
		v0 += ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1)
		v1 += ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3)
	}

	e.PutUint32(dst, v0)
	e.PutUint32(dst[4:], v1)
}

// decryptBlock decrypt a single 8 byte block using TEA.
func decryptBlock(c *Cipher, dst, src []byte) {
	decryptBlockFlexible(c, dst, src, numRounds)
}

// decryptBlockFlexible decrypt a single 8 byte block using TEA, using configurable rounds.
func decryptBlockFlexible(c *Cipher, dst, src []byte, rounds int) {
	e := binary.BigEndian
	v0, v1 := e.Uint32(src), e.Uint32(src[4:])
	var delta uint32 = 0x9e3779b9
	var sum uint32 = delta * (uint32)(rounds/2) // in general, sum = delta * n
	k0, k1, k2, k3 := e.Uint32(c.key[0:]), e.Uint32(c.key[4:]),
		e.Uint32(c.key[8:]), e.Uint32(c.key[12:])

	for i := 0; i < rounds/2; i++ {
		v1 -= ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3)
		v0 -= ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1)
		sum -= delta
	}

	e.PutUint32(dst, v0)
	e.PutUint32(dst[4:], v1)
}
