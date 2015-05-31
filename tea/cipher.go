// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package tea implements TEA encryption, as defined in Needham and Wheeler's
// 1994 technical report, "TEA, a Tiny Encryption Algorithm." See
// http://www.cix.co.uk/~klockstone/tea.pdf for the details.

package tea // import "golang.org/x/crypto/tea"

import "encoding/binary"
import "errors"

// BlockSize is the size of a TEA block, in bytes.
const BlockSize = 8

// delta is the TEA key schedule constant.
var delta uint32 = 0x9e3779b9

// numRounds is the number of rounds in TEA.
const numRounds = 64

// Cipher is an instance of a TEA cipher using a particular key.
type Cipher struct {
	key    []byte
	rounds int
}

// NewCipherWithRounds creates and returns a new Cipher.
// The key argument should be the TEA key.
// TEA only supports 128 bit (16 byte) keys.
// The rounds argument is optional, and allows using TEA with configurable
// numbers of rounds.
func NewCipherWithRounds(key []byte, rounds ...int) (*Cipher, error) {
	if len(key) != 16 {
		return nil, errors.New("tea: incorrect key size")
	}

	c := new(Cipher)
	c.key = key

	if len(rounds) > 0 {
		c.rounds = rounds[0]
	} else {
		c.rounds = numRounds
	}

	return c, nil
}

// BlockSize returns the TEA block size, 8 bytes.
// It is necessary to satisfy the Block interface in the
// package "crypto/cipher".
func (c *Cipher) BlockSize() int { return BlockSize }

// Encrypt encrypts the 8 byte buffer src using the key and stores the result in dst.
// Note that for amounts of data larger than a block,
// it is not safe to just call Encrypt on successive blocks;
// instead, use an encryption mode like CBC (see crypto/cipher/cbc.go).
func (c *Cipher) Encrypt(dst, src []byte) { encryptBlock(c, dst, src) }

// Decrypt decrypts the 8 byte buffer src using the key k and stores the result in dst.
func (c *Cipher) Decrypt(dst, src []byte) { decryptBlock(c, dst, src) }

// encryptBlock encrypts a single 8 byte block using TEA.
func encryptBlock(c *Cipher, dst, src []byte) {
	e := binary.BigEndian
	v0, v1 := e.Uint32(src), e.Uint32(src[4:])
	var sum uint32 = 0
	var delta uint32 = delta
	k0, k1, k2, k3 := e.Uint32(c.key[0:]), e.Uint32(c.key[4:]),
		e.Uint32(c.key[8:]), e.Uint32(c.key[12:])

	for i := 0; i < c.rounds/2; i++ { // cycles = rounds/2
		sum += delta
		v0 += ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1)
		v1 += ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3)
	}

	e.PutUint32(dst, v0)
	e.PutUint32(dst[4:], v1)
}

// decryptBlock decrypt a single 8 byte block using TEA.
func decryptBlock(c *Cipher, dst, src []byte) {
	e := binary.BigEndian
	v0, v1 := e.Uint32(src), e.Uint32(src[4:])
	var delta uint32 = delta
	var sum uint32 = delta * (uint32)(c.rounds/2) // in general, sum = delta * n
	k0, k1, k2, k3 := e.Uint32(c.key[0:]), e.Uint32(c.key[4:]),
		e.Uint32(c.key[8:]), e.Uint32(c.key[12:])

	for i := 0; i < c.rounds/2; i++ {
		v1 -= ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3)
		v0 -= ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1)
		sum -= delta
	}

	e.PutUint32(dst, v0)
	e.PutUint32(dst[4:], v1)
}
