// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package tea implements TEA encryption, as defined in Needham and Wheeler's
// 1994 technical report, "TEA, a Tiny Encryption Algorithm."
package tea // import "golang.org/x/crypto/tea"

// For details, see http://www.cix.co.uk/~klockstone/tea.pdf

import "strconv"

// The TEA block size in bytes.
const BlockSize = 8

// A Cipher is an instance of an TEA cipher using a particular key.
type Cipher struct {
	key []byte
}

type KeySizeError int

func (k KeySizeError) Error() string {
	return "crypto/tea: invalid key size " + strconv.Itoa(int(k))
}

// NewCipher creates and returns a new Cipher.
// The key argument should be the TEA key.
// TEA only supports 128 bit (16 byte) keys.
func NewCipher(key []byte) (*Cipher, error) {
	k := len(key)

	if len(key) != 16 {
		return nil, KeySizeError(k)
	}

	c := new(Cipher)
	c.key = key

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

// EncryptFlexible encrypts the 8 byte buffer src using the key and stores the result in dst, with configurable rounds.
// Note that for amounts of data larger than a block,
// it is not safe to just call Encrypt on successive blocks;
// instead, use an encryption mode like CBC (see crypto/cipher/cbc.go).
func (c *Cipher) EncryptFlexible(dst, src []byte, rounds int) {
	encryptBlockFlexible(c, dst, src, rounds)
}

// Decrypt decrypts the 8 byte buffer src using the key k and stores the result in dst.
func (c *Cipher) Decrypt(dst, src []byte) { decryptBlock(c, dst, src) }

// DecryptFlexible decrypts the 8 byte buffer src using the key k and stores the result in dst, using configurable rounds.
func (c *Cipher) DecryptFlexible(dst, src []byte, rounds int) {
	decryptBlockFlexible(c, dst, src, rounds)
}
