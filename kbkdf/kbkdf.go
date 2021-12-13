// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package kbkdf implements the Key-Based Key Derivation Function (KBKDF) as
// defined in NIST SP800-108: Recommendation for Key Derivation Using
// Pseudorandom Functions.
//
// SP800-108 admits that the fixed input data fields may be omitted unless
// required for certain purposes. This implementation does not omit any of the
// fields and orders them as described in SP800-108. The 'i' and 'L' fields are
// represented as 32-bit unsigned integers in big-endian byte order.
package kbkdf // import "golang.org/x/crypto/kbkdf"

import (
	"crypto/hmac"
	"encoding/binary"
	"hash"
	"math"
)

// counter generates keyLen bytes of key material using the given PRF (i.e.,
// HMAC or CMAC) with the counter-mode KBKDF.
// Panics if keyLen is negative or >= MaxUint32/8.
func counter(prf func() hash.Hash, keyLen int, label, context []byte) []byte {
	if keyLen < 0 {
		panic("kbkdf: negative amount of key data requested")
	}
	if keyLen > (math.MaxUint32 / 8) {
		panic("kbkdf: 2^32 or more bits of key data requested")
	}
	hashLen := prf().Size()
	iterations := (keyLen + hashLen - 1) / hashLen
	result := make([]byte, 0, hashLen*iterations)
	for ctr := uint32(1); ctr <= uint32(iterations); ctr++ {
		ki := prf()
		binary.Write(ki, binary.BigEndian, ctr)
		ki.Write(label)
		ki.Write([]byte{0x00})
		ki.Write(context)
		binary.Write(ki, binary.BigEndian, uint32(keyLen*8))
		result = ki.Sum(result)
	}
	return result[:keyLen]
}

// HMACCounter generates keyLen bytes of key material using HMAC with the given
// hash algorithm as its PRF, with the counter mode KBKDF.
// Panics if keyLen is negative or >= MaxUint32/8.
func HMACCounter(h func() hash.Hash, keyLen int, secret, label, context []byte) []byte {
	prf := func() hash.Hash { return hmac.New(h, secret) }
	return counter(prf, keyLen, label, context)
}
