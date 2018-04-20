// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sha3

// This file provides function for creating TupleHash instances.
// TupleHash is "a SHA-3-derived hash function with variable-length output that
// is designed to simply hash a tuple of input strings, any or all of which may
// be empty strings, in an unambiguous way."
// It specified in NIST Special Publication 800-185, "SHA-3 Derived Functions:
// cSHAKE, KMAC, TupleHash and ParallelHash" [1]
//
// [1] https://doi.org/10.6028/NIST.SP.800-185

import (
	"hash"
)

// TupleHash specific context
type tupleHash struct {
	ShakeHash     // cSHAKE context and Read/Write operations
	hashSize  int // HashSize in bytes
}

// TupleHashXOF specific context
type tupleHashXOF struct {
	ShakeHash        // cSHAKE context and Read/Write operations
	alreadyRead bool // Indicates if output has already started being read
}

// NewTupleHash128 returns a new TupleHash providing 128 bits of security
// that outputs hashSize bytes using the given customizationString.
// Each item of the tuple must be written in a single Write() call.
func NewTupleHash128(hashSize int, customizationString []byte) hash.Hash {
	c := NewCShake128([]byte("TupleHash"), customizationString)
	return &tupleHash{ShakeHash: c, hashSize: hashSize}
}

// NewTupleHash256 returns a new TupleHash providing 128 bits of security
// that outputs hashSize bytes using the given customizationString.
// Each item of the tuple must be written in a single Write() call.
func NewTupleHash256(hashSize int, customizationString []byte) hash.Hash {
	c := NewCShake256([]byte("TupleHash"), customizationString)
	return &tupleHash{ShakeHash: c, hashSize: hashSize}
}

// NewTupleHashXOF128 returns a new TupleHashXOF providing 128 bits of security
// with arbitrary output size that does not need to be known beforehand and
// using the given customizationString.
// Each item of the tuple must be written in a single Write() call.
func NewTupleHashXOF128(customizationString []byte) ShakeHash {
	c := NewCShake128([]byte("TupleHash"), customizationString)
	return &tupleHashXOF{ShakeHash: c}
}

// NewTupleHashXOF256 returns a new TupleHashXOF providing 128 bits of security
// with arbitrary output size that does not need to be known beforehand and
// using the given customizationString.
func NewTupleHashXOF256(customizationString []byte) ShakeHash {
	c := NewCShake256([]byte("TupleHash"), customizationString)
	return &tupleHashXOF{ShakeHash: c}
}

// Write writes a tuple item.
func (k *tupleHash) Write(p []byte) (n int, err error) {
	k.ShakeHash.Write(leftEncode(uint64(len(p) * 8)))
	return k.ShakeHash.Write(p)
}

// BlockSize returns the hash block size.
func (t *tupleHash) BlockSize() int {
	return t.ShakeHash.(*cshakeState).BlockSize()
}

// Size returns the hash size in bytes.
func (t *tupleHash) Size() int {
	return t.hashSize
}

// Sum appends the current TupleHash to b and returns the resulting slice.
// It does not change the underlying hash state.
func (t *tupleHash) Sum(b []byte) []byte {
	dup := t.ShakeHash.Clone()
	dup.Write(rightEncode(uint64(t.hashSize * 8)))
	hash := make([]byte, t.hashSize)
	dup.Read(hash)
	return append(b, hash...)
}

// Write writes a tuple item.
func (t *tupleHashXOF) Write(p []byte) (n int, err error) {
	t.ShakeHash.Write(leftEncode(uint64(len(p) * 8)))
	return t.ShakeHash.Write(p)
}

// Read generates XOF output.
func (t *tupleHashXOF) Read(p []byte) (n int, err error) {
	if !t.alreadyRead {
		// When finished writing to the cShake, we must encode the "size" which
		// is 0 in XOF mode.
		t.alreadyRead = true
		t.ShakeHash.Write(rightEncode(uint64(0)))
	}
	return t.ShakeHash.Read(p)
}

// Clone returns a copy of the ShakeHash in its current state.
func (t *tupleHashXOF) Clone() ShakeHash {
	return &tupleHashXOF{ShakeHash: t.ShakeHash.Clone(), alreadyRead: t.alreadyRead}
}

// Reset resets the ShakeHash to its initial state.
func (t *tupleHashXOF) Reset() {
	t.alreadyRead = false
	t.ShakeHash.Reset()
}
