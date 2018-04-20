// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sha3

// This file provides function for creating KMAC instances.
// KMAC is a Message Authentication Code that based on SHA-3 and
// specified in NIST Special Publication 800-185, "SHA-3 Derived Functions:
// cSHAKE, KMAC, TupleHash and ParallelHash".

import (
	"encoding/binary"
	"hash"
)

const (
	// According to NIST SP 800-185:
	// "When used as a MAC, applications of this Recommendation shall
	// not select an output length L that is less than 32 bits, and
	// shall only select an output length less than 64 bits after a
	// careful risk analysis is performed."
	// 64 bits was selected for safety.
	kmacMinimumTagSize = 8
)

func leftEncode(out hash.Hash, x int) int {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(x))
	xLen := 1
	for b[len(b)-xLen-1] != 0 && xLen < len(b) {
		xLen++
	}
	out.Write([]byte{byte(xLen)})
	out.Write(b[len(b)-xLen:])
	return xLen + 1
}

func rightEncode(out hash.Hash, x int) int {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(x))
	xLen := 1
	for b[len(b)-xLen-1] != 0 && xLen < len(b) {
		xLen++
	}
	out.Write(b[len(b)-xLen:])
	out.Write([]byte{byte(xLen)})
	return xLen + 1

}

func encodeString(out hash.Hash, s []byte) int {
	size := leftEncode(out, len(s)*8)
	out.Write(s)
	return size + len(s)
}

func bytepadStart(out hash.Hash, w int) int {
	return leftEncode(out, w)
}

func bytepadEnd(out hash.Hash, written, w int) {
	for ; written%w != 0; written++ {
		out.Write([]byte{0})
	}
}

// cSHAKE is a customizable version of the SHAKE function.
type cshake struct {
	*state
	initialState *state
}

func newCShake(rate, outputLen int, functionName, customizationString []byte) *cshake {
	if len(functionName) == 0 && len(customizationString) == 0 {
		return &cshake{NewShake128().(*state), nil}
	}
	s := &state{rate: rate, outputLen: outputLen, dsbyte: 0x04}
	written := bytepadStart(s, rate)
	written += encodeString(s, functionName)
	written += encodeString(s, customizationString)
	bytepadEnd(s, written, rate)
	return &cshake{s, s.clone()}
}

func (c *cshake) Reset() {
	c.state = c.initialState.clone()
}

type kmac struct {
	*cshake
}

// NewKMAC128 returns a new KMAC hash providing 128 bits of security using
// the given key, which must have 16 bytes or more, generating the given outputLen
// bytes output and using the given customizationString.
// Note that unlike other hash implementations in the standard library,
// the returned Hash does not implement encoding.BinaryMarshaler
// or encoding.BinaryUnmarshaler.
func NewKMAC128(key []byte, outputLen int, customizationString []byte) hash.Hash {
	if len(key) < 16 {
		panic("Key must not be smaller than security strength")
	}
	return newKMAC(key, outputLen, customizationString, 168)
}

// NewKMAC256 returns a new KMAC hash providing 256 bits of security using
// the given key, which must have 32 bytes or more, generating the given outputLen
// bytes output and using the given customizationString.
// Note that unlike other hash implementations in the standard library,
// the returned Hash does not implement encoding.BinaryMarshaler
// or encoding.BinaryUnmarshaler.
func NewKMAC256(key []byte, outputLen int, customizationString []byte) hash.Hash {
	if len(key) < 32 {
		panic("Key must not be smaller than security strength")
	}
	return newKMAC(key, outputLen, customizationString, 136)
}

func newKMAC(key []byte, outputLen int, customizationString []byte, rate int) hash.Hash {
	if outputLen < kmacMinimumTagSize {
		panic("outputLen is too small")
	}
	c := newCShake(rate, outputLen, []byte("KMAC"), customizationString)
	written := bytepadStart(c, c.rate)
	written += encodeString(c, key)
	bytepadEnd(c, written, c.rate)
	c.initialState = c.clone()
	return &kmac{c}
}

func (k *kmac) Sum(b []byte) []byte {
	s := k.state.clone()
	rightEncode(s, k.outputLen*8)
	return s.Sum(b)
}
