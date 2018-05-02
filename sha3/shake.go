// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sha3

// This file defines the ShakeHash interface, and provides
// functions for creating SHAKE and cSHAKE instances, as well as utility
// functions for hashing bytes to arbitrary-length output.
//
//
// SHAKE implementation is based on FIPS PUB 202 [1]
// cSHAKE implementations is based on NIST SP 800-185 [2]
// [1] https://doi.org/10.6028/NIST.SP.800-185
// [2] https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf

import (
	"io"
)

// ShakeHash defines the interface to hash functions that
// support arbitrary-length output.
type ShakeHash interface {
	// Write absorbs more data into the hash's state. It panics if input is
	// written to it after output has been read from it.
	io.Writer

	// Read reads more output from the hash; reading affects the hash's
	// state. (ShakeHash.Read is thus very different from Hash.Sum)
	// It never returns an error.
	io.Reader

	// Clone returns a copy of the ShakeHash in its current state.
	Clone() ShakeHash
	// Reset resets the ShakeHash to its initial state.
	Reset()
}

// cSHAKE specific context
type cshakeCtx struct {
	state // SHA-3 state context and Read/Write operations

	// initBlock cSHAKE specific initialization set of bytes. It is initialized
	// by newCShake function and stores concatenation of N followed by S, encoded
	// by the method specified in 3.3 of [1].
	// It is stored here in order for Reset() to be able to put context into
	// initial state.
	initBlock []byte
}

// Consts for configuring initial SHA-3 state
const (
	dsbyteShake  = 0x1f
	dsbyteCshake = 0x04
	rate128      = 168
	rate256      = 136
)

func bytepad(input []byte, w int) []byte {
	var buf []byte
	buf = append(buf, leftEncode(uint64(w))...)
	buf = append(buf, input...)
	padlen := w - (len(buf) % w)
	return append(buf, make([]byte, padlen)...)
}

func leftEncode(value uint64) []byte {

	var n byte
	var b [9]byte

	for v := value; v != 0; v = v >> 8 {
		n++
	}

	if n == 0 {
		n = 1
	}

	b[0] = n
	for i := byte(1); i <= n; i++ {
		b[i] = byte(value >> (8 * (i - 1)))
	}

	return b[:n+1]
}

func newCShake(N, S []byte, rate int, dsbyte byte) ShakeHash {

	ctx := cshakeCtx{state: state{rate: rate, dsbyte: dsbyte}}
	ctx.initBlock = append(ctx.initBlock, leftEncode(uint64(len(N)*8))...)
	ctx.initBlock = append(ctx.initBlock, N...)
	ctx.initBlock = append(ctx.initBlock, leftEncode(uint64(len(S)*8))...)
	ctx.initBlock = append(ctx.initBlock, S...)
	ctx.Write(bytepad(ctx.initBlock, ctx.rate))
	return &ctx
}

// Reset resets the hash to initial state.
func (ctx *cshakeCtx) Reset() {
	ctx.reset()
	ctx.Write(bytepad(ctx.initBlock, ctx.rate))
}

// Clone returns copy of a cSHAKE context within its current state.
func (ctx *cshakeCtx) Clone() ShakeHash {
	b := make([]byte, len(ctx.initBlock))
	copy(b, ctx.initBlock)
	return &cshakeCtx{state: *ctx.clone(), initBlock: b}
}

// Clone returns copy of SHAKE context within its current state.
func (ctx *state) Clone() ShakeHash {
	return ctx.clone()
}

// NewShake128 creates a new SHAKE128 variable-output-length ShakeHash.
// Its generic security strength is 128 bits against all attacks if at
// least 32 bytes of its output are used.
func NewShake128() ShakeHash {
	if h := newShake128Asm(); h != nil {
		return h
	}
	return &state{rate: rate128, dsbyte: dsbyteShake}
}

// NewShake256 creates a new SHAKE128 variable-output-length ShakeHash.
// Its generic security strength is 256 bits against all attacks if
// at least 64 bytes of its output are used.
func NewShake256() ShakeHash {
	if h := newShake256Asm(); h != nil {
		return h
	}
	return &state{rate: rate256, dsbyte: dsbyteShake}
}

// NewCShake128 initializes cSHAKE-128. N is a function-name bit string, used
// by NIST to define functions based on cSHAKE. nil can be provided when no
// function other than cSHAKE is desired. S is a user selected customization bit
// string. It is used to define a variant of the function. S can be nil if no
// customization is desired.
// When len(N) and len(S) are both equal to 0 then function returns instance of
// SHAKE128
func NewCShake128(N, S []byte) ShakeHash {
	if len(N) == 0 && len(S) == 0 {
		return NewShake128()
	}
	return newCShake(N, S, rate128, dsbyteCshake)
}

// NewCShake256 initializes cSHAKE-256. N is a function-name bit string, used
// by NIST to define functions based on cSHAKE. nil can be provided when no
// function other than cSHAKE is desired. S is a user selected customization bit
// string. It is used to define a variant of the function. S can be nil if no
// customization is desired.
// When len(N) and len(S) are both equal to 0 then function returns instance of
// SHAKE256
func NewCShake256(N, S []byte) ShakeHash {
	if len(N) == 0 && len(S) == 0 {
		return NewShake256()
	}
	return newCShake(N, S, rate256, dsbyteCshake)
}

func sum(out, data []byte, h ShakeHash) {
	h.Write(data)
	h.Read(out)
}

// ShakeSum128 helper function calculates digest of SHAKE128. out is a
// output buffer in which hash will be stored. in is an input message.
func ShakeSum128(out, in []byte) { sum(out, in, NewShake128()) }

// ShakeSum256 helper function calculates digest of SHAKE256. out is a
// output buffer in which hash will be stored. in is an input message.
func ShakeSum256(out, in []byte) { sum(out, in, NewShake256()) }

// CShakeSum128 helper function calculates digest of cSHAKE128. out is a
// output buffer in which hash will be stored. in is an input message. N
// and S are same as for NewCShakeXXX functions.
func CShakeSum128(out, in, N, S []byte) { sum(out, in, NewCShake128(N, S)) }

// CShakeSum256 helper function calculates digest of cSHAKE256. out is a
// output buffer in which hash will be stored. in is an input message. N
// and S are same as for NewCShakeXXX functions.
func CShakeSum256(out, in, N, S []byte) { sum(out, in, NewCShake256(N, S)) }
