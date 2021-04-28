// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build 386 || arm || mips || mipsle
// +build 386 arm mips mipsle

package curve25519

import (
	"github.com/mit-plv/fiat-crypto/fiat-go/32/curve25519"
)

type fieldElement = [10]uint32

func feFromBytes(dst *fieldElement, src *[32]byte) { curve25519.FromBytes(dst, src) }
func feToBytes(dst *[32]byte, src *fieldElement)   { curve25519.ToBytes(dst, src) }

func feZero(fe *fieldElement)       { *fe = fieldElement{} }
func feOne(fe *fieldElement)        { *fe = fieldElement{1} }
func feCopy(dst, src *fieldElement) { *dst = *src }

func feAdd(dst, a, b *fieldElement)  { curve25519.Add(dst, a, b) }
func feSub(dst, a, b *fieldElement)  { curve25519.Sub(dst, a, b) }
func feMul(h, f, g *fieldElement)    { curve25519.CarryMul(h, f, g) }
func feSquare(h, f *fieldElement)    { curve25519.CarrySquare(h, f) }
func feMul121666(h, f *fieldElement) { curve25519.CarryScmul121666(h, f) }

// feCSwap replaces (f,g) with (g,f) if b == 1; replaces (f,g) with (f,g) if b == 0.
//
// Preconditions: b in {0,1}.
func feCSwap(f, g *fieldElement, swap byte) {
	b := -uint32(swap)
	for i := range f {
		t := b & (f[i] ^ g[i])
		f[i] ^= t
		g[i] ^= t
	}
}
