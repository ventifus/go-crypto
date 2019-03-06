// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build amd64,!gccgo,!appengine

package curve25519

import (
	"golang.org/x/crypto/curve25519/internal/fp"
	"golang.org/x/sys/cpu"
)

var hasBmi2Adx bool

func init() { hasBmi2Adx = cpu.X86.HasBMI2 && cpu.X86.HasADX }

// clamp converts a key into a valid scalar
func clamp(in *[32]byte) *[32]byte {
	out := *in
	out[0] &= 248
	out[31] &= 127
	out[31] |= 64
	return &out
}

// ScalarBaseMult sets dst to the product in*base where dst and base are the x
// coordinates of group points, base is the standard generator and all values
// are in little-endian form.
func ScalarBaseMult(out, in *[32]byte) {
	// The algorithm implemented is the right-to-left Joye's ladder as described
	// in "How to precompute a ladder" in SAC'2017.
	k := clamp(in)
	w := [4]fp.Elt{
		fp.Elt{1}, // x1 = 1
		fp.Elt{1}, // z1 = 1
		fp.Elt{ // x2 = G-S
			0xbd, 0xaa, 0x2f, 0xc8, 0xfe, 0xe1, 0x94, 0x7e,
			0xf8, 0xed, 0xb2, 0x14, 0xae, 0x95, 0xf0, 0xbb,
			0xe2, 0x48, 0x5d, 0x23, 0xb9, 0xa0, 0xc7, 0xad,
			0x34, 0xab, 0x7c, 0xe2, 0xee, 0xcd, 0xae, 0x1e},
		fp.Elt{1}, // z2 = 1
	}
	swap := uint(1)
	for s := 0; s < 255-3; s++ {
		i := (s + 3) / 8
		j := (s + 3) % 8
		bit := uint((k[i] >> uint(j)) & 1)
		difAdd(&w, &tableBasePoint255[s], swap^bit)
		swap = bit
	}
	double(&w)
	double(&w)
	double(&w)
	x, z := &w[0], &w[1]
	fp.Inv(z, z)
	fp.Mul((*fp.Elt)(out), x, z)
	fp.Modp((*fp.Elt)(out))
}

// ScalarMult sets dst to the product in*base where dst and base are the x
// coordinates of group points and all values are in little-endian form.
func ScalarMult(out, in, base *[32]byte) {
	k := clamp(in)
	// [RFC-7748] When receiving such an array, implementations
	// of X25519 (but not X448) MUST mask the most significant
	// bit in the final byte.
	xP := *base
	xP[31] &= (1 << (255 % 8)) - 1
	w := [5]fp.Elt{
		xP,        // x1 = xP
		fp.Elt{1}, // x2 = 1
		fp.Elt{0}, // z2 = 0
		xP,        // x3 = xP
		fp.Elt{1}, // z3 = 1
	}
	move := uint(0)
	for s := 255 - 1; s >= 0; s-- {
		i := s / 8
		j := s % 8
		bit := uint((k[i] >> uint(j)) & 1)
		ladderStep(&w, move^bit)
		move = bit
	}
	x, z := &w[1], &w[2]
	fp.Inv(z, z)
	fp.Mul((*fp.Elt)(out), x, z)
	fp.Modp((*fp.Elt)(out))
}

//go:noescape
func ladderStep(work *[5]fp.Elt, move uint)

//go:noescape
func difAdd(work *[4]fp.Elt, mu *fp.Elt, swap uint)

//go:noescape
func double(work *[4]fp.Elt)
