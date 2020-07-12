// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package curve25519

// This code is a port of the public domain, "ref10" implementation of
// curve25519 from SUPERCOP 20130419 by D. J. Bernstein.

func feOne(fe *fieldElement) {
	*fe = fieldElement{1}
}

func feCopy(dst, src *fieldElement) {
	*dst = *src
}

// feCSwap replaces (f,g) with (g,f) if b == 1; replaces (f,g) with (f,g) if b == 0.
//
// Preconditions: b in {0,1}.
func feCSwap(f, g *fieldElement, b word) {
	b = -b
	for i := range f {
		t := uword(b) & (f[i] ^ g[i])
		f[i] ^= t
		g[i] ^= t
	}
}

// feInvert sets out = z^-1.
func feInvert(out, z *fieldElement) {
	var t0, t1, t2, t3 fieldElement
	var i int

	fiat_25519_carry_square(&t0, z)
	fiat_25519_carry_square(&t1, &t0)
	for i = 1; i < 2; i++ {
		fiat_25519_carry_square(&t1, &t1)
	}
	fiat_25519_carry_mul(&t1, z, &t1)
	fiat_25519_carry_mul(&t0, &t0, &t1)
	fiat_25519_carry_square(&t2, &t0)
	for i = 1; i < 1; i++ {
		fiat_25519_carry_square(&t2, &t2)
	}
	fiat_25519_carry_mul(&t1, &t1, &t2)
	fiat_25519_carry_square(&t2, &t1)
	for i = 1; i < 5; i++ {
		fiat_25519_carry_square(&t2, &t2)
	}
	fiat_25519_carry_mul(&t1, &t2, &t1)
	fiat_25519_carry_square(&t2, &t1)
	for i = 1; i < 10; i++ {
		fiat_25519_carry_square(&t2, &t2)
	}
	fiat_25519_carry_mul(&t2, &t2, &t1)
	fiat_25519_carry_square(&t3, &t2)
	for i = 1; i < 20; i++ {
		fiat_25519_carry_square(&t3, &t3)
	}
	fiat_25519_carry_mul(&t2, &t3, &t2)
	fiat_25519_carry_square(&t2, &t2)
	for i = 1; i < 10; i++ {
		fiat_25519_carry_square(&t2, &t2)
	}
	fiat_25519_carry_mul(&t1, &t2, &t1)
	fiat_25519_carry_square(&t2, &t1)
	for i = 1; i < 50; i++ {
		fiat_25519_carry_square(&t2, &t2)
	}
	fiat_25519_carry_mul(&t2, &t2, &t1)
	fiat_25519_carry_square(&t3, &t2)
	for i = 1; i < 100; i++ {
		fiat_25519_carry_square(&t3, &t3)
	}
	fiat_25519_carry_mul(&t2, &t3, &t2)
	fiat_25519_carry_square(&t2, &t2)
	for i = 1; i < 50; i++ {
		fiat_25519_carry_square(&t2, &t2)
	}
	fiat_25519_carry_mul(&t1, &t2, &t1)
	fiat_25519_carry_square(&t1, &t1)
	for i = 1; i < 5; i++ {
		fiat_25519_carry_square(&t1, &t1)
	}
	fiat_25519_carry_mul(out, &t1, &t0)
}

func scalarMultGeneric(out, in, base *[32]byte) {
	var e [32]byte
	var x1, x2, z2, x3, z3, tmp0, tmp1 fieldElement

	copy(e[:], base[:])
	e[31] &= 0x7f
	fiat_25519_from_bytes(&x1, &e)
	feOne(&x2)
	feCopy(&x3, &x1)
	feOne(&z3)

	copy(e[:], in[:])
	e[0] &= 248
	e[31] &= 127
	e[31] |= 64

	swap := word(0)
	for pos := 254; pos >= 0; pos-- {
		b := e[pos/8] >> uint(pos&7)
		b &= 1
		swap ^= word(b)
		feCSwap(&x2, &x3, swap)
		feCSwap(&z2, &z3, swap)
		swap = word(b)

		fiat_25519_sub(&tmp0, &x3, &z3)
		fiat_25519_sub(&tmp1, &x2, &z2)
		fiat_25519_add(&x2, &x2, &z2)
		fiat_25519_add(&z2, &x3, &z3)
		fiat_25519_carry_mul(&z3, &tmp0, &x2)
		fiat_25519_carry_mul(&z2, &z2, &tmp1)
		fiat_25519_carry_square(&tmp0, &tmp1)
		fiat_25519_carry_square(&tmp1, &x2)
		fiat_25519_add(&x3, &z3, &z2)
		fiat_25519_sub(&z2, &z3, &z2)
		fiat_25519_carry_mul(&x2, &tmp1, &tmp0)
		fiat_25519_sub(&tmp1, &tmp1, &tmp0)
		fiat_25519_carry_square(&z2, &z2)
		fiat_25519_carry_scmul_121666(&z3, &tmp1)
		fiat_25519_carry_square(&x3, &x3)
		fiat_25519_add(&tmp0, &tmp0, &z3)
		fiat_25519_carry_mul(&z3, &x1, &z2)
		fiat_25519_carry_mul(&z2, &tmp1, &tmp0)
	}

	feCSwap(&x2, &x3, swap)
	feCSwap(&z2, &z3, swap)

	feInvert(&z2, &z2)
	fiat_25519_carry_mul(&x2, &x2, &z2)
	fiat_25519_to_bytes(out, &x2)
}
