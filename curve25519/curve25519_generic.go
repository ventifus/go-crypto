// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package curve25519

// This code is a port of the public domain, "ref10" implementation of
// curve25519 from SUPERCOP 20130419 by D. J. Bernstein.

// feInvert sets out = z^-1.
func feInvert(out, z *fieldElement) {
	var t0, t1, t2, t3 fieldElement
	var i int

	feSquare(&t0, z)
	for i = 1; i < 1; i++ {
		feSquare(&t0, &t0)
	}
	feSquare(&t1, &t0)
	for i = 1; i < 2; i++ {
		feSquare(&t1, &t1)
	}
	feMul(&t1, z, &t1)
	feMul(&t0, &t0, &t1)
	feSquare(&t2, &t0)
	for i = 1; i < 1; i++ {
		feSquare(&t2, &t2)
	}
	feMul(&t1, &t1, &t2)
	feSquare(&t2, &t1)
	for i = 1; i < 5; i++ {
		feSquare(&t2, &t2)
	}
	feMul(&t1, &t2, &t1)
	feSquare(&t2, &t1)
	for i = 1; i < 10; i++ {
		feSquare(&t2, &t2)
	}
	feMul(&t2, &t2, &t1)
	feSquare(&t3, &t2)
	for i = 1; i < 20; i++ {
		feSquare(&t3, &t3)
	}
	feMul(&t2, &t3, &t2)
	feSquare(&t2, &t2)
	for i = 1; i < 10; i++ {
		feSquare(&t2, &t2)
	}
	feMul(&t1, &t2, &t1)
	feSquare(&t2, &t1)
	for i = 1; i < 50; i++ {
		feSquare(&t2, &t2)
	}
	feMul(&t2, &t2, &t1)
	feSquare(&t3, &t2)
	for i = 1; i < 100; i++ {
		feSquare(&t3, &t3)
	}
	feMul(&t2, &t3, &t2)
	feSquare(&t2, &t2)
	for i = 1; i < 50; i++ {
		feSquare(&t2, &t2)
	}
	feMul(&t1, &t2, &t1)
	feSquare(&t1, &t1)
	for i = 1; i < 5; i++ {
		feSquare(&t1, &t1)
	}
	feMul(out, &t1, &t0)
}

func scalarMultGeneric(out, scalar, point *[32]byte) {
	var e [32]byte

	copy(e[:], scalar[:])
	e[0] &= 248
	e[31] &= 127
	e[31] |= 64

	var x1, x2, z2, x3, z3, tmp0, tmp1 fieldElement
	feFromBytes(&x1, point)
	feOne(&x2)
	feZero(&z2) // XXX: implicit
	feCopy(&x3, &x1)
	feOne(&z3)

	swap := byte(0)
	for pos := 254; pos >= 0; pos-- {
		b := e[pos/8] >> uint(pos&7)
		b &= 1
		swap ^= b
		feCSwap(&x2, &x3, swap)
		feCSwap(&z2, &z3, swap)
		swap = b

		feSub(&tmp0, &x3, &z3)
		feSub(&tmp1, &x2, &z2)
		feAdd(&x2, &x2, &z2)
		feAdd(&z2, &x3, &z3)
		feMul(&z3, &tmp0, &x2)
		feMul(&z2, &z2, &tmp1)
		feSquare(&tmp0, &tmp1)
		feSquare(&tmp1, &x2)
		feAdd(&x3, &z3, &z2)
		feSub(&z2, &z3, &z2)
		feMul(&x2, &tmp1, &tmp0)
		feSub(&tmp1, &tmp1, &tmp0)
		feSquare(&z2, &z2)
		feMul121666(&z3, &tmp1)
		feSquare(&x3, &x3)
		feAdd(&tmp0, &tmp0, &z3)
		feMul(&z3, &x1, &z2)
		feMul(&z2, &tmp1, &tmp0)
	}

	feCSwap(&x2, &x3, swap)
	feCSwap(&z2, &z3, swap)

	feInvert(&z2, &z2)
	feMul(&x2, &x2, &z2)
	feToBytes(out, &x2)
}
