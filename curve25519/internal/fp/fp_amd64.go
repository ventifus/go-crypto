// Copyright (c) 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build amd64,!gccgo,!appengine

// Package fp provides prime field arithmetic for GF(2^255-19).
package fp

import (
	"golang.org/x/sys/cpu"
)

// Size in bytes of an element
const Size = 32

// Elt represents an element of the field
type Elt [Size]byte

// P is the prime modulus 2^255-19
var P = Elt{
	0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
}

var hasBmi2Adx bool

func init() { hasBmi2Adx = cpu.X86.HasBMI2 && cpu.X86.HasADX }

// Inv calculates z = 1/x mod p
func Inv(z, x *Elt) {
	x0, x1, x2 := &Elt{}, &Elt{}, &Elt{}
	Sqr(x1, x)
	Sqr(x0, x1)
	Sqr(x0, x0)
	Mul(x0, x0, x)
	Mul(z, x0, x1)
	Sqr(x1, z)
	Mul(x0, x0, x1)
	Sqr(x1, x0)
	for i := 0; i < 4; i++ {
		Sqr(x1, x1)
	}
	Mul(x0, x0, x1)
	Sqr(x1, x0)
	for i := 0; i < 9; i++ {
		Sqr(x1, x1)
	}
	Mul(x1, x1, x0)
	Sqr(x2, x1)
	for i := 0; i < 19; i++ {
		Sqr(x2, x2)
	}
	Mul(x2, x2, x1)
	for i := 0; i < 10; i++ {
		Sqr(x2, x2)
	}
	Mul(x2, x2, x0)
	Sqr(x0, x2)
	for i := 0; i < 49; i++ {
		Sqr(x0, x0)
	}
	Mul(x0, x0, x2)
	Sqr(x1, x0)
	for i := 0; i < 99; i++ {
		Sqr(x1, x1)
	}
	Mul(x1, x1, x0)
	for i := 0; i < 50; i++ {
		Sqr(x1, x1)
	}
	Mul(x1, x1, x2)
	for i := 0; i < 5; i++ {
		Sqr(x1, x1)
	}
	Mul(z, z, x1)
}

// Cmov assigns y to x if n is non-zero 0
//go:noescape
func Cmov(x, y *Elt, n uint)

// Cswap interchages x and y if n is non-zero 0
//go:noescape
func Cswap(x, y *Elt, n uint)

// Add calculates z = x+y mod p
//go:noescape
func Add(z, x, y *Elt)

// Sub calculates z = x-y mod p
//go:noescape
func Sub(z, x, y *Elt)

// Mul calculates z = x*y mod p
//go:noescape
func Mul(z, x, y *Elt)

// Sqr calculates z = x^2 mod p
//go:noescape
func Sqr(z, x *Elt)

// Modp calculates z is between [0,p-1]
//go:noescape
func Modp(z *Elt)

// MulA24 calculates z = ((A-2)/4)*x mod p = 121666*x mod p
//go:noescape
func MulA24(z, x *Elt)
