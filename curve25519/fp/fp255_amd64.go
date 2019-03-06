// Copyright (c) 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build amd64,!gccgo,!appengine

// Package fp provides prime field arithmetic for GF(2^255-19).
package fp

import (
	"crypto/rand"
	"crypto/subtle"
	"fmt"
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

func (e Elt) String() string {
	s := "0x"
	for i := Size - 1; i >= 0; i-- {
		s += fmt.Sprintf("%02x", e[i])
	}
	return s
}

// Field is GF(2^255-19)
type Field interface {
	Rand(z *Elt)         // z = random(0,2^32)
	Neg(z, x *Elt)       // z = -x mod p
	Add(z, x, y *Elt)    // z = x+y mod p
	Sub(z, x, y *Elt)    // z = x-y mod p
	Mul(z, x, y *Elt)    // z = x*y mod p
	Sqr(z, x *Elt)       // z = x^2 mod p
	Inv(z, x *Elt)       // z = 1/x mod p
	Modp(z *Elt)         // z is between [0,p-1]
	sqrn(z *Elt, n uint) // z = x^{2^n} mod p
}

// Fp255 returns a field interface for arithmetic operations.
func Fp255() Field {
	if cpu.X86.HasADX && cpu.X86.HasBMI2 {
		return fieldBmi2Adx{}
	}
	return field{}
}

type field struct{}
type fieldBmi2Adx struct{ field }

func (f field) Rand(z *Elt)         { _, _ = rand.Read((*z)[:]) }
func (f field) Neg(z, x *Elt)       { f.Sub(z, x, &P) }
func (f field) Equal(x, y *Elt) int { return subtle.ConstantTimeCompare(x[:], y[:]) }

func inv(f Field, z, x *Elt) {
	var x0, x1, x2 Elt
	f.Sqr(&x1, x)
	f.Sqr(&x0, &x1)
	f.Sqr(&x0, &x0)
	f.Mul(&x0, &x0, x)
	f.Mul(z, &x0, &x1)
	f.Sqr(&x1, z)
	f.Mul(&x0, &x0, &x1)
	x1 = x0
	f.sqrn(&x1, 5)
	f.Mul(&x0, &x0, &x1)
	x1 = x0
	f.sqrn(&x1, 10)
	f.Mul(&x1, &x1, &x0)
	x2 = x1
	f.sqrn(&x2, 20)
	f.Mul(&x2, &x2, &x1)
	f.sqrn(&x2, 10)
	f.Mul(&x2, &x2, &x0)
	x0 = x2
	f.sqrn(&x0, 50)
	f.Mul(&x0, &x0, &x2)
	x1 = x0
	f.sqrn(&x1, 100)
	f.Mul(&x1, &x1, &x0)
	f.sqrn(&x1, 50)
	f.Mul(&x1, &x1, &x2)
	f.sqrn(&x1, 5)
	f.Mul(z, z, &x1)
}

func (f field) Inv(z, x *Elt)        { inv(f, z, x) }
func (f fieldBmi2Adx) Inv(z, x *Elt) { inv(f, z, x) }

//go:noescape
func (field) Modp(z *Elt)

//go:noescape
func (field) Sub(z, x, y *Elt)

//go:noescape
func (field) Add(z, x, y *Elt)

//go:noescape
func (field) Mul(z, x, y *Elt)

//go:noescape
func (field) Sqr(z, x *Elt)

//go:noescape
func (field) sqrn(z *Elt, n uint)

//go:noescape
func (fieldBmi2Adx) Add(z, x, y *Elt)

//go:noescape
func (fieldBmi2Adx) Mul(z, x, y *Elt)

//go:noescape
func (fieldBmi2Adx) Sqr(z, x *Elt)

//go:noescape
func (fieldBmi2Adx) sqrn(z *Elt, n uint)
