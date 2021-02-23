// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !amd64 || purego || !gc
// +build !amd64 purego !gc

package sha3

// rc stores the round constants for use in the ι step.
var rc = [24]uint64{
	0x0000000000000001,
	0x0000000000008082,
	0x800000000000808A,
	0x8000000080008000,
	0x000000000000808B,
	0x0000000080000001,
	0x8000000080008081,
	0x8000000000008009,
	0x000000000000008A,
	0x0000000000000088,
	0x0000000080008009,
	0x000000008000000A,
	0x000000008000808B,
	0x800000000000008B,
	0x8000000000008089,
	0x8000000000008003,
	0x8000000000008002,
	0x8000000000000080,
	0x000000000000800A,
	0x800000008000000A,
	0x8000000080008081,
	0x8000000000008080,
	0x0000000080000001,
	0x8000000080008008,
}

// keccakF1600 applies the Keccak permutation to a 1600b-wide
// state represented as a slice of 25 uint64s.
func keccakF1600(a *[25]uint64) {
	// Implementation translated from Keccak-inplace.c
	// in the keccak reference code.
	var t, bc0, bc1, bc2, bc3, bc4, d0, d1, d2, d3, d4 uint64

	a0 := a[0]
	a1 := a[1]
	a2 := a[2]
	a3 := a[3]
	a4 := a[4]
	a5 := a[5]
	a6 := a[6]
	a7 := a[7]
	a8 := a[8]
	a9 := a[9]
	a10 := a[10]
	a11 := a[11]
	a12 := a[12]
	a13 := a[13]
	a14 := a[14]
	a15 := a[15]
	a16 := a[16]
	a17 := a[17]
	a18 := a[18]
	a19 := a[19]
	a20 := a[20]
	a21 := a[21]
	a22 := a[22]
	a23 := a[23]
	a24 := a[24]

	for i := 0; i < 24; i += 4 {
		// Combines the 5 steps in each round into 2 steps.
		// Unrolls 4 rounds per loop and spreads some steps across rounds.

		// Round 1
		bc0 = a0 ^ a5 ^ a10 ^ a15 ^ a20
		bc1 = a1 ^ a6 ^ a11 ^ a16 ^ a21
		bc2 = a2 ^ a7 ^ a12 ^ a17 ^ a22
		bc3 = a3 ^ a8 ^ a13 ^ a18 ^ a23
		bc4 = a4 ^ a9 ^ a14 ^ a19 ^ a24
		d0 = bc4 ^ (bc1<<1 | bc1>>63)
		d1 = bc0 ^ (bc2<<1 | bc2>>63)
		d2 = bc1 ^ (bc3<<1 | bc3>>63)
		d3 = bc2 ^ (bc4<<1 | bc4>>63)
		d4 = bc3 ^ (bc0<<1 | bc0>>63)

		bc0 = a0 ^ d0
		t = a6 ^ d1
		bc1 = t<<44 | t>>(64-44)
		t = a12 ^ d2
		bc2 = t<<43 | t>>(64-43)
		t = a18 ^ d3
		bc3 = t<<21 | t>>(64-21)
		t = a24 ^ d4
		bc4 = t<<14 | t>>(64-14)
		a0 = bc0 ^ (bc2 &^ bc1) ^ rc[i]
		a6 = bc1 ^ (bc3 &^ bc2)
		a12 = bc2 ^ (bc4 &^ bc3)
		a18 = bc3 ^ (bc0 &^ bc4)
		a24 = bc4 ^ (bc1 &^ bc0)

		t = a10 ^ d0
		bc2 = t<<3 | t>>(64-3)
		t = a16 ^ d1
		bc3 = t<<45 | t>>(64-45)
		t = a22 ^ d2
		bc4 = t<<61 | t>>(64-61)
		t = a3 ^ d3
		bc0 = t<<28 | t>>(64-28)
		t = a9 ^ d4
		bc1 = t<<20 | t>>(64-20)
		a10 = bc0 ^ (bc2 &^ bc1)
		a16 = bc1 ^ (bc3 &^ bc2)
		a22 = bc2 ^ (bc4 &^ bc3)
		a3 = bc3 ^ (bc0 &^ bc4)
		a9 = bc4 ^ (bc1 &^ bc0)

		t = a20 ^ d0
		bc4 = t<<18 | t>>(64-18)
		t = a1 ^ d1
		bc0 = t<<1 | t>>(64-1)
		t = a7 ^ d2
		bc1 = t<<6 | t>>(64-6)
		t = a13 ^ d3
		bc2 = t<<25 | t>>(64-25)
		t = a19 ^ d4
		bc3 = t<<8 | t>>(64-8)
		a20 = bc0 ^ (bc2 &^ bc1)
		a1 = bc1 ^ (bc3 &^ bc2)
		a7 = bc2 ^ (bc4 &^ bc3)
		a13 = bc3 ^ (bc0 &^ bc4)
		a19 = bc4 ^ (bc1 &^ bc0)

		t = a5 ^ d0
		bc1 = t<<36 | t>>(64-36)
		t = a11 ^ d1
		bc2 = t<<10 | t>>(64-10)
		t = a17 ^ d2
		bc3 = t<<15 | t>>(64-15)
		t = a23 ^ d3
		bc4 = t<<56 | t>>(64-56)
		t = a4 ^ d4
		bc0 = t<<27 | t>>(64-27)
		a5 = bc0 ^ (bc2 &^ bc1)
		a11 = bc1 ^ (bc3 &^ bc2)
		a17 = bc2 ^ (bc4 &^ bc3)
		a23 = bc3 ^ (bc0 &^ bc4)
		a4 = bc4 ^ (bc1 &^ bc0)

		t = a15 ^ d0
		bc3 = t<<41 | t>>(64-41)
		t = a21 ^ d1
		bc4 = t<<2 | t>>(64-2)
		t = a2 ^ d2
		bc0 = t<<62 | t>>(64-62)
		t = a8 ^ d3
		bc1 = t<<55 | t>>(64-55)
		t = a14 ^ d4
		bc2 = t<<39 | t>>(64-39)
		a15 = bc0 ^ (bc2 &^ bc1)
		a21 = bc1 ^ (bc3 &^ bc2)
		a2 = bc2 ^ (bc4 &^ bc3)
		a8 = bc3 ^ (bc0 &^ bc4)
		a14 = bc4 ^ (bc1 &^ bc0)

		// Round 2
		bc0 = a0 ^ a5 ^ a10 ^ a15 ^ a20
		bc1 = a1 ^ a6 ^ a11 ^ a16 ^ a21
		bc2 = a2 ^ a7 ^ a12 ^ a17 ^ a22
		bc3 = a3 ^ a8 ^ a13 ^ a18 ^ a23
		bc4 = a4 ^ a9 ^ a14 ^ a19 ^ a24
		d0 = bc4 ^ (bc1<<1 | bc1>>63)
		d1 = bc0 ^ (bc2<<1 | bc2>>63)
		d2 = bc1 ^ (bc3<<1 | bc3>>63)
		d3 = bc2 ^ (bc4<<1 | bc4>>63)
		d4 = bc3 ^ (bc0<<1 | bc0>>63)

		bc0 = a0 ^ d0
		t = a16 ^ d1
		bc1 = t<<44 | t>>(64-44)
		t = a7 ^ d2
		bc2 = t<<43 | t>>(64-43)
		t = a23 ^ d3
		bc3 = t<<21 | t>>(64-21)
		t = a14 ^ d4
		bc4 = t<<14 | t>>(64-14)
		a0 = bc0 ^ (bc2 &^ bc1) ^ rc[i+1]
		a16 = bc1 ^ (bc3 &^ bc2)
		a7 = bc2 ^ (bc4 &^ bc3)
		a23 = bc3 ^ (bc0 &^ bc4)
		a14 = bc4 ^ (bc1 &^ bc0)

		t = a20 ^ d0
		bc2 = t<<3 | t>>(64-3)
		t = a11 ^ d1
		bc3 = t<<45 | t>>(64-45)
		t = a2 ^ d2
		bc4 = t<<61 | t>>(64-61)
		t = a18 ^ d3
		bc0 = t<<28 | t>>(64-28)
		t = a9 ^ d4
		bc1 = t<<20 | t>>(64-20)
		a20 = bc0 ^ (bc2 &^ bc1)
		a11 = bc1 ^ (bc3 &^ bc2)
		a2 = bc2 ^ (bc4 &^ bc3)
		a18 = bc3 ^ (bc0 &^ bc4)
		a9 = bc4 ^ (bc1 &^ bc0)

		t = a15 ^ d0
		bc4 = t<<18 | t>>(64-18)
		t = a6 ^ d1
		bc0 = t<<1 | t>>(64-1)
		t = a22 ^ d2
		bc1 = t<<6 | t>>(64-6)
		t = a13 ^ d3
		bc2 = t<<25 | t>>(64-25)
		t = a4 ^ d4
		bc3 = t<<8 | t>>(64-8)
		a15 = bc0 ^ (bc2 &^ bc1)
		a6 = bc1 ^ (bc3 &^ bc2)
		a22 = bc2 ^ (bc4 &^ bc3)
		a13 = bc3 ^ (bc0 &^ bc4)
		a4 = bc4 ^ (bc1 &^ bc0)

		t = a10 ^ d0
		bc1 = t<<36 | t>>(64-36)
		t = a1 ^ d1
		bc2 = t<<10 | t>>(64-10)
		t = a17 ^ d2
		bc3 = t<<15 | t>>(64-15)
		t = a8 ^ d3
		bc4 = t<<56 | t>>(64-56)
		t = a24 ^ d4
		bc0 = t<<27 | t>>(64-27)
		a10 = bc0 ^ (bc2 &^ bc1)
		a1 = bc1 ^ (bc3 &^ bc2)
		a17 = bc2 ^ (bc4 &^ bc3)
		a8 = bc3 ^ (bc0 &^ bc4)
		a24 = bc4 ^ (bc1 &^ bc0)

		t = a5 ^ d0
		bc3 = t<<41 | t>>(64-41)
		t = a21 ^ d1
		bc4 = t<<2 | t>>(64-2)
		t = a12 ^ d2
		bc0 = t<<62 | t>>(64-62)
		t = a3 ^ d3
		bc1 = t<<55 | t>>(64-55)
		t = a19 ^ d4
		bc2 = t<<39 | t>>(64-39)
		a5 = bc0 ^ (bc2 &^ bc1)
		a21 = bc1 ^ (bc3 &^ bc2)
		a12 = bc2 ^ (bc4 &^ bc3)
		a3 = bc3 ^ (bc0 &^ bc4)
		a19 = bc4 ^ (bc1 &^ bc0)

		// Round 3
		bc0 = a0 ^ a5 ^ a10 ^ a15 ^ a20
		bc1 = a1 ^ a6 ^ a11 ^ a16 ^ a21
		bc2 = a2 ^ a7 ^ a12 ^ a17 ^ a22
		bc3 = a3 ^ a8 ^ a13 ^ a18 ^ a23
		bc4 = a4 ^ a9 ^ a14 ^ a19 ^ a24
		d0 = bc4 ^ (bc1<<1 | bc1>>63)
		d1 = bc0 ^ (bc2<<1 | bc2>>63)
		d2 = bc1 ^ (bc3<<1 | bc3>>63)
		d3 = bc2 ^ (bc4<<1 | bc4>>63)
		d4 = bc3 ^ (bc0<<1 | bc0>>63)

		bc0 = a0 ^ d0
		t = a11 ^ d1
		bc1 = t<<44 | t>>(64-44)
		t = a22 ^ d2
		bc2 = t<<43 | t>>(64-43)
		t = a8 ^ d3
		bc3 = t<<21 | t>>(64-21)
		t = a19 ^ d4
		bc4 = t<<14 | t>>(64-14)
		a0 = bc0 ^ (bc2 &^ bc1) ^ rc[i+2]
		a11 = bc1 ^ (bc3 &^ bc2)
		a22 = bc2 ^ (bc4 &^ bc3)
		a8 = bc3 ^ (bc0 &^ bc4)
		a19 = bc4 ^ (bc1 &^ bc0)

		t = a15 ^ d0
		bc2 = t<<3 | t>>(64-3)
		t = a1 ^ d1
		bc3 = t<<45 | t>>(64-45)
		t = a12 ^ d2
		bc4 = t<<61 | t>>(64-61)
		t = a23 ^ d3
		bc0 = t<<28 | t>>(64-28)
		t = a9 ^ d4
		bc1 = t<<20 | t>>(64-20)
		a15 = bc0 ^ (bc2 &^ bc1)
		a1 = bc1 ^ (bc3 &^ bc2)
		a12 = bc2 ^ (bc4 &^ bc3)
		a23 = bc3 ^ (bc0 &^ bc4)
		a9 = bc4 ^ (bc1 &^ bc0)

		t = a5 ^ d0
		bc4 = t<<18 | t>>(64-18)
		t = a16 ^ d1
		bc0 = t<<1 | t>>(64-1)
		t = a2 ^ d2
		bc1 = t<<6 | t>>(64-6)
		t = a13 ^ d3
		bc2 = t<<25 | t>>(64-25)
		t = a24 ^ d4
		bc3 = t<<8 | t>>(64-8)
		a5 = bc0 ^ (bc2 &^ bc1)
		a16 = bc1 ^ (bc3 &^ bc2)
		a2 = bc2 ^ (bc4 &^ bc3)
		a13 = bc3 ^ (bc0 &^ bc4)
		a24 = bc4 ^ (bc1 &^ bc0)

		t = a20 ^ d0
		bc1 = t<<36 | t>>(64-36)
		t = a6 ^ d1
		bc2 = t<<10 | t>>(64-10)
		t = a17 ^ d2
		bc3 = t<<15 | t>>(64-15)
		t = a3 ^ d3
		bc4 = t<<56 | t>>(64-56)
		t = a14 ^ d4
		bc0 = t<<27 | t>>(64-27)
		a20 = bc0 ^ (bc2 &^ bc1)
		a6 = bc1 ^ (bc3 &^ bc2)
		a17 = bc2 ^ (bc4 &^ bc3)
		a3 = bc3 ^ (bc0 &^ bc4)
		a14 = bc4 ^ (bc1 &^ bc0)

		t = a10 ^ d0
		bc3 = t<<41 | t>>(64-41)
		t = a21 ^ d1
		bc4 = t<<2 | t>>(64-2)
		t = a7 ^ d2
		bc0 = t<<62 | t>>(64-62)
		t = a18 ^ d3
		bc1 = t<<55 | t>>(64-55)
		t = a4 ^ d4
		bc2 = t<<39 | t>>(64-39)
		a10 = bc0 ^ (bc2 &^ bc1)
		a21 = bc1 ^ (bc3 &^ bc2)
		a7 = bc2 ^ (bc4 &^ bc3)
		a18 = bc3 ^ (bc0 &^ bc4)
		a4 = bc4 ^ (bc1 &^ bc0)

		// Round 4
		bc0 = a0 ^ a5 ^ a10 ^ a15 ^ a20
		bc1 = a1 ^ a6 ^ a11 ^ a16 ^ a21
		bc2 = a2 ^ a7 ^ a12 ^ a17 ^ a22
		bc3 = a3 ^ a8 ^ a13 ^ a18 ^ a23
		bc4 = a4 ^ a9 ^ a14 ^ a19 ^ a24
		d0 = bc4 ^ (bc1<<1 | bc1>>63)
		d1 = bc0 ^ (bc2<<1 | bc2>>63)
		d2 = bc1 ^ (bc3<<1 | bc3>>63)
		d3 = bc2 ^ (bc4<<1 | bc4>>63)
		d4 = bc3 ^ (bc0<<1 | bc0>>63)

		bc0 = a0 ^ d0
		t = a1 ^ d1
		bc1 = t<<44 | t>>(64-44)
		t = a2 ^ d2
		bc2 = t<<43 | t>>(64-43)
		t = a3 ^ d3
		bc3 = t<<21 | t>>(64-21)
		t = a4 ^ d4
		bc4 = t<<14 | t>>(64-14)
		a0 = bc0 ^ (bc2 &^ bc1) ^ rc[i+3]
		a1 = bc1 ^ (bc3 &^ bc2)
		a2 = bc2 ^ (bc4 &^ bc3)
		a3 = bc3 ^ (bc0 &^ bc4)
		a4 = bc4 ^ (bc1 &^ bc0)

		t = a5 ^ d0
		bc2 = t<<3 | t>>(64-3)
		t = a6 ^ d1
		bc3 = t<<45 | t>>(64-45)
		t = a7 ^ d2
		bc4 = t<<61 | t>>(64-61)
		t = a8 ^ d3
		bc0 = t<<28 | t>>(64-28)
		t = a9 ^ d4
		bc1 = t<<20 | t>>(64-20)
		a5 = bc0 ^ (bc2 &^ bc1)
		a6 = bc1 ^ (bc3 &^ bc2)
		a7 = bc2 ^ (bc4 &^ bc3)
		a8 = bc3 ^ (bc0 &^ bc4)
		a9 = bc4 ^ (bc1 &^ bc0)

		t = a10 ^ d0
		bc4 = t<<18 | t>>(64-18)
		t = a11 ^ d1
		bc0 = t<<1 | t>>(64-1)
		t = a12 ^ d2
		bc1 = t<<6 | t>>(64-6)
		t = a13 ^ d3
		bc2 = t<<25 | t>>(64-25)
		t = a14 ^ d4
		bc3 = t<<8 | t>>(64-8)
		a10 = bc0 ^ (bc2 &^ bc1)
		a11 = bc1 ^ (bc3 &^ bc2)
		a12 = bc2 ^ (bc4 &^ bc3)
		a13 = bc3 ^ (bc0 &^ bc4)
		a14 = bc4 ^ (bc1 &^ bc0)

		t = a15 ^ d0
		bc1 = t<<36 | t>>(64-36)
		t = a16 ^ d1
		bc2 = t<<10 | t>>(64-10)
		t = a17 ^ d2
		bc3 = t<<15 | t>>(64-15)
		t = a18 ^ d3
		bc4 = t<<56 | t>>(64-56)
		t = a19 ^ d4
		bc0 = t<<27 | t>>(64-27)
		a15 = bc0 ^ (bc2 &^ bc1)
		a16 = bc1 ^ (bc3 &^ bc2)
		a17 = bc2 ^ (bc4 &^ bc3)
		a18 = bc3 ^ (bc0 &^ bc4)
		a19 = bc4 ^ (bc1 &^ bc0)

		t = a20 ^ d0
		bc3 = t<<41 | t>>(64-41)
		t = a21 ^ d1
		bc4 = t<<2 | t>>(64-2)
		t = a22 ^ d2
		bc0 = t<<62 | t>>(64-62)
		t = a23 ^ d3
		bc1 = t<<55 | t>>(64-55)
		t = a24 ^ d4
		bc2 = t<<39 | t>>(64-39)
		a20 = bc0 ^ (bc2 &^ bc1)
		a21 = bc1 ^ (bc3 &^ bc2)
		a22 = bc2 ^ (bc4 &^ bc3)
		a23 = bc3 ^ (bc0 &^ bc4)
		a24 = bc4 ^ (bc1 &^ bc0)
	}
	a[0] = a0
	a[1] = a1
	a[2] = a2
	a[3] = a3
	a[4] = a4
	a[5] = a5
	a[6] = a6
	a[7] = a7
	a[8] = a8
	a[9] = a9
	a[10] = a10
	a[11] = a11
	a[12] = a12
	a[13] = a13
	a[14] = a14
	a[15] = a15
	a[16] = a16
	a[17] = a17
	a[18] = a18
	a[19] = a19
	a[20] = a20
	a[21] = a21
	a[22] = a22
	a[23] = a23
	a[24] = a24
}
