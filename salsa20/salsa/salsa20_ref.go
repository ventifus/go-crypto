// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package salsa

import (
	"encoding/binary"
	"math/bits"
)

const rounds = 20

func quarterRound(a, b, c, d uint32) (uint32, uint32, uint32, uint32) {
	b ^= bits.RotateLeft32(a+d, 7)
	c ^= bits.RotateLeft32(b+a, 9)
	d ^= bits.RotateLeft32(c+b, 13)
	a ^= bits.RotateLeft32(d+c, 18)
	return a, b, c, d
}

// core applies the Salsa20 core function to 16-byte input in, 32-byte key k,
// and 16-byte constant c, and puts the result into 64-byte array out.
func core(out *[64]byte, in *[16]byte, k *[32]byte, c *[16]byte) {
	j0 := uint32(c[0]) | uint32(c[1])<<8 | uint32(c[2])<<16 | uint32(c[3])<<24
	j1 := uint32(k[0]) | uint32(k[1])<<8 | uint32(k[2])<<16 | uint32(k[3])<<24
	j2 := uint32(k[4]) | uint32(k[5])<<8 | uint32(k[6])<<16 | uint32(k[7])<<24
	j3 := uint32(k[8]) | uint32(k[9])<<8 | uint32(k[10])<<16 | uint32(k[11])<<24
	j4 := uint32(k[12]) | uint32(k[13])<<8 | uint32(k[14])<<16 | uint32(k[15])<<24
	j5 := uint32(c[4]) | uint32(c[5])<<8 | uint32(c[6])<<16 | uint32(c[7])<<24
	j6 := uint32(in[0]) | uint32(in[1])<<8 | uint32(in[2])<<16 | uint32(in[3])<<24
	j7 := uint32(in[4]) | uint32(in[5])<<8 | uint32(in[6])<<16 | uint32(in[7])<<24
	j8 := uint32(in[8]) | uint32(in[9])<<8 | uint32(in[10])<<16 | uint32(in[11])<<24
	j9 := uint32(in[12]) | uint32(in[13])<<8 | uint32(in[14])<<16 | uint32(in[15])<<24
	j10 := uint32(c[8]) | uint32(c[9])<<8 | uint32(c[10])<<16 | uint32(c[11])<<24
	j11 := uint32(k[16]) | uint32(k[17])<<8 | uint32(k[18])<<16 | uint32(k[19])<<24
	j12 := uint32(k[20]) | uint32(k[21])<<8 | uint32(k[22])<<16 | uint32(k[23])<<24
	j13 := uint32(k[24]) | uint32(k[25])<<8 | uint32(k[26])<<16 | uint32(k[27])<<24
	j14 := uint32(k[28]) | uint32(k[29])<<8 | uint32(k[30])<<16 | uint32(k[31])<<24
	j15 := uint32(c[12]) | uint32(c[13])<<8 | uint32(c[14])<<16 | uint32(c[15])<<24

	x0, x1, x2, x3, x4, x5, x6, x7, x8 := j0, j1, j2, j3, j4, j5, j6, j7, j8
	x9, x10, x11, x12, x13, x14, x15 := j9, j10, j11, j12, j13, j14, j15

	for i := 0; i < rounds; i += 2 {
		// columns
		x0, x4, x8, x12 = quarterRound(x0, x4, x8, x12)
		x5, x9, x13, x1 = quarterRound(x5, x9, x13, x1)
		x10, x14, x2, x6 = quarterRound(x10, x14, x2, x6)
		x15, x3, x7, x11 = quarterRound(x15, x3, x7, x11)

		// rows
		x0, x1, x2, x3 = quarterRound(x0, x1, x2, x3)
		x5, x6, x7, x4 = quarterRound(x5, x6, x7, x4)
		x10, x11, x8, x9 = quarterRound(x10, x11, x8, x9)
		x15, x12, x13, x14 = quarterRound(x15, x12, x13, x14)
	}
	x0 += j0
	x1 += j1
	x2 += j2
	x3 += j3
	x4 += j4
	x5 += j5
	x6 += j6
	x7 += j7
	x8 += j8
	x9 += j9
	x10 += j10
	x11 += j11
	x12 += j12
	x13 += j13
	x14 += j14
	x15 += j15

	binary.LittleEndian.PutUint32(out[0:4], x0)
	binary.LittleEndian.PutUint32(out[4:8], x1)
	binary.LittleEndian.PutUint32(out[8:12], x2)
	binary.LittleEndian.PutUint32(out[12:16], x3)
	binary.LittleEndian.PutUint32(out[16:20], x4)
	binary.LittleEndian.PutUint32(out[20:24], x5)
	binary.LittleEndian.PutUint32(out[24:28], x6)
	binary.LittleEndian.PutUint32(out[28:32], x7)
	binary.LittleEndian.PutUint32(out[32:36], x8)
	binary.LittleEndian.PutUint32(out[36:40], x9)
	binary.LittleEndian.PutUint32(out[40:44], x10)
	binary.LittleEndian.PutUint32(out[44:48], x11)
	binary.LittleEndian.PutUint32(out[48:52], x12)
	binary.LittleEndian.PutUint32(out[52:56], x13)
	binary.LittleEndian.PutUint32(out[56:60], x14)
	binary.LittleEndian.PutUint32(out[60:64], x15)
}

// genericXORKeyStream is the generic implementation of XORKeyStream to be used
// when no assembly implementation is available.
func genericXORKeyStream(out, in []byte, counter *[16]byte, key *[32]byte) {
	var block [64]byte
	var counterCopy [16]byte
	copy(counterCopy[:], counter[:])

	for len(in) >= 64 {
		core(&block, &counterCopy, key, &Sigma)
		for i, x := range block {
			out[i] = in[i] ^ x
		}
		u := uint32(1)
		for i := 8; i < 16; i++ {
			u += uint32(counterCopy[i])
			counterCopy[i] = byte(u)
			u >>= 8
		}
		in = in[64:]
		out = out[64:]
	}

	if len(in) > 0 {
		core(&block, &counterCopy, key, &Sigma)
		for i, v := range in {
			out[i] = v ^ block[i]
		}
	}
}
