// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package salsa provides low-level access to functions in the Salsa family.
package salsa // import "golang.org/x/crypto/salsa20/salsa"

import (
	"encoding/binary"
)

// Sigma is the Salsa20 constant for 256-bit keys.
var Sigma = [16]byte{'e', 'x', 'p', 'a', 'n', 'd', ' ', '3', '2', '-', 'b', 'y', 't', 'e', ' ', 'k'}

// HSalsa20 applies the HSalsa20 core function to a 16-byte input in, 32-byte
// key k, and 16-byte constant c, and puts the result into the 32-byte array
// out.
func HSalsa20(out *[32]byte, in *[16]byte, k *[32]byte, c *[16]byte) {
	x0 := uint32(c[0]) | uint32(c[1])<<8 | uint32(c[2])<<16 | uint32(c[3])<<24
	x1 := uint32(k[0]) | uint32(k[1])<<8 | uint32(k[2])<<16 | uint32(k[3])<<24
	x2 := uint32(k[4]) | uint32(k[5])<<8 | uint32(k[6])<<16 | uint32(k[7])<<24
	x3 := uint32(k[8]) | uint32(k[9])<<8 | uint32(k[10])<<16 | uint32(k[11])<<24
	x4 := uint32(k[12]) | uint32(k[13])<<8 | uint32(k[14])<<16 | uint32(k[15])<<24
	x5 := uint32(c[4]) | uint32(c[5])<<8 | uint32(c[6])<<16 | uint32(c[7])<<24
	x6 := uint32(in[0]) | uint32(in[1])<<8 | uint32(in[2])<<16 | uint32(in[3])<<24
	x7 := uint32(in[4]) | uint32(in[5])<<8 | uint32(in[6])<<16 | uint32(in[7])<<24
	x8 := uint32(in[8]) | uint32(in[9])<<8 | uint32(in[10])<<16 | uint32(in[11])<<24
	x9 := uint32(in[12]) | uint32(in[13])<<8 | uint32(in[14])<<16 | uint32(in[15])<<24
	x10 := uint32(c[8]) | uint32(c[9])<<8 | uint32(c[10])<<16 | uint32(c[11])<<24
	x11 := uint32(k[16]) | uint32(k[17])<<8 | uint32(k[18])<<16 | uint32(k[19])<<24
	x12 := uint32(k[20]) | uint32(k[21])<<8 | uint32(k[22])<<16 | uint32(k[23])<<24
	x13 := uint32(k[24]) | uint32(k[25])<<8 | uint32(k[26])<<16 | uint32(k[27])<<24
	x14 := uint32(k[28]) | uint32(k[29])<<8 | uint32(k[30])<<16 | uint32(k[31])<<24
	x15 := uint32(c[12]) | uint32(c[13])<<8 | uint32(c[14])<<16 | uint32(c[15])<<24

	for i := 0; i < 20; i += 2 {
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

	binary.LittleEndian.PutUint32(out[0:4], x0)
	binary.LittleEndian.PutUint32(out[4:8], x5)
	binary.LittleEndian.PutUint32(out[8:12], x10)
	binary.LittleEndian.PutUint32(out[12:16], x15)
	binary.LittleEndian.PutUint32(out[16:20], x6)
	binary.LittleEndian.PutUint32(out[20:24], x7)
	binary.LittleEndian.PutUint32(out[24:28], x8)
	binary.LittleEndian.PutUint32(out[28:32], x9)
}
