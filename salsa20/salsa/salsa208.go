// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package salsa

import "encoding/binary"

// Core208 applies the Salsa20/8 core function to the 64-byte array in and puts
// the result into the 64-byte array out. The input and output may be the same array.
func Core208(out *[64]byte, in *[64]byte) {
	j0 := uint32(in[0]) | uint32(in[1])<<8 | uint32(in[2])<<16 | uint32(in[3])<<24
	j1 := uint32(in[4]) | uint32(in[5])<<8 | uint32(in[6])<<16 | uint32(in[7])<<24
	j2 := uint32(in[8]) | uint32(in[9])<<8 | uint32(in[10])<<16 | uint32(in[11])<<24
	j3 := uint32(in[12]) | uint32(in[13])<<8 | uint32(in[14])<<16 | uint32(in[15])<<24
	j4 := uint32(in[16]) | uint32(in[17])<<8 | uint32(in[18])<<16 | uint32(in[19])<<24
	j5 := uint32(in[20]) | uint32(in[21])<<8 | uint32(in[22])<<16 | uint32(in[23])<<24
	j6 := uint32(in[24]) | uint32(in[25])<<8 | uint32(in[26])<<16 | uint32(in[27])<<24
	j7 := uint32(in[28]) | uint32(in[29])<<8 | uint32(in[30])<<16 | uint32(in[31])<<24
	j8 := uint32(in[32]) | uint32(in[33])<<8 | uint32(in[34])<<16 | uint32(in[35])<<24
	j9 := uint32(in[36]) | uint32(in[37])<<8 | uint32(in[38])<<16 | uint32(in[39])<<24
	j10 := uint32(in[40]) | uint32(in[41])<<8 | uint32(in[42])<<16 | uint32(in[43])<<24
	j11 := uint32(in[44]) | uint32(in[45])<<8 | uint32(in[46])<<16 | uint32(in[47])<<24
	j12 := uint32(in[48]) | uint32(in[49])<<8 | uint32(in[50])<<16 | uint32(in[51])<<24
	j13 := uint32(in[52]) | uint32(in[53])<<8 | uint32(in[54])<<16 | uint32(in[55])<<24
	j14 := uint32(in[56]) | uint32(in[57])<<8 | uint32(in[58])<<16 | uint32(in[59])<<24
	j15 := uint32(in[60]) | uint32(in[61])<<8 | uint32(in[62])<<16 | uint32(in[63])<<24

	x0, x1, x2, x3, x4, x5, x6, x7, x8 := j0, j1, j2, j3, j4, j5, j6, j7, j8
	x9, x10, x11, x12, x13, x14, x15 := j9, j10, j11, j12, j13, j14, j15

	for i := 0; i < 8; i += 2 {
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
