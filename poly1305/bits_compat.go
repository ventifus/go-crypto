// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !go1.12

package poly1305

// Generic fallbacks for the math/bits intrinsics added in Go 1.12.

func bitsAdd64(x, y, carry uint64) (sum, carryOut uint64) {
	const mask32 = 1<<32 - 1
	x0 := x & mask32
	x1 := x >> 32
	y0 := y & mask32
	y1 := y >> 32
	sum0 := (x0 + y0 + carry) & mask32
	c := ((x0 & y0) | ((x0 | y0) & ^sum0)) >> 31
	sum1 := (x1 + y1 + c) & mask32
	carryOut = ((x1 & y1) | ((x1 | y1) & ^sum1)) >> 31
	sum = (sum1 << 32) | sum0
	return
}

func bitsSub64(x, y, borrow uint64) (diff, borrowOut uint64) {
	const mask32 = 1<<32 - 1
	x0 := x & mask32
	x1 := x >> 32
	y0 := y & mask32
	y1 := y >> 32
	diff0 := (x0 - y0 - borrow) & mask32
	b := ((^x0 & y0) | (^(x0 ^ y0) & diff0)) >> 31
	diff1 := (x1 - y1 - b) & mask32
	borrowOut = ((^x1 & y1) | (^(x1 ^ y1) & diff1)) >> 31
	diff = (diff1 << 32) | diff0
	return
}

func bitsMul64(x, y uint64) (hi, lo uint64) {
	const mask32 = 1<<32 - 1
	x0 := x & mask32
	x1 := x >> 32
	y0 := y & mask32
	y1 := y >> 32
	w0 := x0 * y0
	t := x1*y0 + w0>>32
	w1 := t & mask32
	w2 := t >> 32
	w1 += x0 * y1
	hi = x1*y1 + w2 + w1>>32
	lo = x * y
	return
}
