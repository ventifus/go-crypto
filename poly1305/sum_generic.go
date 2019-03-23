// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This file provides the generic implementation of Sum and MAC, which should
// be used if no assembly implementations are available.

package poly1305

import (
	"encoding/binary"
	"math/bits"
)

const (
	msgBlock   = 1
	finalBlock = 0
)

// sumGeneric generates an authenticator for msg using a one-time key and
// puts the 16-byte result into out.
func sumGeneric(out *[TagSize]byte, msg []byte, key *[32]byte) {
	h := newMACGeneric(key)
	h.Write(msg)
	h.Sum(out)
}

func newMACGeneric(key *[32]byte) (h macGeneric) {
	initializeGeneric(key, &h.r, &h.s)
	return
}

type state struct {
	h [3]uint64
	r [2]uint64
	s [2]uint64
}

type macGeneric struct {
	state
	buffer [TagSize]byte
	offset int
}

func (h *macGeneric) Write(p []byte) (n int, err error) {
	n = len(p)
	if h.offset > 0 {
		remaining := TagSize - h.offset
		if n < remaining {
			h.offset += copy(h.buffer[h.offset:], p)
			return n, nil
		}
		copy(h.buffer[h.offset:], p[:remaining])
		p = p[remaining:]
		h.offset = 0
		updateGeneric(h.buffer[:], msgBlock, &h.h, &h.r)
	}
	if nn := len(p) - (len(p) % TagSize); nn > 0 {
		updateGeneric(p, msgBlock, &h.h, &h.r)
		p = p[nn:]
	}
	if len(p) > 0 {
		h.offset += copy(h.buffer[h.offset:], p)
	}
	return n, nil
}

func (h *macGeneric) Sum(out *[16]byte) {
	H, R := h.h, h.r
	if h.offset > 0 {
		var buffer [TagSize]byte
		copy(buffer[:], h.buffer[:h.offset])
		buffer[h.offset] = 1 // invariant: h.offset < TagSize
		updateGeneric(buffer[:], finalBlock, &H, &R)
	}
	finalizeGeneric(out, &H, &h.s)
}

func initializeGeneric(key *[32]byte, r, s *[2]uint64) {
	r[0] = binary.LittleEndian.Uint64(key[0:8]) & 0x0FFFFFFC0FFFFFFF
	r[1] = binary.LittleEndian.Uint64(key[8:16]) & 0x0FFFFFFC0FFFFFFC
	s[0] = binary.LittleEndian.Uint64(key[16:24])
	s[1] = binary.LittleEndian.Uint64(key[24:32])
}

type uint128 struct {
	lo, hi uint64
}

func mul64(a, b uint64) uint128 {
	hi, lo := bits.Mul64(a, b)
	return uint128{lo, hi}
}

func add128(a, b uint128) uint128 {
	lo, c := bits.Add64(a.lo, b.lo, 0)
	hi, c := bits.Add64(a.hi, b.hi, c)
	if c != 0 {
		panic("poly1305: unexpected overflow")
	}
	return uint128{lo, hi}
}

func shiftRight2(a uint128) uint128 {
	a.lo = a.lo>>2 | (a.hi&3)<<62
	a.hi = a.hi >> 2
	return a
}

func updateGeneric(msg []byte, flag uint64, h *[3]uint64, r *[2]uint64) {
	h0, h1, h2 := h[0], h[1], h[2]
	r0, r1 := r[0], r[1]

	for len(msg) >= TagSize {
		var c uint64

		h0, c = bits.Add64(h0, binary.LittleEndian.Uint64(msg[0:8]), 0)
		h1, c = bits.Add64(h1, binary.LittleEndian.Uint64(msg[8:16]), c)
		h2 += c + flag

		h0r0 := mul64(h0, r0)
		h1r0 := mul64(h1, r0)
		h2r0 := mul64(h2, r0)
		if h2r0.hi != 0 {
			panic("poly1305: unexpected overflow")
		}
		h0r1 := mul64(h0, r1)
		h1r1 := mul64(h1, r1)
		h2r1 := mul64(h2, r1)
		if h2r1.hi != 0 {
			panic("poly1305: unexpected overflow")
		}

		m0 := h0r0
		m1 := add128(h1r0, h0r1)
		m2 := add128(h2r0, h1r1)
		m3 := h2r1

		m1.lo, c = bits.Add64(m1.lo, m0.hi, 0)
		m2.lo, c = bits.Add64(m2.lo, m1.hi, c)
		m3.lo, _ = bits.Add64(m3.lo, m2.hi, c)

		h0, h1, h2 = m0.lo, m1.lo, m2.lo&3
		cc := uint128{m2.lo & 0xFFFFFFFFFFFFFFFC, m3.lo}

		h0, c = bits.Add64(h0, cc.lo, 0)
		h1, c = bits.Add64(h1, cc.hi, c)
		h2 += c

		cc = shiftRight2(cc)

		h0, c = bits.Add64(h0, cc.lo, 0)
		h1, c = bits.Add64(h1, cc.hi, c)
		h2 += c

		msg = msg[TagSize:]
	}

	h[0], h[1], h[2] = h0, h1, h2
}

// select64 returns x if v == 1 and y if v == 0.
func select64(v, x, y uint64) uint64 { return ^(v-1)&x | (v-1)&y }

// [p0, p1, p2] is 2¹³⁰ - 5 in little endian order.
const (
	p0 = 0xFFFFFFFFFFFFFFFB
	p1 = 0xFFFFFFFFFFFFFFFF
	p2 = 3
)

func finalizeGeneric(out *[TagSize]byte, h *[3]uint64, s *[2]uint64) {
	h0, h1, h2 := h[0], h[1], h[2]

	// h - p
	t0, b := bits.Sub64(h0, p0, 0)
	t1, b := bits.Sub64(h1, p1, b)
	_, b = bits.Sub64(h2, p2, b)

	// select h if h < p else h - p
	h0 = select64(b, h0, t0)
	h1 = select64(b, h1, t1)

	// tag = (h + s) % (2^128)
	h0, c := bits.Add64(h0, s[0], 0)
	h1, _ = bits.Add64(h1, s[1], c)

	binary.LittleEndian.PutUint64(out[0:8], h0)
	binary.LittleEndian.PutUint64(out[8:16], h1)
}
