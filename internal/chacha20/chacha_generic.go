// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package ChaCha20 implements the core ChaCha20 function as specified
// in https://tools.ietf.org/html/rfc7539#section-2.3.
package chacha20

import (
	"crypto/cipher"
	"encoding/binary"
)

// assert that *Cipher implements cipher.Stream
var _ = cipher.Stream(&Cipher{})

type Cipher struct {
	key     [8]uint32
	counter [4]uint32
	buf     [64]byte
	len     int
}

const (
	j0 uint32 = 0x61707865
	j1 uint32 = 0x3320646e
	j2 uint32 = 0x79622d32
	j3 uint32 = 0x6b206574
)

// New creates a new ChaCha20 stream cipher with the given initial
// counter and key. *Cipher implements the cipher.Stream interface.
func New(iv [4]uint32, key [8]uint32) *Cipher {
	return &Cipher{counter: iv, key: key}
}

// XORKeyStream encrypts src and writes the result to dst.
// src and dst must overlap entirely or not at all.
func (s *Cipher) XORKeyStream(dst, src []byte) {
	// xor src with buffered keystream first
	if s.len != 0 {
		buf := s.buf[len(s.buf)-s.len:]
		if len(src) < len(buf) {
			buf = buf[:len(src)]
		}
		td, ts := dst[:len(buf)], src[:len(buf)] // BCE hint
		for i, b := range buf {
			td[i] = ts[i] ^ b
		}
		s.len -= len(buf)
		if s.len != 0 {
			return
		}
		s.buf = [len(s.buf)]byte{} // zero the empty buffer
		src = src[len(buf):]
		dst = dst[len(buf):]
	}

	if len(src) == 0 {
		return
	}

	// set up a 64-byte buffer to pad out the final block if needed
	rem := len(src) % 64  // length of final block
	fin := len(src) - rem // index of final block
	if rem > 0 {
		copy(s.buf[:], src[fin:])
	}

	// qr calculates a quarter round
	qr := func(a, b, c, d uint32) (uint32, uint32, uint32, uint32) {
		a += b
		c ^= a
		c = (c << 16) | (c >> 16)
		d += c
		b ^= d
		b = (b << 12) | (b >> 20)
		a += b
		c ^= a
		c = (c << 8) | (c >> 24)
		d += c
		b ^= d
		b = (b << 7) | (b >> 25)
		return a, b, c, d
	}

	// pre-calculate most of the first round
	s1, s5, s13, s9 := qr(j1, s.key[1], s.counter[1], s.key[5])
	s2, s6, s14, s10 := qr(j2, s.key[2], s.counter[2], s.key[6])
	s3, s7, s15, s11 := qr(j3, s.key[3], s.counter[3], s.key[7])

	n := len(src)
	src, dst = src[:n:n], dst[:n:n] // BCE hint
	for i := 0; i < n; i += 64 {
		// calculate the remainder of the first round
		s0, s4, s12, s8 := qr(j0, s.key[0], s.counter[0], s.key[4])

		// execute the second round
		x0, x5, x15, x10 := qr(s0, s5, s15, s10)
		x1, x6, x12, x11 := qr(s1, s6, s12, s11)
		x2, x7, x13, x8 := qr(s2, s7, s13, s8)
		x3, x4, x14, x9 := qr(s3, s4, s14, s9)

		// execute the remaining 18 rounds
		for i := 0; i < 9; i++ {
			x0, x4, x12, x8 = qr(x0, x4, x12, x8)
			x1, x5, x13, x9 = qr(x1, x5, x13, x9)
			x2, x6, x14, x10 = qr(x2, x6, x14, x10)
			x3, x7, x15, x11 = qr(x3, x7, x15, x11)

			x0, x5, x15, x10 = qr(x0, x5, x15, x10)
			x1, x6, x12, x11 = qr(x1, x6, x12, x11)
			x2, x7, x13, x8 = qr(x2, x7, x13, x8)
			x3, x4, x14, x9 = qr(x3, x4, x14, x9)
		}

		x0 += j0
		x1 += j1
		x2 += j2
		x3 += j3

		x4 += s.key[0]
		x5 += s.key[1]
		x6 += s.key[2]
		x7 += s.key[3]
		x8 += s.key[4]
		x9 += s.key[5]
		x10 += s.key[6]
		x11 += s.key[7]

		x12 += s.counter[0]
		x13 += s.counter[1]
		x14 += s.counter[2]
		x15 += s.counter[3]

		// increment 32-bits of counter
		s.counter[0] += 1

		// pad to 64 bytes if needed
		in, out := src[i:], dst[i:]
		if i == fin {
			in, out = s.buf[:], s.buf[:]
		}
		in, out = in[:64], out[:64]

		// XOR one byte at a time
		xor(out[0:], in[0:], x0)
		xor(out[4:], in[4:], x1)
		xor(out[8:], in[8:], x2)
		xor(out[12:], in[12:], x3)
		xor(out[16:], in[16:], x4)
		xor(out[20:], in[20:], x5)
		xor(out[24:], in[24:], x6)
		xor(out[28:], in[28:], x7)
		xor(out[32:], in[32:], x8)
		xor(out[36:], in[36:], x9)
		xor(out[40:], in[40:], x10)
		xor(out[44:], in[44:], x11)
		xor(out[48:], in[48:], x12)
		xor(out[52:], in[52:], x13)
		xor(out[56:], in[56:], x14)
		xor(out[60:], in[60:], x15)
	}
	if rem != 0 {
		s.len = 64 - rem
		copy(dst[fin:], s.buf[:])
	}
}

// Advance discards bytes in the key stream until the next 64 byte block
// boundary is reached. If the key stream is already at a block boundary
// no bytes will be discarded.
func (s *Cipher) Advance() {
	s.len = 0
	s.buf = [len(s.buf)]byte{}
}

// XORKeyStream crypts bytes from in to out using the given key and counters.
// In and out must overlap entirely or not at all. Counter contains the raw
// ChaCha20 counter bytes (i.e. block counter followed by nonce).
func XORKeyStream(out, in []byte, counter *[16]byte, key *[32]byte) {
	s := Cipher{
		counter: [4]uint32{
			binary.LittleEndian.Uint32(counter[0:4]),
			binary.LittleEndian.Uint32(counter[4:8]),
			binary.LittleEndian.Uint32(counter[8:12]),
			binary.LittleEndian.Uint32(counter[12:16]),
		},
		key: [8]uint32{
			binary.LittleEndian.Uint32(key[0:4]),
			binary.LittleEndian.Uint32(key[4:8]),
			binary.LittleEndian.Uint32(key[8:12]),
			binary.LittleEndian.Uint32(key[12:16]),
			binary.LittleEndian.Uint32(key[16:20]),
			binary.LittleEndian.Uint32(key[20:24]),
			binary.LittleEndian.Uint32(key[24:28]),
			binary.LittleEndian.Uint32(key[28:32]),
		},
	}
	s.XORKeyStream(out, in)
}
