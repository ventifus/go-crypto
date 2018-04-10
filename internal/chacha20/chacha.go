// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package ChaCha20 implements the core ChaCha20 function as specified
// in https://tools.ietf.org/html/rfc7539#section-2.3.
package chacha20

import (
	"crypto/cipher"
	"encoding/binary"
	"runtime"
)

const rounds = 20

// fast64 indicates that the architecture can heavily optimize 64-bit
// unaligned little endian reads and writes.
const fast64 = runtime.GOARCH == "amd64" ||
	runtime.GOARCH == "arm64" ||
	runtime.GOARCH == "ppc64le" ||
	runtime.GOARCH == "s390x"

// assert that *State implements cipher.Stream
var _ = cipher.Stream(&State{})

type State struct {
	key     [8]uint32
	counter [4]uint32
	buf     [bufSize]byte
	len     int
}

// New creates a new ChaCha20 stream cipher with the given initial
// counter and key. *State implements the cipher.Stream interface.
func New(iv [4]uint32, key [8]uint32) *State {
	return &State{counter: iv, key: key}
}

// XORKeyStream encrypts src and writes the result to dst.
// src and dst must overlap entirely or not at all.
func (s *State) XORKeyStream(dst, src []byte) {
	if len(src) == 0 {
		return
	}

	// assert length of dst
	_ = dst[len(src)-1]
	dst = dst[:len(src)]

	// use buffered keystream first
	buf := s.buf[len(s.buf)-s.len:]
	if len(buf) > 0 {
		l := len(s.buf)
		if len(src) < l {
			l = len(src)
		}
		buf = buf[:l]
		td, ts := dst[:len(buf)], src[:len(buf)] // BCE hint
		for i, b := range buf {
			td[i] = ts[i] ^ b
		}
		s.len -= l
		src = src[l:]
		dst = dst[l:]
	}

	if len(src) == 0 {
		return
	}
	if hasAsm {
		s.coreAsm(dst, src)
		return
	}
	s.core(dst, src)
}

// Advance discards bytes in the key stream until the next 64 byte block
// boundary is reached. If the key stream is already at a block boundary
// no bytes will be discarded.
func (s *State) Advance() {
	s.len &^= 63
}

// core applies the ChaCha20 core function to 16-byte input in, 32-byte key k,
// and 16-byte constant c, and puts the result into 64-byte array out.
func (s *State) core(dst, src []byte) {
	ctr, key := &s.counter, &s.key

	const j0, j1, j2, j3 uint32 = 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574

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
	s1, s5, s13, s9 := qr(j1, key[1], ctr[1], key[5])
	s2, s6, s14, s10 := qr(j2, key[2], ctr[2], key[6])
	s3, s7, s15, s11 := qr(j3, key[3], ctr[3], key[7])
	for {
		// calculate the variable part of the first round
		x0, x4, x12, x8 := qr(j0, key[0], ctr[0], key[4])
		x1, x2, x3, x5, x6, x7 := s1, s2, s3, s5, s6, s7
		x9, x10, x11, x13, x14, x15 := s9, s10, s11, s13, s14, s15

		// execute the remaining 19 rounds
		for i := rounds/2 - 1; ; i-- {
			x0, x5, x15, x10 = qr(x0, x5, x15, x10)
			x1, x6, x12, x11 = qr(x1, x6, x12, x11)
			x2, x7, x13, x8 = qr(x2, x7, x13, x8)
			x3, x4, x14, x9 = qr(x3, x4, x14, x9)

			if i == 0 {
				break
			}

			x0, x4, x12, x8 = qr(x0, x4, x12, x8)
			x1, x5, x13, x9 = qr(x1, x5, x13, x9)
			x2, x6, x14, x10 = qr(x2, x6, x14, x10)
			x3, x7, x15, x11 = qr(x3, x7, x15, x11)
		}

		x0 += j0
		x1 += j1
		x2 += j2
		x3 += j3

		x4 += key[0]
		x5 += key[1]
		x6 += key[2]
		x7 += key[3]
		x8 += key[4]
		x9 += key[5]
		x10 += key[6]
		x11 += key[7]

		x12 += ctr[0]
		x13 += ctr[1]
		x14 += ctr[2]
		x15 += ctr[3]

		// increment 32-bits of counter
		ctr[0] += 1

		// pad to 64 bytes if needed
		in, out := src, dst
		if len(in) < 64 {
			in, out = make([]byte, 64), s.buf[:64]
			copy(in, src)
		}
		in, out = in[:64], out[:64] // BCE hint

		// XOR src with the keystream and write to dst
		if fast64 {
			// TODO(mundaym): it would be nice to make this
			// one function, but we need it to inline and
			// the little endian operations are expensive
			// as far as the compiler is concerned.
			put := func(b []byte, v uint64) {
				binary.LittleEndian.PutUint64(b, v)
			}
			get := func(b []byte) uint64 {
				return binary.LittleEndian.Uint64(b)
			}
			merge := func(u, v uint32) uint64 {
				return uint64(u) ^ (uint64(v) << 32)
			}

			// XOR in 8 byte chunks
			put(out[0:], get(in[0:])^merge(x0, x1))
			put(out[8:], get(in[8:])^merge(x2, x3))
			put(out[16:], get(in[16:])^merge(x4, x5))
			put(out[24:], get(in[24:])^merge(x6, x7))
			put(out[32:], get(in[32:])^merge(x8, x9))
			put(out[40:], get(in[40:])^merge(x10, x11))
			put(out[48:], get(in[48:])^merge(x12, x13))
			put(out[56:], get(in[56:])^merge(x14, x15))
		} else {
			xor := func(out, in []byte, u uint32) {
				out[0] = in[0] ^ byte(u)
				out[1] = in[1] ^ byte(u>>8)
				out[2] = in[2] ^ byte(u>>16)
				out[3] = in[3] ^ byte(u>>24)
			}

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

		if len(src) <= 64 {
			s.len = 64 - len(src)
			if len(src) < 64 {
				copy(dst, out)
			}
			return
		}
		src = src[64:]
		dst = dst[64:]
	}
}

// XORKeyStream crypts bytes from in to out using the given key and counters.
// In and out must overlap entirely or not at all. Counter contains the raw
// ChaCha20 counter bytes (i.e. block counter followed by nonce).
func XORKeyStream(out, in []byte, counter *[16]byte, key *[32]byte) {
	s := State{
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
