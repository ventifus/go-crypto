// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package ChaCha20 implements the core ChaCha20 function as specified in https://tools.ietf.org/html/rfc7539#section-2.3.
package chacha20

import (
	"crypto/cipher"
	"encoding/binary"
)

const rounds = 20

type state struct {
	buf     []byte
	key     [8]uint32
	counter [4]uint32
	storage [64]byte
}

// New creates a new ChaCha20 stream cipher with the given initial
// counter and key.
func New(iv [16]byte, key [32]byte) cipher.Stream {
	var s state
	for i := range s.key {
		s.key[i] = binary.LittleEndian.Uint32(key[i*4 : (i+1)*4])
	}
	for i := range s.counter {
		s.counter[i] = binary.LittleEndian.Uint32(iv[i*4 : (i+1)*4])
	}
	return &s
}

// XORKeyStream encrypts src and writes the result to dst.
// src and dst must overlap entirely or not at all.
func (s *state) XORKeyStream(dst, src []byte) {
	// avoid write barriers in loop
	buf := s.buf

	for len(src) > 0 {
		if len(buf) == 0 {
			core(&s.storage, &s.counter, &s.key)
			s.counter[0] += 1
			buf = s.storage[:]
		}

		l := len(buf)
		if len(src) < l {
			l = len(src)
		}
		// TODO(mundaym): wide unaligned XORs on architectures with
		// unaligned loads.
		td, ts := dst[:l], src[:l] // BCE hint
		for i, b := range buf[:l] {
			td[i] = ts[i] ^ b
		}
		buf = buf[l:]
		src = src[l:]
		dst = dst[l:]
	}

	// update stored buffer value
	s.buf = buf
}

// core applies the ChaCha20 core function to 16-byte input in, 32-byte key k,
// and 16-byte constant c, and puts the result into 64-byte array out.
func core(out *[64]byte, in *[4]uint32, k *[8]uint32) {
	j0 := uint32(0x61707865)
	j1 := uint32(0x3320646e)
	j2 := uint32(0x79622d32)
	j3 := uint32(0x6b206574)

	x0, x1, x2, x3 := j0, j1, j2, j3
	x4, x5, x6, x7, x8, x9, x10, x11 := k[0], k[1], k[2], k[3], k[4], k[5], k[6], k[7]
	x12, x13, x14, x15 := in[0], in[1], in[2], in[3]

	for i := 0; i < rounds; i += 2 {
		x0 += x4
		x12 ^= x0
		x12 = (x12 << 16) | (x12 >> 16)
		x8 += x12
		x4 ^= x8
		x4 = (x4 << 12) | (x4 >> 20)
		x0 += x4
		x12 ^= x0
		x12 = (x12 << 8) | (x12 >> 24)
		x8 += x12
		x4 ^= x8
		x4 = (x4 << 7) | (x4 >> 25)
		x1 += x5
		x13 ^= x1
		x13 = (x13 << 16) | (x13 >> 16)
		x9 += x13
		x5 ^= x9
		x5 = (x5 << 12) | (x5 >> 20)
		x1 += x5
		x13 ^= x1
		x13 = (x13 << 8) | (x13 >> 24)
		x9 += x13
		x5 ^= x9
		x5 = (x5 << 7) | (x5 >> 25)
		x2 += x6
		x14 ^= x2
		x14 = (x14 << 16) | (x14 >> 16)
		x10 += x14
		x6 ^= x10
		x6 = (x6 << 12) | (x6 >> 20)
		x2 += x6
		x14 ^= x2
		x14 = (x14 << 8) | (x14 >> 24)
		x10 += x14
		x6 ^= x10
		x6 = (x6 << 7) | (x6 >> 25)
		x3 += x7
		x15 ^= x3
		x15 = (x15 << 16) | (x15 >> 16)
		x11 += x15
		x7 ^= x11
		x7 = (x7 << 12) | (x7 >> 20)
		x3 += x7
		x15 ^= x3
		x15 = (x15 << 8) | (x15 >> 24)
		x11 += x15
		x7 ^= x11
		x7 = (x7 << 7) | (x7 >> 25)
		x0 += x5
		x15 ^= x0
		x15 = (x15 << 16) | (x15 >> 16)
		x10 += x15
		x5 ^= x10
		x5 = (x5 << 12) | (x5 >> 20)
		x0 += x5
		x15 ^= x0
		x15 = (x15 << 8) | (x15 >> 24)
		x10 += x15
		x5 ^= x10
		x5 = (x5 << 7) | (x5 >> 25)
		x1 += x6
		x12 ^= x1
		x12 = (x12 << 16) | (x12 >> 16)
		x11 += x12
		x6 ^= x11
		x6 = (x6 << 12) | (x6 >> 20)
		x1 += x6
		x12 ^= x1
		x12 = (x12 << 8) | (x12 >> 24)
		x11 += x12
		x6 ^= x11
		x6 = (x6 << 7) | (x6 >> 25)
		x2 += x7
		x13 ^= x2
		x13 = (x13 << 16) | (x13 >> 16)
		x8 += x13
		x7 ^= x8
		x7 = (x7 << 12) | (x7 >> 20)
		x2 += x7
		x13 ^= x2
		x13 = (x13 << 8) | (x13 >> 24)
		x8 += x13
		x7 ^= x8
		x7 = (x7 << 7) | (x7 >> 25)
		x3 += x4
		x14 ^= x3
		x14 = (x14 << 16) | (x14 >> 16)
		x9 += x14
		x4 ^= x9
		x4 = (x4 << 12) | (x4 >> 20)
		x3 += x4
		x14 ^= x3
		x14 = (x14 << 8) | (x14 >> 24)
		x9 += x14
		x4 ^= x9
		x4 = (x4 << 7) | (x4 >> 25)
	}

	binary.LittleEndian.PutUint32(out[0:4], x0+j0)
	binary.LittleEndian.PutUint32(out[4:8], x1+j1)
	binary.LittleEndian.PutUint32(out[8:12], x2+j2)
	binary.LittleEndian.PutUint32(out[12:16], x3+j3)
	binary.LittleEndian.PutUint32(out[16:20], x4+k[0])
	binary.LittleEndian.PutUint32(out[20:24], x5+k[1])
	binary.LittleEndian.PutUint32(out[24:28], x6+k[2])
	binary.LittleEndian.PutUint32(out[28:32], x7+k[3])
	binary.LittleEndian.PutUint32(out[32:36], x8+k[4])
	binary.LittleEndian.PutUint32(out[36:40], x9+k[5])
	binary.LittleEndian.PutUint32(out[40:44], x10+k[6])
	binary.LittleEndian.PutUint32(out[44:48], x11+k[7])
	binary.LittleEndian.PutUint32(out[48:52], x12+in[0])
	binary.LittleEndian.PutUint32(out[52:56], x13+in[1])
	binary.LittleEndian.PutUint32(out[56:60], x14+in[2])
	binary.LittleEndian.PutUint32(out[60:64], x15+in[3])
}

// XORKeyStream crypts bytes from in to out using the given key and counters.
// In and out must overlap entirely or not at all. Counter contains the raw
// ChaCha20 counter bytes (i.e. block counter followed by nonce).
func XORKeyStream(out, in []byte, counter *[16]byte, key *[32]byte) {
	s := New(*counter, *key)
	s.XORKeyStream(out, in)
}
