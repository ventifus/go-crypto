// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package ripemd160 implements the RIPEMD-160 hash algorithm.
package ripemd160 // import "golang.org/x/crypto/ripemd160"

// RIPEMD-160 is designed by by Hans Dobbertin, Antoon Bosselaers, and Bart
// Preneel with specifications available at:
// http://homes.esat.kuleuven.be/~cosicart/pdf/AB-9601/AB-9601.pdf.

import (
	"crypto"
	"encoding/binary"
	"errors"
	"hash"
)

func init() {
	crypto.RegisterHash(crypto.RIPEMD160, New)
}

// The size of the checksum in bytes.
const Size = 20

// The block size of the hash algorithm in bytes.
const BlockSize = 64

const (
	_s0 = 0x67452301
	_s1 = 0xefcdab89
	_s2 = 0x98badcfe
	_s3 = 0x10325476
	_s4 = 0xc3d2e1f0
)

// digest represents the partial evaluation of a checksum.
type digest struct {
	s  [5]uint32       // running context
	x  [BlockSize]byte // temporary buffer
	nx int             // index into x
	tc uint64          // total count of bytes processed
}

const (
	magic         = "rmd"
	marshaledSize = len(magic) + 5*4 + BlockSize + 1 + 8
)

func (d *digest) MarshalBinary() ([]byte, error) {
	b := make([]byte, 0, marshaledSize)
	b = append(b, magic...)
	for i := 0; i < 5; i++ {
		b = appendUint32(b, d.s[i])
	}
	b = append(b, d.x[:]...)
	// Maximum value for nx is 64
	b = append(b, byte(d.nx))
	b = appendUint64(b, d.tc)
	return b, nil
}

func (d *digest) UnmarshalBinary(b []byte) error {
	if len(b) < len(magic) || string(b[:len(magic)]) != magic {
		return errors.New("crypto/ripemd160: invalid hash state identifier")
	}
	if len(b) != marshaledSize {
		return errors.New("crypto/ripemd160: invalid hash state size")
	}
	b = b[len(magic):]
	for i := 0; i < 5; i++ {
		b, d.s[i] = consumeUint32(b)
	}
	copy(d.x[:], b[:BlockSize])
	b = b[BlockSize:]
	d.nx = int(b[0])
	b = b[1:]
	b, d.tc = consumeUint64(b)
	return nil
}

func (d *digest) Reset() {
	d.s[0], d.s[1], d.s[2], d.s[3], d.s[4] = _s0, _s1, _s2, _s3, _s4
	d.nx = 0
	d.tc = 0
}

// New returns a new hash.Hash computing the checksum. The returned hash.Hash
// implements BinaryMarshaler and BinaryUnmarshaler for state (de)serialization
// as documented by hash.Hash.
func New() hash.Hash {
	result := new(digest)
	result.Reset()
	return result
}

func (d *digest) Size() int { return Size }

func (d *digest) BlockSize() int { return BlockSize }

func (d *digest) Write(p []byte) (nn int, err error) {
	nn = len(p)
	d.tc += uint64(nn)
	if d.nx > 0 {
		n := len(p)
		if n > BlockSize-d.nx {
			n = BlockSize - d.nx
		}
		for i := 0; i < n; i++ {
			d.x[d.nx+i] = p[i]
		}
		d.nx += n
		if d.nx == BlockSize {
			_Block(d, d.x[0:])
			d.nx = 0
		}
		p = p[n:]
	}
	n := _Block(d, p)
	p = p[n:]
	if len(p) > 0 {
		d.nx = copy(d.x[:], p)
	}
	return
}

func (d0 *digest) Sum(in []byte) []byte {
	// Make a copy of d0 so that caller can keep writing and summing.
	d := *d0

	// Padding.  Add a 1 bit and 0 bits until 56 bytes mod 64.
	tc := d.tc
	var tmp [64]byte
	tmp[0] = 0x80
	if tc%64 < 56 {
		d.Write(tmp[0 : 56-tc%64])
	} else {
		d.Write(tmp[0 : 64+56-tc%64])
	}

	// Length in bits.
	tc <<= 3
	for i := uint(0); i < 8; i++ {
		tmp[i] = byte(tc >> (8 * i))
	}
	d.Write(tmp[0:8])

	if d.nx != 0 {
		panic("d.nx != 0")
	}

	var digest [Size]byte
	for i, s := range d.s {
		digest[i*4] = byte(s)
		digest[i*4+1] = byte(s >> 8)
		digest[i*4+2] = byte(s >> 16)
		digest[i*4+3] = byte(s >> 24)
	}

	return append(in, digest[:]...)
}

func appendUint64(b []byte, x uint64) []byte {
	var a [8]byte
	binary.BigEndian.PutUint64(a[:], x)
	return append(b, a[:]...)
}

func appendUint32(b []byte, x uint32) []byte {
	var a [4]byte
	binary.BigEndian.PutUint32(a[:], x)
	return append(b, a[:]...)
}

func consumeUint64(b []byte) ([]byte, uint64) {
	x := binary.BigEndian.Uint64(b)
	return b[8:], x
}

func consumeUint32(b []byte) ([]byte, uint32) {
	x := binary.BigEndian.Uint32(b)
	return b[4:], x
}
