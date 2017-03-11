// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package blake2b

import (
	"encoding/binary"
	"errors"
	"io"
)

type XOF interface {
	io.Writer

	io.Reader

	Clone() XOF

	Reset()
}

func NewXOF(size uint32, key []byte) (XOF, error) {
	d, err := newDigest(Size, key)
	if err != nil {
		return nil, err
	}
	x := &xof{
		d:         *d,
		length:    size,
		remaining: size,
	}
	x.Reset()
	return x, nil
}

var (
	errLimitExceeded  = errors.New("crypto/blake2s: hash limit execeeded")
	errWriteAfterRead = errors.New("crypto/blake2s: write after read")
)

type xof struct {
	d                 digest
	length, remaining uint32
	root, block       [Size]byte
	offset            int
	nodeOffset        uint32
	readMode          bool
}

func (x *xof) Write(p []byte) (n int, err error) {
	if x.readMode {
		return 0, errWriteAfterRead // TODO(aead): decision about error handling err vs. panic
	}
	return x.d.Write(p)
}

func (x *xof) Clone() XOF {
	clone := *x
	return &clone
}

func (x *xof) Reset() {
	x.d.Reset()
	x.d.h[1] ^= uint64(x.length) << 32

	x.remaining = x.length
	x.offset, x.nodeOffset = 0, 0
	x.readMode = false
}

func (x *xof) Read(p []byte) (n int, err error) {
	if !x.readMode {
		x.d.finalize(&(x.root))
		x.readMode = true
	}

	n = len(p)
	if n > int(x.remaining) {
		n = int(x.remaining)
		p = p[:n]
		err = errLimitExceeded
	}

	if x.offset > 0 {
		dif := Size - x.offset
		if n < dif {
			x.offset += copy(p, x.block[x.offset:])
			x.remaining -= uint32(n)
			return
		}
		copy(p, x.block[x.offset:])
		p = p[dif:]
		x.offset = 0
		x.remaining -= uint32(dif)
	}

	var cfg [Size]byte
	cfg[0] = byte(Size)
	binary.LittleEndian.PutUint32(cfg[4:], uint32(Size))
	binary.LittleEndian.PutUint32(cfg[12:], x.length)
	cfg[17] = byte(Size)

	for len(p) >= Size {
		binary.LittleEndian.PutUint32(cfg[8:], x.nodeOffset)
		x.nodeOffset++

		x.d.initConfig(&cfg)
		x.d.Write(x.root[:])
		x.d.finalize(&(x.block))

		copy(p, x.block[:])
		x.remaining -= uint32(Size)
		p = p[Size:]
	}

	if nn := len(p); nn > 0 {
		if x.remaining < uint32(Size) {
			cfg[0] = byte(x.remaining)
		}
		binary.LittleEndian.PutUint32(cfg[8:], x.nodeOffset)
		x.nodeOffset++

		x.d.initConfig(&cfg)
		x.d.Write(x.root[:])
		x.d.finalize(&(x.block))

		x.offset = copy(p, x.block[:nn])
		x.remaining -= uint32(nn)
	}

	return
}

func (d *digest) initConfig(cfg *[Size]byte) {
	d.offset, d.c[0], d.c[1] = 0, 0, 0
	for i := range d.h {
		d.h[i] = iv[i] ^ binary.LittleEndian.Uint64(cfg[i*8:])
	}
}
