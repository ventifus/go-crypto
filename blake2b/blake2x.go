// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package blake2b

import (
	"encoding/binary"
	"errors"
	"io"
)

// XOF defines the interface to hash functions that
// support arbitrary-length output.
type XOF interface {
	// Write absorbs more data into the hash's state. It panics if input is
	// written to it after output has been read from it.
	io.Writer

	// Read reads more output from the hash; reading affects the hash's
	// state. (ShakeHash.Read is thus very different from Hash.Sum)
	// It returns a non-nil error if the read limit is exceeded and the
	// number of bytes read from the hash.
	io.Reader

	// Clone returns a copy of the XOF in its current state.
	Clone() XOF

	// Reset resets the XOF to its initial state.
	Reset()
}

// NewXOF creates a new variable-output-length hash.
// The hash can produce size bytes of output. A non-nil
// key turns the hash into a MAC. The key must between
// zero and 64 bytes long.
func NewXOF(size uint32, key []byte) (XOF, error) {
	if len(key) > Size {
		return nil, errKeySize
	}
	x := &xof{
		d: digest{
			size:   Size,
			keyLen: len(key),
		},
		length: size,
	}
	copy(x.d.key[:], key)
	x.Reset()
	return x, nil
}

type xof struct {
	d                 digest
	length, remaining uint32
	cfg, root, block  [Size]byte
	offset            int
	nodeOffset        uint32
	readMode          bool
}

func (x *xof) Write(p []byte) (n int, err error) {
	if x.readMode {
		panic("blake2b: write to XOF after read")
	}
	return x.d.Write(p)
}

func (x *xof) Clone() XOF {
	clone := *x
	return &clone
}

func (x *xof) Reset() {
	x.cfg[0] = byte(Size)
	binary.LittleEndian.PutUint32(x.cfg[4:], uint32(Size)) // leaf length
	binary.LittleEndian.PutUint32(x.cfg[12:], x.length)    // XOF length
	x.cfg[17] = byte(Size)                                 // inner hash size

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
		err = errors.New("blake2b: hash limit exceeded")
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

	for len(p) >= Size {
		binary.LittleEndian.PutUint32(x.cfg[8:], x.nodeOffset)
		x.nodeOffset++

		x.d.initConfig(&(x.cfg))
		x.d.Write(x.root[:])
		x.d.finalize(&(x.block))

		copy(p, x.block[:])
		x.remaining -= uint32(Size)
		p = p[Size:]
	}

	if nn := len(p); nn > 0 {
		if x.remaining < uint32(Size) {
			x.cfg[0] = byte(x.remaining)
		}
		binary.LittleEndian.PutUint32(x.cfg[8:], x.nodeOffset)
		x.nodeOffset++

		x.d.initConfig(&(x.cfg))
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
