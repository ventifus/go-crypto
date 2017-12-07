// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package argon2

import (
	"encoding/binary"
	"hash"

	"golang.org/x/crypto/blake2b"
)

// initAble is implemented by the BLAKE2b implementation.
type initAble interface {
	Init(int)
}

// blake2bHash computes an arbitrary long hash value of in
// and writes the hash to out.
func blake2bHash(out []byte, in []byte) {
	var (
		buffer [blake2b.Size]byte
		b2     hash.Hash
	)
	if n := len(out); n < blake2b.Size {
		b2, _ = blake2b.New512(nil)
		b2.(initAble).Init(n)
	} else {
		b2, _ = blake2b.New512(nil)
	}
	binary.LittleEndian.PutUint32(buffer[:4], uint32(len(out)))
	b2.Write(buffer[:4])

	b2.Write(in)
	if len(out) <= blake2b.Size {
		b2.Sum(out[:0])
		return
	}

	outLen := len(out)
	b2.Sum(buffer[:0])
	b2.Reset()
	copy(out, buffer[:32])
	out = out[32:]
	for len(out) > blake2b.Size {
		b2.Write(buffer[:])
		b2.Sum(buffer[:0])
		copy(out, buffer[:32])
		out = out[32:]
		b2.Reset()
	}

	if outLen%blake2b.Size > 0 {
		b2.(initAble).Init(33 + (outLen+31)%32)
	}
	b2.Write(buffer[:])
	b2.Sum(out[:0])
}
