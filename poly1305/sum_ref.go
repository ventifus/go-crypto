// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !amd64
// +build !arm

package poly1305

// Sum generates an authenticator for msg using a one-time key and puts the
// 16-byte result into out. Authenticating two different messages with the same
// key allows an attacker to forge messages at will.
func Sum(out *[TagSize]byte, msg []byte, key *[32]byte) {
	var (
		h, r  [5]uint32
		pad   [4]uint32
		block [TagSize]byte
		off   int
	)

	initialize(&r, &pad, key)

	n := len(msg) & (^(TagSize - 1))
	if n > 0 {
		core(msg[:n], msgBlock, &h, &r)
		msg = msg[n:]
	}

	if len(msg) > 0 {
		off += copy(block[:], msg)
		block[off] = 1
		core(block[:], finalBlock, &h, &r)
	}

	finalize(out, &h, &pad)
}
