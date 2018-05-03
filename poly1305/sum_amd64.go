// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build amd64,!gccgo,!appengine

package poly1305

//go:noescape
func initialize(state *[7]uint64, key *[32]byte)

//go:noescape
func update(state *[7]uint64, msg []byte)

//go:noescape
func finalize(tag *[TagSize]byte, state *[7]uint64)

// Sum generates an authenticator for m using a one-time key and puts the
// 16-byte result into out. Authenticating two different messages with the same
// key allows an attacker to forge messages at will.
func Sum(out *[16]byte, m []byte, key *[32]byte) {
	h := newHash(key)
	h.Write(m)
	h.Sum(out)
}

func newHash(key *[32]byte) (h hash) {
	initialize(&h.state, key)
	return
}

type hash struct {
	state [7]uint64 // := uint64{ h0, h1, h2, r0, r1, pad0, pad1 }

	buffer [TagSize]byte
	offset int
}

func (h *hash) Write(p []byte) (n int, err error) {
	n = len(p)
	if h.offset > 0 {
		remaining := TagSize - h.offset
		if n <= remaining {
			h.offset += copy(h.buffer[h.offset:], p)
			return n, nil
		}
		copy(h.buffer[h.offset:], p[:remaining])
		p = p[remaining:]
		h.offset = 0
		update(&(h.state), h.buffer[:])
	}
	if nn := len(p) & (^(TagSize - 1)); nn > 0 { // process full 16-byte blocks
		update(&(h.state), p[:nn])
		p = p[nn:]
	}
	if len(p) > 0 {
		h.offset += copy(h.buffer[h.offset:], p)
	}
	return n, nil
}

func (h *hash) Sum(out *[16]byte) {
	state := h.state
	if h.offset > 0 {
		update(&state, h.buffer[:h.offset])
	}
	finalize(out, &state)
}
