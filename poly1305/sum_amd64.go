// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build amd64,!gccgo,!appengine

package poly1305

//go:noescape
func update(state *state, msg []byte)

// Sum generates an authenticator for m using a one-time key and puts the
// 16-byte result into out. Authenticating two different messages with the same
// key allows an attacker to forge messages at will.
func Sum(out *[16]byte, m []byte, key *[32]byte) {
	h := newMAC(key)
	h.Write(m)
	h.Sum(out)
}

func newMAC(key *[32]byte) (h mac) {
	initializeGeneric(key, &h.r, &h.s)
	return
}

type mac struct {
	state
	buffer [TagSize]byte
	offset int
}

func (h *mac) Write(p []byte) (n int, err error) {
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
		update(&h.state, h.buffer[:])
	}
	if nn := len(p) - (len(p) % TagSize); nn > 0 {
		update(&h.state, p[:nn])
		p = p[nn:]
	}
	if len(p) > 0 {
		h.offset += copy(h.buffer[h.offset:], p)
	}
	return n, nil
}

func (h *mac) Sum(out *[16]byte) {
	state := h.state
	if h.offset > 0 {
		update(&state, h.buffer[:h.offset])
	}
	finalizeGeneric(out, &state.h, &state.s)
}
