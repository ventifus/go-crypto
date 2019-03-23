// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build amd64,!gccgo,!appengine

package poly1305

//go:noescape
func update(state *macState, msg []byte)

func sum(out *[16]byte, m []byte, key *[32]byte) {
	h := newMAC(key)
	h.Write(m)
	h.Sum(out)
}

func newMAC(key *[32]byte) (h mac) {
	initialize(key, &h.r, &h.s)
	return
}

type mac struct{ macGeneric }

func (h *mac) Write(p []byte) (int, error) {
	if h.offset > 0 {
		n := copy(h.buffer[h.offset:], p)
		if h.offset+n < TagSize {
			h.offset += n
			return len(p), nil
		}
		p = p[n:]
		h.offset = 0
		update(&h.macState, h.buffer[:])
	}
	if n := len(p) - (len(p) % TagSize); n > 0 {
		update(&h.macState, p[:n])
		p = p[n:]
	}
	if len(p) > 0 {
		h.offset += copy(h.buffer[h.offset:], p)
	}
	return len(p), nil
}

func (h *mac) Sum(out *[16]byte) {
	state := h.macState
	if h.offset > 0 {
		update(&state, h.buffer[:h.offset])
	}
	finalize(out, &state.h, &state.s)
}
