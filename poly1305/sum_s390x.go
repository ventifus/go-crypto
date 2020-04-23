// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !gccgo,!purego

package poly1305

import (
	"golang.org/x/sys/cpu"
)

// updateVX is an assembly implementation of Poly1305 that uses vector
// instructions. It must only be called if the vector facility (vx) is
// available.
//go:noescape
func updateVX(state *macState, msg []byte)

// mac is a wrapper for macGeneric that redirects calls that would have gone to
// updateGeneric to update.
//
// A larger buffer is used than in the generic implementation. This is because
// the vector implementation has a high fixed cost per call relative to its
// speed overall.
type mac struct {
	macState

	buffer [256]byte // size must be a multiple of 16
	offset int
}

func (h *mac) Write(p []byte) (int, error) {
	nn := len(p)
	if h.offset > 0 {
		n := copy(h.buffer[h.offset:], p)
		if n == len(p) {
			h.offset += n
			return nn, nil
		}
		p = p[n:]
		h.offset = 0
		if cpu.S390X.HasVX {
			updateVX(&h.macState, h.buffer[:])
		} else {
			updateGeneric(&h.macState, h.buffer[:])
		}
	}

	tail := len(p) % len(h.buffer) // number of bytes to copy into buffer
	body := len(p) - tail          // number of bytes to process now
	if body > 0 {
		if cpu.S390X.HasVX {
			updateVX(&h.macState, p[:body])
		} else {
			updateGeneric(&h.macState, p[:body])
		}
	}
	h.offset = copy(h.buffer[:], p[body:]) // copy tail bytes - can be 0
	return nn, nil
}

func (h *mac) Sum(out *[16]byte) {
	state := h.macState
	remainder := h.buffer[:h.offset]
	if cpu.S390X.HasVX && len(remainder) > 32 {
		updateVX(&state, remainder)
	} else if h.offset > 0 {
		updateGeneric(&state, remainder)
	}
	finalize(out, &state.h, &state.s)
}
