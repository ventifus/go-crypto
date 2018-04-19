// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build go1.11

package chacha20

import (
	"encoding/binary"
)

const blockSize = 64

func XORKeyStream(out, in []byte, counter *[16]byte, key *[32]byte) {

	var state [16]uint32
	state[0] = 0x61707865
	state[1] = 0x3320646e
	state[2] = 0x79622d32
	state[3] = 0x6b206574
	state[4] = binary.LittleEndian.Uint32(key[0:4])
	state[5] = binary.LittleEndian.Uint32(key[4:8])
	state[6] = binary.LittleEndian.Uint32(key[8:12])
	state[7] = binary.LittleEndian.Uint32(key[12:16])
	state[8] = binary.LittleEndian.Uint32(key[16:20])
	state[9] = binary.LittleEndian.Uint32(key[20:24])
	state[10] = binary.LittleEndian.Uint32(key[24:28])
	state[11] = binary.LittleEndian.Uint32(key[28:32])
	state[12] = binary.LittleEndian.Uint32(counter[0:4])
	state[13] = binary.LittleEndian.Uint32(counter[4:8])
	state[14] = binary.LittleEndian.Uint32(counter[8:12])
	state[15] = binary.LittleEndian.Uint32(counter[12:16])

	for len(in) >= blockSize*4 {
		block4(&state, out, in)
		in = in[blockSize*4:]
		out = out[blockSize*4:]
		state[12] += 4
	}

	if len(in) == 0 {
		return
	}

	for len(in) >= blockSize {
		block(&state, out, in)
		in = in[blockSize:]
		out = out[blockSize:]
		state[12] += 1
	}

	if len(in) == 0 {
		return
	}

	buf := make([]byte, blockSize, blockSize)
	copy(buf, in)
	block(&state, buf, buf)
	copy(out, buf)
}

//go:noescape
func block(state *[16]uint32, out, in []byte)

//go:noescape
func block4(state *[16]uint32, out, in []byte)
