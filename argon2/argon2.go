// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package argon2 implements the key derivation function Argon2.
// Argon2 is specfifed at https://github.com/P-H-C/phc-winner-argon2/blob/master/argon2-specs.pdf
package argon2

import (
	"encoding/binary"

	"golang.org/x/crypto/blake2b"
)

// Key derives a key from the password, salt, and cost parameters, returning a byte slice of length keyLen
// that can be used as cryptographic key.
//
// time is the CPU cost, memory is the memory cost and threads is the parallism degree parameter. The memory
// cost is always adjusted to be at least 8 times the parallism degree. The CPU cost and parallism degree must
// be greater than zero.
func Key(password, salt, secret, data []byte, time, memory uint32, threads uint8, keyLen uint32) []byte {
	if time < 1 {
		panic("argon2: number of rounds too small")
	}
	if threads < 1 {
		panic("argon2: paralisim degree too low")
	}
	const Argon2d = 0
	mem := memory / (4 * uint32(threads)) * (4 * uint32(threads))
	if mem < 8*uint32(threads) {
		mem = 8 * uint32(threads)
	}
	B := initBlocks(password, salt, secret, data, time, mem, uint32(threads), keyLen, Argon2d)
	processBlocks(B, time, mem, uint32(threads))
	return extractHash(B, mem, uint32(threads), keyLen)
}

func initBlocks(password, salt, key, data []byte, time, memory, threads, keyLen uint32, mode int) [][128]uint64 {
	var (
		block  [1024]byte
		h0     [blake2b.Size + 8]byte
		params [24]byte
		tmp    [4]byte
	)

	b2, _ := blake2b.New512(nil)
	binary.LittleEndian.PutUint32(params[0:4], threads)
	binary.LittleEndian.PutUint32(params[4:8], keyLen)
	binary.LittleEndian.PutUint32(params[8:12], memory)
	binary.LittleEndian.PutUint32(params[12:16], time)
	binary.LittleEndian.PutUint32(params[16:20], 0x13)
	binary.LittleEndian.PutUint32(params[20:24], uint32(mode))
	b2.Write(params[:])
	binary.LittleEndian.PutUint32(tmp[:], uint32(len(password)))
	b2.Write(tmp[:])
	b2.Write(password)
	binary.LittleEndian.PutUint32(tmp[:], uint32(len(salt)))
	b2.Write(tmp[:])
	b2.Write(salt)
	binary.LittleEndian.PutUint32(tmp[:], uint32(len(key)))
	b2.Write(tmp[:])
	b2.Write(key)
	binary.LittleEndian.PutUint32(tmp[:], uint32(len(data)))
	b2.Write(tmp[:])
	b2.Write(data)
	b2.Sum(h0[:0])

	B := make([][128]uint64, memory)
	for lane := uint32(0); lane < threads; lane++ {
		j := lane * (memory / threads)
		binary.LittleEndian.PutUint32(h0[blake2b.Size+4:], lane)

		binary.LittleEndian.PutUint32(h0[blake2b.Size:], 0)
		blake2bHash(block[:], h0[:])
		for i := range B[0] {
			B[j+0][i] = binary.LittleEndian.Uint64(block[i*8:])
		}

		binary.LittleEndian.PutUint32(h0[blake2b.Size:], 1)
		blake2bHash(block[:], h0[:])
		for i := range B[0] {
			B[j+1][i] = binary.LittleEndian.Uint64(block[i*8:])
		}
	}
	return B
}

func processBlocks(B [][128]uint64, time, memory, threads uint32) {
	const syncPoints = 4
	var tmp [128]uint64
	lanes := memory / threads
	segments := lanes / syncPoints
	for n := uint32(0); n < time; n++ {
		for slice := uint32(0); slice < syncPoints; slice++ {
			for lane := uint32(0); lane < threads; lane++ {
				index := uint32(0)
				if n == 0 && slice == 0 {
					index = 2 // we have already generated the first two blocks
				}
				offset := lane*lanes + slice*segments + index
				for index < segments {
					prev := offset - 1
					if index == 0 && slice == 0 {
						prev = lane*lanes + lanes - 1 // last block in lane
					}
					random := B[prev][0]
					newOffset := indexAlpha(random, lanes, segments, threads, n, slice, lane, index)
					processBlock(&B[offset], &tmp, &B[prev], &B[newOffset])
					index, offset = index+1, offset+1
				}
			}
		}
	}
}

func extractHash(B [][128]uint64, mem, p, keyLen uint32) []byte {
	lanes := mem / p
	for lane := uint32(0); lane < p-1; lane++ {
		for i, v := range B[(lane*lanes)+lanes-1] {
			B[mem-1][i] ^= v
		}
	}

	var block [1024]byte
	for i, v := range B[mem-1] {
		binary.LittleEndian.PutUint64(block[i*8:], v)
	}
	key := make([]byte, keyLen)
	blake2bHash(key, block[:])
	return key
}

func indexAlpha(rand uint64, lanes, segments, threads, n, slice, lane, index uint32) uint32 {
	refLane := uint32(rand>>32) % threads

	m, s := 3*segments, (slice+1)%4*segments
	if lane == refLane {
		m += index
	}
	if n == 0 {
		m, s = slice*segments, 0
		if slice == 0 || lane == refLane {
			m += index
		}
	}
	if index == 0 || lane == refLane {
		m--
	}
	return phi(rand, uint64(m), uint64(s), refLane, lanes)
}

func phi(rand, m, s uint64, lane, lanes uint32) uint32 {
	p := rand & 0xFFFFFFFF
	p = (p * p) >> 32
	p = (p * m) >> 32
	return lane*lanes + uint32((s+m-(p+1))%uint64(lanes))
}
