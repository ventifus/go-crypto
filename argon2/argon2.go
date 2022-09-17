// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package argon2 implements the key derivation function Argon2.
// Argon2 was selected as the winner of the Password Hashing Competition and can
// be used to derive cryptographic keys from passwords.
//
// For a detailed specification of Argon2 see [1].
//
// If you aren't sure which function you need, use Argon2id (IDKey) and
// the parameter recommendations for your scenario.
//
// # Argon2i
//
// Argon2i (implemented by Key) is the side-channel resistant version of Argon2.
// It uses data-independent memory access, which is preferred for password
// hashing and password-based key derivation. Argon2i requires more passes over
// memory than Argon2id to protect from trade-off attacks. The recommended
// parameters (taken from [2]) for non-interactive operations are time=3 and to
// use the maximum available memory.
//
// # Argon2id
//
// Argon2id (implemented by IDKey) is a hybrid version of Argon2 combining
// Argon2i and Argon2d. It uses data-independent memory access for the first
// half of the first iteration over the memory and data-dependent memory access
// for the rest. Argon2id is side-channel resistant and provides better brute-
// force cost savings due to time-memory tradeoffs than Argon2i. The recommended
// parameters for non-interactive operations (taken from [2]) are time=1 and to
// use the maximum available memory.
//
// [1] https://github.com/P-H-C/phc-winner-argon2/blob/master/argon2-specs.pdf
// [2] https://tools.ietf.org/html/draft-irtf-cfrg-argon2-03#section-9.3
package argon2

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"golang.org/x/crypto/blake2b"
)

// The Argon2 version implemented by this package.
const Version = 0x13

const (
	RecommendedTime   uint32 = 1
	RecommendedMemory uint32 = 32 * 1024
)

// constants used by the high-level API.
const (
	saltLen = 16
	keyLen  = 32
)

const (
	argon2d = iota
	argon2i
	argon2id
)

// If we would use a type for the above constants,
// this could be a generated method using the stringer tool.
// However, that would have required refactoring
// of the existing code.
func modeString(mode int) string {
	switch mode {
	case argon2d:
		return "argon2d"
	case argon2i:
		return "argon2i"
	case argon2id:
		return "argon2id"
	default:
		return "unknown"
	}
}

func parseMode(s string) (int, error) {
	switch s {
	case "argon2d":
		return argon2d, nil
	case "argon2i":
		return argon2i, nil
	case "argon2id":
		return argon2id, nil
	default:
		return -1, fmt.Errorf("argon2: unknown mode %s", s)
	}
}

// Key derives a key from the password, salt, and cost parameters using Argon2i
// returning a byte slice of length keyLen that can be used as cryptographic
// key. The CPU cost and parallelism degree must be greater than zero.
//
// For example, you can get a derived key for e.g. AES-256 (which needs a
// 32-byte key) by doing:
//
//	key := argon2.Key([]byte("some password"), salt, 3, 32*1024, 4, 32)
//
// The draft RFC recommends[2] time=3, and memory=32*1024 is a sensible number.
// If using that amount of memory (32 MB) is not possible in some contexts then
// the time parameter can be increased to compensate.
//
// The time parameter specifies the number of passes over the memory and the
// memory parameter specifies the size of the memory in KiB. For example
// memory=32*1024 sets the memory cost to ~32 MB. The number of threads can be
// adjusted to the number of available CPUs. The cost parameters should be
// increased as memory latency and CPU parallelism increases. Remember to get a
// good random salt.
func Key(password, salt []byte, time, memory uint32, threads uint8, keyLen uint32) []byte {
	return deriveKey(argon2i, password, salt, nil, nil, time, memory, threads, keyLen)
}

// IDKey derives a key from the password, salt, and cost parameters using
// Argon2id returning a byte slice of length keyLen that can be used as
// cryptographic key. The CPU cost and parallelism degree must be greater than
// zero.
//
// For example, you can get a derived key for e.g. AES-256 (which needs a
// 32-byte key) by doing:
//
//	key := argon2.IDKey([]byte("some password"), salt, 1, 64*1024, 4, 32)
//
// The draft RFC recommends[2] time=1, and memory=64*1024 is a sensible number.
// If using that amount of memory (64 MB) is not possible in some contexts then
// the time parameter can be increased to compensate.
//
// The time parameter specifies the number of passes over the memory and the
// memory parameter specifies the size of the memory in KiB. For example
// memory=64*1024 sets the memory cost to ~64 MB. The number of threads can be
// adjusted to the numbers of available CPUs. The cost parameters should be
// increased as memory latency and CPU parallelism increases. Remember to get a
// good random salt.
func IDKey(password, salt []byte, time, memory uint32, threads uint8, keyLen uint32) []byte {
	return deriveKey(argon2id, password, salt, nil, nil, time, memory, threads, keyLen)
}

func deriveKey(mode int, password, salt, secret, data []byte, time, memory uint32, threads uint8, keyLen uint32) []byte {
	if time < 1 {
		panic("argon2: number of rounds too small")
	}
	if threads < 1 {
		panic("argon2: parallelism degree too low")
	}
	h0 := initHash(password, salt, secret, data, time, memory, uint32(threads), keyLen, mode)

	memory = memory / (syncPoints * uint32(threads)) * (syncPoints * uint32(threads))
	if memory < 2*syncPoints*uint32(threads) {
		memory = 2 * syncPoints * uint32(threads)
	}
	B := initBlocks(&h0, memory, uint32(threads))
	processBlocks(B, time, memory, uint32(threads), mode)
	return extractKey(B, memory, uint32(threads), keyLen)
}

const (
	blockLength = 128
	syncPoints  = 4
)

type block [blockLength]uint64

func initHash(password, salt, key, data []byte, time, memory, threads, keyLen uint32, mode int) [blake2b.Size + 8]byte {
	var (
		h0     [blake2b.Size + 8]byte
		params [24]byte
		tmp    [4]byte
	)

	b2, _ := blake2b.New512(nil)
	binary.LittleEndian.PutUint32(params[0:4], threads)
	binary.LittleEndian.PutUint32(params[4:8], keyLen)
	binary.LittleEndian.PutUint32(params[8:12], memory)
	binary.LittleEndian.PutUint32(params[12:16], time)
	binary.LittleEndian.PutUint32(params[16:20], uint32(Version))
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
	return h0
}

func initBlocks(h0 *[blake2b.Size + 8]byte, memory, threads uint32) []block {
	var block0 [1024]byte
	B := make([]block, memory)
	for lane := uint32(0); lane < threads; lane++ {
		j := lane * (memory / threads)
		binary.LittleEndian.PutUint32(h0[blake2b.Size+4:], lane)

		binary.LittleEndian.PutUint32(h0[blake2b.Size:], 0)
		blake2bHash(block0[:], h0[:])
		for i := range B[j+0] {
			B[j+0][i] = binary.LittleEndian.Uint64(block0[i*8:])
		}

		binary.LittleEndian.PutUint32(h0[blake2b.Size:], 1)
		blake2bHash(block0[:], h0[:])
		for i := range B[j+1] {
			B[j+1][i] = binary.LittleEndian.Uint64(block0[i*8:])
		}
	}
	return B
}

func processBlocks(B []block, time, memory, threads uint32, mode int) {
	lanes := memory / threads
	segments := lanes / syncPoints

	processSegment := func(n, slice, lane uint32, wg *sync.WaitGroup) {
		var addresses, in, zero block
		if mode == argon2i || (mode == argon2id && n == 0 && slice < syncPoints/2) {
			in[0] = uint64(n)
			in[1] = uint64(lane)
			in[2] = uint64(slice)
			in[3] = uint64(memory)
			in[4] = uint64(time)
			in[5] = uint64(mode)
		}

		index := uint32(0)
		if n == 0 && slice == 0 {
			index = 2 // we have already generated the first two blocks
			if mode == argon2i || mode == argon2id {
				in[6]++
				processBlock(&addresses, &in, &zero)
				processBlock(&addresses, &addresses, &zero)
			}
		}

		offset := lane*lanes + slice*segments + index
		var random uint64
		for index < segments {
			prev := offset - 1
			if index == 0 && slice == 0 {
				prev += lanes // last block in lane
			}
			if mode == argon2i || (mode == argon2id && n == 0 && slice < syncPoints/2) {
				if index%blockLength == 0 {
					in[6]++
					processBlock(&addresses, &in, &zero)
					processBlock(&addresses, &addresses, &zero)
				}
				random = addresses[index%blockLength]
			} else {
				random = B[prev][0]
			}
			newOffset := indexAlpha(random, lanes, segments, threads, n, slice, lane, index)
			processBlockXOR(&B[offset], &B[prev], &B[newOffset])
			index, offset = index+1, offset+1
		}
		wg.Done()
	}

	for n := uint32(0); n < time; n++ {
		for slice := uint32(0); slice < syncPoints; slice++ {
			var wg sync.WaitGroup
			for lane := uint32(0); lane < threads; lane++ {
				wg.Add(1)
				go processSegment(n, slice, lane, &wg)
			}
			wg.Wait()
		}
	}

}

func extractKey(B []block, memory, threads, keyLen uint32) []byte {
	lanes := memory / threads
	for lane := uint32(0); lane < threads-1; lane++ {
		for i, v := range B[(lane*lanes)+lanes-1] {
			B[memory-1][i] ^= v
		}
	}

	var block [1024]byte
	for i, v := range B[memory-1] {
		binary.LittleEndian.PutUint64(block[i*8:], v)
	}
	key := make([]byte, keyLen)
	blake2bHash(key, block[:])
	return key
}

func indexAlpha(rand uint64, lanes, segments, threads, n, slice, lane, index uint32) uint32 {
	refLane := uint32(rand>>32) % threads
	if n == 0 && slice == 0 {
		refLane = lane
	}
	m, s := 3*segments, ((slice+1)%syncPoints)*segments
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

func getSalt(reader io.Reader) ([]byte, error) {
	salt := make([]byte, saltLen)
	if _, err := reader.Read(salt); err != nil {
		return nil, fmt.Errorf("argon2: %w generating salt", err)
	}

	return salt, nil
}

func newHash(password string, time, memoryKB uint32, reader io.Reader) (encoded string, err error) {
	enc := encoding{
		mode:        argon2id,
		version:     Version,
		memory:      memoryKB,
		time:        time,
		parallelism: 1,
	}

	if enc.salt, err = getSalt(reader); err != nil {
		return "", err
	}

	enc.key = IDKey([]byte(password), enc.salt, time, memoryKB, enc.parallelism, keyLen)

	return enc.String(), nil
}

// NewHash creates a new IDKey, encoded in the PHC string format for argon2.
// A random salt of 16 bytes is generated and stored in the encoded string,
// along with all used parameters for later password verification.
//
// See https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md
// for more information about the encoding scheme.
func NewHash(password string, time, memoryKB uint32) (encoded string, err error) {
	return newHash(password, time, memoryKB, rand.Reader)
}

// Cost extracts the parameters used from an PHC string formatted hash.
func Cost(hash string) (time, memoryKB uint32, threads uint8, err error) {
	enc, err := decode(hash)
	if err != nil {
		return 0, 0, 0, err
	}

	return enc.time, enc.memory, enc.parallelism, nil
}

var ErrPasswordMismatch = errors.New("password does not match")

// Check hashes password and compares the result with the key stored
// in the PHC encoded string, using the same parameters.
func Check(hash, password string) error {
	enc, err := decode(hash)
	if err != nil {
		return err
	}

	keyLen := uint32(len(enc.key))

	key := deriveKey(enc.mode, []byte(password), enc.salt, nil, nil, enc.time, enc.memory, enc.parallelism, keyLen)

	result := subtle.ConstantTimeCompare(key, enc.key)
	if result == 0 {
		return ErrPasswordMismatch
	}

	return nil
}

func calibrate(target time.Duration, memoryKB uint32, reader io.Reader) (times uint32, err error) {
	salt, err := getSalt(reader)
	if err != nil {
		return 0, err
	}

	password := []byte("password")
	times = RecommendedTime

	var sum time.Duration

	for i := 1; ; i++ {
		start := time.Now()
		IDKey(password, salt, times, memoryKB, 1, keyLen)
		dur := time.Since(start)

		sum += dur

		// average result of the times parameter
		avg := sum / time.Duration(i) / time.Duration(times)

		// increment is target - duration diveded by the average.
		incr := int32((target - dur) / avg)
		if incr == 0 { // found a stable times value, so we can stop.
			break
		}

		// applying half of the increment, prevents extreme overshooting
		// of times value. Something like a inversed gain.
		times += uint32(incr / 2)

		// fmt.Println("sum: ", sum, "dur:", dur, "avg:", avg, "incr:", incr)
	}

	// make sure times is not a unsafe low number or 0.
	if times < RecommendedTime {
		return RecommendedTime, nil
	}

	return times, nil
}

// Calibrate the time parameter for IDKey to take around target amount of time
// to hash a key, using a fixed amount of memory.
//
// This function iterates on executions of IDKey and can take a long time to
// complete if target is high and/or memoryKB is low, or when hardware is giving
// inconsistent results due to CPU power management.
func Calibrate(target time.Duration, memoryKB uint32) (times uint32, err error) {
	return calibrate(target, memoryKB, rand.Reader)
}
