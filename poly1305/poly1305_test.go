// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package poly1305

import (
	"bytes"
	"testing"
	"unsafe"
)

func generateTestData(size int) (key [32]byte, tag [16]byte, m []byte) {
	for i := range key {
		key[i] = 0xff
	}
	m = make([]byte, size)
	for i := range m {
		m[i] = 0xff
	}
	poly1305Generic(&tag, m, &key)
	return
}

var testData = []struct {
	in, k, correct []byte
}{
	{
		[]byte("Hello world!"),
		[]byte("this is 32-byte key for Poly1305"),
		[]byte{0xa6, 0xf7, 0x45, 0x00, 0x8f, 0x81, 0xc9, 0x16, 0xa2, 0x0d, 0xcc, 0x74, 0xee, 0xf2, 0xb2, 0xf0},
	},
	{
		make([]byte, 32),
		[]byte("this is 32-byte key for Poly1305"),
		[]byte{0x49, 0xec, 0x78, 0x09, 0x0e, 0x48, 0x1e, 0xc6, 0xc2, 0x6b, 0x33, 0xb9, 0x1c, 0xcc, 0x03, 0x07},
	},
	{
		make([]byte, 2007),
		[]byte("this is 32-byte key for Poly1305"),
		[]byte{0xda, 0x84, 0xbc, 0xab, 0x02, 0x67, 0x6c, 0x38, 0xcd, 0xb0, 0x15, 0x60, 0x42, 0x74, 0xc2, 0xaa},
	},
	{
		make([]byte, 2007),
		make([]byte, 32),
		make([]byte, 16),
	},
}

func testSum(t *testing.T, unaligned bool) {
	var out [16]byte
	var key [32]byte

	for i, v := range testData {
		in := v.in
		if unaligned {
			in = unalignBytes(in)
		}
		copy(key[:], v.k)
		Sum(&out, in, &key)
		if !bytes.Equal(out[:], v.correct) {
			t.Errorf("%d: got %x, expected %x", i, out[:], v.correct)
		}
	}

	for size := 0; size < 1000; size++ {
		key, correct, m := generateTestData(size)
		Sum(&out, m, &key)
		if !bytes.Equal(out[:], correct[:]) {
			t.Errorf("Size %d: got %x, expected %x", size, out[:], correct[:])
		}
	}
}

func TestSum(t *testing.T)          { testSum(t, false) }
func TestSumUnaligned(t *testing.T) { testSum(t, true) }

func benchmark(b *testing.B, size int, unaligned bool) {
	var out [16]byte
	var key [32]byte
	in := make([]byte, size)
	if unaligned {
		in = unalignBytes(in)
	}
	b.SetBytes(int64(len(in)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Sum(&out, in, &key)
	}
}

func Benchmark64(b *testing.B)          { benchmark(b, 64, false) }
func Benchmark1K(b *testing.B)          { benchmark(b, 1024, false) }
func Benchmark64Unaligned(b *testing.B) { benchmark(b, 64, true) }
func Benchmark1KUnaligned(b *testing.B) { benchmark(b, 1024, true) }

func unalignBytes(in []byte) []byte {
	out := make([]byte, len(in)+1)
	if uintptr(unsafe.Pointer(&out[0]))&(unsafe.Alignof(uint32(0))-1) == 0 {
		out = out[1:]
	} else {
		out = out[:len(in)]
	}
	copy(out, in)
	return out
}
