// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package chacha20

import (
	"encoding/hex"
	"fmt"
	"testing"
)

func TestCore(t *testing.T) {
	testCore(t)
}

func testCore(t *testing.T) {
	// This is just a smoke test that checks the example from
	// https://tools.ietf.org/html/rfc7539#section-2.3.2. The
	// chacha20poly1305 package contains much more extensive tests of this
	// code.
	var key [32]byte
	for i := range key {
		key[i] = byte(i)
	}

	var input [16]byte
	input[0] = 1
	input[7] = 9
	input[11] = 0x4a

	var out [64]byte
	XORKeyStream(out[:], out[:], &input, &key)
	const expected = "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e"
	if result := hex.EncodeToString(out[:]); result != expected {
		t.Errorf("wanted %x but got %x", expected, result)
	}
}

// TestBoundsCheck tests that a call to XORKeyStream panics if the output slice
// is shorter than the input slice.
// Note: this test primarily exists to ensure that assembly implementations
// panic correctly.
func TestBoundsCheck(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			return
		}
		t.Errorf("expected panic")
	}()

	var key [32]byte
	var counter [16]byte
	msg := make([]byte, 256)
	XORKeyStream(msg[:len(msg)-2], msg, &counter, &key)
}

// TestNoInput tests that XORKeyStream correctly accepts input slices with
// a length of 0.
func TestNoInput(t *testing.T) {
	var key [32]byte
	var counter [16]byte
	msg := make([]byte, 256)
	for i := range msg {
		msg[i] = byte(i)
	}
	XORKeyStream(msg, msg[:0], &counter, &key)
	for i := range msg {
		if msg[i] != byte(i) {
			t.Errorf("msg[%v]: got %v, want %v", i, msg[i], byte(i))
		}
	}
}

func BenchmarkChaCha20(b *testing.B) {
	sizes := []int{32, 63, 64, 256, 1024, 1350, 65536}
	for _, size := range sizes {
		s := size
		b.Run(fmt.Sprint(s), func(b *testing.B) {
			k := [32]byte{}
			c := [16]byte{}
			src := make([]byte, s)
			dst := make([]byte, s)
			b.SetBytes(int64(s))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				XORKeyStream(dst, src, &c, &k)
			}
		})
	}
}
