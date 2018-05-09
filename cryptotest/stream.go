// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cryptotest

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"fmt"
	"io"
	"math/rand"
	"strings"
	"testing"
	"time"
)

// Each test is executed with each of the buffer lengths in bufLens.
var (
	bufLens = []int{0, 1, 3, 4, 8, 10, 15, 16, 20, 32, 50, 4096, 5000}
	bufCap  = 10000
)

// MakeStream returns a cipher.Stream instance.
//
// Multiple calls to MakeStream must return equivalent instances,
// so for example the key and/or IV must be fixed.
type MakeStream func() cipher.Stream

// TestStream performs a set of tests on cipher.Stream implementations,
// checking the documented requirements of XORKeyStream.
func TestStream(t *testing.T, ms MakeStream) {
	rng := newRandReader(t)

	t.Run("Aliasing", func(t *testing.T) {
		plaintext := make([]byte, bufCap)
		rng.Read(plaintext)
		for _, length := range bufLens {
			lenmsg := fmt.Sprintf("length %d: ", length)

			b1, b2 := make([]byte, length), make([]byte, length)
			copy(b1, plaintext)

			rng.Read(b2)
			ms().XORKeyStream(b2, b1)
			expectEqual(t, plaintext[:length], b1, lenmsg+"src modified when different from dst")

			ms().XORKeyStream(b1, b1)
			expectEqual(t, b2, b1, lenmsg+"different result with src = dst")

			b3 := make([]byte, bufCap)
			copy(b3, plaintext)
			ms().XORKeyStream(b3, plaintext[:length])
			expectEqual(t, plaintext[length:], b3[length:], lenmsg+"rest of dst modified with len(src) < len(dst)")
		}
	})

	t.Run("XORSemantics", func(t *testing.T) {
		if strings.Contains(t.Name(), "TestCFBStream") {
			// This is ugly, but so is CFB's abuse of cipher.Stream.
			// Don't want to make it easier for anyone else to do that.
			t.Skip("CFB implements cipher.Stream but does not follow XOR semantics")
		}

		plaintext := make([]byte, bufCap)
		rng.Read(plaintext)
		for _, length := range bufLens {
			lenmsg := fmt.Sprintf("length %d: ", length)

			b1, b2 := make([]byte, length), make([]byte, length)

			ms().XORKeyStream(b1, plaintext[:length])
			ms().XORKeyStream(b1, b1)
			expectEqual(t, plaintext[:length], b1, lenmsg+"encrypt-decrypt cycle did not return plaintext")

			ms().XORKeyStream(b1, b1)
			xor(b1, plaintext[:length])
			ms().XORKeyStream(b2, b2)
			expectEqual(t, b2, b1, lenmsg+"xor semantics were not preserved")
		}
	})

	t.Run("OutOfBoundsWrite", func(t *testing.T) { // Issue 21104
		plaintext := make([]byte, bufCap)
		rng.Read(plaintext)
		ciphertext := make([]byte, bufCap)
		copy(ciphertext, plaintext)
		for _, length := range bufLens {
			lenmsg := fmt.Sprintf("length %d: ", length)
			expectPanic(t, func() { ms().XORKeyStream(ciphertext[:length], plaintext) },
				"XORKeyStream expected to panic on len(dst) < len(src), but didn't")
			expectEqual(t, plaintext[length:], ciphertext[length:], lenmsg+"XORKeyStream did out of bounds write")
		}
	})

	t.Run("KeepState", func(t *testing.T) {
		plaintext := make([]byte, bufCap)
		rng.Read(plaintext)
		ciphertext, dst := make([]byte, bufCap), make([]byte, bufCap)
		ms().XORKeyStream(ciphertext, plaintext)
		for _, step := range bufLens {
			if step == 0 {
				continue
			}
			lenmsg := fmt.Sprintf("step %d: ", step)

			for i := range dst {
				dst[i] = 0
			}

			stream := ms()
			i := 0
			for i+step < len(plaintext) {
				stream.XORKeyStream(dst[i:], plaintext[i:i+step])
				i += step
			}
			stream.XORKeyStream(dst[i:], plaintext[i:])

			expectEqual(t, ciphertext, dst, lenmsg+"two successive XORKeyStream calls returned a different result than a single one")
		}
	})
}

// TestStreamFromBlock performs the same tests as TestStream, but simplifies
// testing block modes that can be instantiated with a cipher.Block and an IV.
func TestStreamFromBlock(t *testing.T, bm func(b cipher.Block, iv []byte) cipher.Stream) {
	rng := newRandReader(t)

	t.Run("WrongIVLen", func(t *testing.T) {
		key := make([]byte, 16)
		c, _ := aes.NewCipher(key)
		iv := make([]byte, aes.BlockSize+1)
		expectPanic(t, func() { bm(c, iv) }, "did not panic for len(IV) != cipher.Block.BlockSize()")
	})

	for _, keylen := range []int{128, 192, 256} {
		t.Run(fmt.Sprintf("AES-%d", keylen), func(t *testing.T) {
			iv := make([]byte, aes.BlockSize)
			rng.Read(iv)
			key := make([]byte, keylen/8)
			rng.Read(key)
			c, err := aes.NewCipher(key)
			if err != nil {
				panic(err)
			}
			TestStream(t, func() cipher.Stream { return bm(c, iv) })
		})
	}

	t.Run("DES", func(t *testing.T) {
		key := make([]byte, 8)
		rng.Read(key)
		iv := make([]byte, des.BlockSize)
		rng.Read(iv)
		c, err := des.NewCipher(key)
		if err != nil {
			panic(err)
		}
		TestStream(t, func() cipher.Stream { return bm(c, iv) })
	})
}

func newRandReader(t *testing.T) io.Reader {
	seed := time.Now().UnixNano()
	t.Logf("Deterministic RNG seed: 0x%x", seed)
	return rand.New(rand.NewSource(seed))
}

func expectEqual(t *testing.T, want, got []byte, msg string) {
	if !bytes.Equal(want, got) {
		t.Errorf("%s; want %x, got %x", msg, want, got)
	}
}

func expectPanic(t *testing.T, f func(), msg string) {
	defer func() {
		err := recover()
		if err == nil {
			t.Errorf(msg)
		}
	}()
	f()
}

func xor(a, b []byte) {
	for i := range a {
		a[i] ^= b[i]
	}
}
