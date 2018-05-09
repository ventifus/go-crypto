// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package cryptotest provides a test suite for implementations of
// crypto/cipher interfaces.
//
// Its API is not yet stable, and might change significantly.
package cryptotest

// TODO(filippo): cipher.AEAD tests.
// TODO(filippo): hash.Hash tests.
// TODO(filippo): cipher.Block tests.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"fmt"
	"io"
	"testing"
)

// MakeBlockMode returns a cipher.BlockMode instance.
// It expects len(iv) == b.BlockSize().
type MakeBlockMode func(b cipher.Block, iv []byte) cipher.BlockMode

// TestBlockMode performs a set of tests on cipher.BlockMode implementations,
// checking the documented requirements of CryptBlocks.
func TestBlockMode(t *testing.T, encrypter, decrypter MakeBlockMode) {
	rng := newRandReader(t)

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
			testBlockModePair(t, rng, encrypter, decrypter, c, iv)
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
		testBlockModePair(t, rng, encrypter, decrypter, c, iv)
	})
}

func testBlockModePair(t *testing.T, rng io.Reader, e, d MakeBlockMode, b cipher.Block, iv []byte) {
	t.Run("Encryption", func(t *testing.T) {
		testBlockMode(t, rng, e, b, iv)
	})
	t.Run("Decryption", func(t *testing.T) {
		testBlockMode(t, rng, d, b, iv)
	})
	t.Run("Cycle", func(t *testing.T) {
		bs := e(b, iv).BlockSize()
		if d(b, iv).BlockSize() != bs {
			t.Skip("mismatching encryption and decryption blocksizes")
		}
		plaintext, dst := make([]byte, bs*2), make([]byte, bs*2)
		rng.Read(plaintext)
		e(b, iv).CryptBlocks(dst, plaintext)
		d(b, iv).CryptBlocks(dst, dst)
		expectEqual(t, plaintext, dst, "plaintext is different after a encrypt/decrypt cycle")
	})
}

func testBlockMode(t *testing.T, rng io.Reader, bm MakeBlockMode, b cipher.Block, iv []byte) {
	bs := bm(b, iv).BlockSize()

	t.Run("WrongIVLen", func(t *testing.T) {
		iv := make([]byte, b.BlockSize()+1)
		expectPanic(t, func() { bm(b, iv) }, "did not panic for len(IV) != cipher.Block.BlockSize()")
	})

	t.Run("Aliasing", func(t *testing.T) {
		plaintext, ciphertext, dst := make([]byte, bs*2), make([]byte, bs*2), make([]byte, bs*2)
		for _, length := range []int{0, bs, bs * 2} {
			rng.Read(plaintext)
			copy(dst, plaintext)

			bm(b, iv).CryptBlocks(ciphertext[:length], plaintext[:length])
			expectEqual(t, dst, plaintext, "encryption modified src")

			bm(b, iv).CryptBlocks(dst[:length], dst[:length])
			expectEqual(t, dst[:length], ciphertext[:length], "encryption behaves differently when dst = src")

			bm(b, iv).CryptBlocks(dst, plaintext[:length])
			expectEqual(t, dst[length:], plaintext[length:], "encryption modified dst past len(src)")
		}
	})

	t.Run("PartialBlocks", func(t *testing.T) {
		buf := make([]byte, bs)
		expectPanic(t, func() { bm(b, iv).CryptBlocks(buf, buf[:bs-1]) }, "expected panic for partial src block")
	})

	t.Run("OutOfBoundsWrite", func(t *testing.T) { // Issue 21104
		plaintext, ciphertext := make([]byte, bs*2), make([]byte, bs*2)
		rng.Read(plaintext)
		copy(ciphertext, plaintext)
		expectPanic(t, func() { bm(b, iv).CryptBlocks(ciphertext[:bs], plaintext) },
			"CryptBlocks expected to panic on len(dst) < len(src), but didn't")
		expectEqual(t, plaintext[bs:], ciphertext[bs:], "CryptBlocks did out of bounds write")
	})

	t.Run("KeepState", func(t *testing.T) {
		plaintext, ciphertext, dst := make([]byte, bs*4), make([]byte, bs*4), make([]byte, bs*4)
		rng.Read(plaintext)
		bm(b, iv).CryptBlocks(ciphertext, plaintext)

		length, b := 2*bs, bm(b, iv)
		b.CryptBlocks(dst, plaintext[:length])
		b.CryptBlocks(dst[length:], plaintext[length:])

		expectEqual(t, ciphertext, dst, "two successive CryptBlocks calls returned a different result than a single one")
	})
}
