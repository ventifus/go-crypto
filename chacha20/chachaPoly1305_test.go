// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package chacha20

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// Test vector from:
// https://tools.ietf.org/html/rfc7539#section-2.8.2
var aeadTestVectors = []struct {
	key, nonce, data string
	msg, ciphertext  string
	tagSize          int
}{
	{
		key: "808182838485868788898a8b8c8d8e8f" +
			"909192939495969798999a9b9c9d9e9f",
		nonce: "070000004041424344454647",
		data:  "50515253c0c1c2c3c4c5c6c7",
		msg: "4c616469657320616e642047656e746c656d656e206f662074686520636c6173" +
			"73206f66202739393a204966204920636f756c64206f6666657220796f75206f" +
			"6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73" +
			"637265656e20776f756c642062652069742e",
		ciphertext: "d31a8d34648e60db7b86afbc53ef7ec2" +
			"a4aded51296e08fea9e2b5a736ee62d6" +
			"3dbea45e8ca9671282fafb69da92728b" +
			"1a71de0a9e060b2905d6a5b67ecd3b36" +
			"92ddbd7f2d778b8c9803aee328091b58" +
			"fab324e4fad675945585808b4831d7bc" +
			"3ff4def08e4b7a9de576d26586cec64b" +
			"6116" +
			"1ae10b594f09e26a7e902ecbd0600691", // poly 1305 tag
		tagSize: TagSize,
	},
	{
		key: "808182838485868788898a8b8c8d8e8f" +
			"909192939495969798999a9b9c9d9e9f",
		nonce: "070000004041424344454647",
		data:  "50515253c0c1c2c3c4c5c6c7",
		msg: "4c616469657320616e642047656e746c656d656e206f662074686520636c6173" +
			"73206f66202739393a204966204920636f756c64206f6666657220796f75206f" +
			"6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73" +
			"637265656e20776f756c642062652069742e",
		ciphertext: "d31a8d34648e60db7b86afbc53ef7ec2" +
			"a4aded51296e08fea9e2b5a736ee62d6" +
			"3dbea45e8ca9671282fafb69da92728b" +
			"1a71de0a9e060b2905d6a5b67ecd3b36" +
			"92ddbd7f2d778b8c9803aee328091b58" +
			"fab324e4fad675945585808b4831d7bc" +
			"3ff4def08e4b7a9de576d26586cec64b" +
			"6116" +
			"1ae10b594f09e26a7e902ecb", // poly 1305 tag
		tagSize: 12,
	},
}

func TestAEADVectors(t *testing.T) {
	for i, v := range aeadTestVectors {
		key := fromHex(v.key)
		nonce := fromHex(v.nonce)
		msg := fromHex(v.msg)
		data := fromHex(v.data)
		ciphertext := fromHex(v.ciphertext)

		var Key [32]byte
		copy(Key[:], key)
		c, err := NewChaCha20Poly1305WithTagSize(&Key, v.tagSize)
		if err != nil {
			t.Fatalf("Test vector %d: Failed to create AEAD instance: %s", i, err)
		}

		buf := make([]byte, len(ciphertext))
		c.Seal(buf, nonce, msg, data)

		if !bytes.Equal(buf, ciphertext) {
			t.Fatalf("TestVector %d Seal failed:\nFound   : %s\nExpected: %s", i, hex.EncodeToString(buf), hex.EncodeToString(ciphertext))
		}

		buf, err = c.Open(buf, nonce, buf, data)

		if err != nil {
			t.Fatalf("TestVector %d: Open failed - Cause: %s", i, err)
		}
		if !bytes.Equal(msg, buf) {
			t.Fatalf("TestVector %d Open failed:\nFound   : %s\nExpected: %s", i, hex.EncodeToString(buf), hex.EncodeToString(msg))
		}
	}
}

var recFunc = func(t *testing.T, msg string) {
	if recover() == nil {
		t.Fatalf("Expected error: %s", msg)
	}
}

func TestNewChaCha20Poly1305WithTagSize(t *testing.T) {
	var key [32]byte
	_, err := NewChaCha20Poly1305WithTagSize(&key, 0)
	if err == nil {
		t.Fatalf("NewChaCha20Poly1305WithTagSize accepted invalid tagsize: %d", 0)
	}

	_, err = NewChaCha20Poly1305WithTagSize(&key, 17)
	if err == nil {
		t.Fatalf("NewChaCha20Poly1305WithTagSize accepted invalid tagsize: %d", 0)
	}
}

func TestOverhead(t *testing.T) {
	var key [32]byte
	c := NewChaCha20Poly1305(&key)

	if o := c.Overhead(); o != TagSize {
		t.Fatalf("Expected %d but Overhead() returned %d", TagSize, o)
	}

	c, err := NewChaCha20Poly1305WithTagSize(&key, 12)
	if err != nil {
		t.Fatalf("Failed to create ChaCha20Poly1305 instance: %s", err)
	}
	if o := c.Overhead(); o != 12 {
		t.Fatalf("Expected %d but Overhead() returned %d", 12, o)
	}
}

func TestNonceSize(t *testing.T) {
	var key [32]byte
	c := NewChaCha20Poly1305(&key)
	if n := c.NonceSize(); n != NonceSize {
		t.Fatalf("Expected %d but NonceSize() returned %d", TagSize, n)
	}
}

func TestSeal(t *testing.T) {
	var key [32]byte
	c := NewChaCha20Poly1305(&key)

	var (
		nonce [NonceSize]byte
		src   [64]byte
		dst   [64 + TagSize]byte
	)

	mustFail := func(msg string, dst, nonce, src []byte) {
		defer recFunc(t, msg)
		c.Seal(dst, nonce, src, nil)
	}

	mustFail("nonce size is invalid", dst[:], nonce[:NonceSize-1], src[:])

	mustFail("dst length invalid", dst[:len(dst)-2], nonce[:], src[:])
}

func TestOpen(t *testing.T) {
	var key [32]byte
	c := NewChaCha20Poly1305(&key)

	var (
		nonce [NonceSize]byte
		src   [64]byte
		dst   [64 + TagSize]byte
	)

	_, err := c.Open(dst[:], nonce[:NonceSize-1], src[:], nil)
	if err == nil {
		t.Fatal("Open() accepted invalid nonce size")
	}

	_, err = c.Open(dst[:], nonce[:], src[:TagSize-1], nil)
	if err == nil {
		t.Fatal("Open() accepted invalid ciphertext length")
	}

	mustFail := func(msg string, dst, nonce, src []byte) {
		defer recFunc(t, msg)
		c.Open(dst, nonce, src, nil)
	}

	mustFail("dst length invalid", dst[:len(src)-TagSize-1], nonce[:], src[:])

	// Check tag verification
	c.Seal(dst[:], nonce[:], src[:], nil)
	dst[len(src)+1] += 1 // modify tag

	_, err = c.Open(src[:], nonce[:], dst[:], nil)
	if err == nil {
		t.Fatal("Open() accepted invalid auth. tag")
	}
}

// Benchmarks

func BenchmarkSeal64B(b *testing.B) {
	var key [32]byte
	var nonce [12]byte
	c := NewChaCha20Poly1305(&key)

	msg := make([]byte, 64)
	dst := make([]byte, len(msg)+TagSize)
	data := make([]byte, 32)

	b.SetBytes(int64(len(msg)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dst = c.Seal(dst, nonce[:], msg, data)
	}
}

func BenchmarkSeal16K(b *testing.B) {
	var key [32]byte
	var nonce [12]byte
	c := NewChaCha20Poly1305(&key)

	msg := make([]byte, 16*1024)
	dst := make([]byte, len(msg)+TagSize)
	data := make([]byte, 32)

	b.SetBytes(int64(len(msg)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dst = c.Seal(dst, nonce[:], msg, data)
	}
}

func BenchmarkOpen64B(b *testing.B) {
	var key [32]byte
	var nonce [12]byte
	c := NewChaCha20Poly1305(&key)

	msg := make([]byte, 64)
	dst := make([]byte, len(msg))
	ciphertext := make([]byte, len(msg)+TagSize)
	data := make([]byte, 32)
	ciphertext = c.Seal(ciphertext, nonce[:], msg, data)

	b.SetBytes(int64(len(msg)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dst, _ = c.Open(dst, nonce[:], ciphertext, data)
	}
}

func BenchmarkOpen16K(b *testing.B) {
	var key [32]byte
	var nonce [12]byte
	c := NewChaCha20Poly1305(&key)

	msg := make([]byte, 16*1024)
	dst := make([]byte, len(msg))
	ciphertext := make([]byte, len(msg)+TagSize)
	data := make([]byte, 32)
	ciphertext = c.Seal(ciphertext, nonce[:], msg, data)

	b.SetBytes(int64(len(msg)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dst, _ = c.Open(dst, nonce[:], ciphertext, data)
	}
}
