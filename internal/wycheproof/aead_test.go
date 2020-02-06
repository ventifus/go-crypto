// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wycheproof

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"testing"
)

func TestAead(t *testing.T) {
	// AeadTestVector
	type AeadTestVector struct {

		// additional authenticated data
		Aad string `json:"aad,omitempty"`

		// A brief description of the test case
		Comment string `json:"comment,omitempty"`

		// the ciphertext (without iv and tag)
		Ct string `json:"ct,omitempty"`

		// A list of flags
		Flags []string `json:"flags,omitempty"`

		// the nonce
		Iv string `json:"iv,omitempty"`

		// the key
		Key string `json:"key,omitempty"`

		// the plaintext
		Msg string `json:"msg,omitempty"`

		// Test result
		Result string `json:"result,omitempty"`

		// the authentication tag
		Tag string `json:"tag,omitempty"`

		// Identifier of the test case
		TcId int `json:"tcId,omitempty"`
	}

	// Notes a description of the labels used in the test vectors
	type Notes struct {
	}

	// AeadTestGroup
	type AeadTestGroup struct {

		// the IV size in bits
		IvSize int `json:"ivSize,omitempty"`

		// the keySize in bits
		KeySize int `json:"keySize,omitempty"`

		// the expected size of the tag in bits
		TagSize int               `json:"tagSize,omitempty"`
		Tests   []*AeadTestVector `json:"tests,omitempty"`
		Type    interface{}       `json:"type,omitempty"`
	}

	// Root
	type Root struct {

		// the primitive tested in the test file
		Algorithm string `json:"algorithm,omitempty"`

		// the version of the test vectors.
		GeneratorVersion string `json:"generatorVersion,omitempty"`

		// additional documentation
		Header []string `json:"header,omitempty"`

		// a description of the labels used in the test vectors
		Notes *Notes `json:"notes,omitempty"`

		// the number of test vectors in this test
		NumberOfTests int              `json:"numberOfTests,omitempty"`
		Schema        interface{}      `json:"schema,omitempty"`
		TestGroups    []*AeadTestGroup `json:"testGroups,omitempty"`
	}

	flagsShouldPass := map[string]bool{
		// Ivs smaller than 12 bytes are less secure with AES-GCM, but still allowed.
		"SmallIv": true,
	}

	var root Root
	readTestVector(t, "aes_gcm_test.json", &root)
	for _, tg := range root.TestGroups {
		for _, tv := range tg.Tests {
			block, err := aes.NewCipher(decodeHex(tv.Key))
			if err != nil {
				t.Fatalf("#%d: %v", tv.TcId, err)
			}
			// IvSize is in bits, but NonceSize is in bytes, so divide by 8.
			aead, err := cipher.NewGCMWithNonceSize(block, tg.IvSize/8)
			if err != nil {
				t.Fatalf("#%d: %v", tv.TcId, err)
			}
			if tg.TagSize/8 != aead.Overhead() {
				t.Fatalf("#%d: bad tag length", tv.TcId)
			}

			// Encrypt the message, then decrypt the new ciphertext and validate
			// the decrypted message.
			ciphertext := aead.Seal(nil, decodeHex(tv.Iv), decodeHex(tv.Msg), decodeHex(tv.Aad))
			msg, err := aead.Open(nil, decodeHex(tv.Iv), ciphertext, decodeHex(tv.Aad))
			if got, want := hex.EncodeToString(msg), tv.Msg; got != want {
				t.Errorf("#%d: bad message after encrypting and decrypting: %s, want %v", tv.TcId, got, want)
			}

			// Decrypt the ciphertext and validate the decrypted message.
			tv.Ct += tv.Tag // append the tag to the ciphertext
			msg2, err := aead.Open(nil, decodeHex(tv.Iv), decodeHex(tv.Ct), decodeHex(tv.Aad))
			if wantPass := shouldPass(tv.Result, tv.Flags, flagsShouldPass); (err == nil) != wantPass {
				t.Errorf("#%d, type: %s, comment: %q, decryption wanted success: %t, got err: %v", tv.TcId, tv.Result, tv.Comment, wantPass, err)
			}
			if err != nil {
				continue // don't validate message if decryption failed
			}
			if got, want := hex.EncodeToString(msg2), tv.Msg; got != want {
				t.Errorf("#%d: bad message after decrypting ciphertext: %s, want %v", tv.TcId, got, want)
			}
		}
	}
}

// This is failing because an IV size of 0 leaks the authentication
// key, thus should not be allowed, but our implementation passes.
// The RFC?
