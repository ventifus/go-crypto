// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wycheproof

import (
	"encoding/hex"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

func TestChaCha20Poly1305(t *testing.T) {
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

	// badNonceTestIDs have a bad nonce that causes a panic
	// in aead.Seal, so should be skipped
	badNonceTestIDs := []int{294, 295, 296, 297, 298, 299, 300}

	var root Root
	readTestVector(t, "chacha20_poly1305_test.json", &root)
	for _, tg := range root.TestGroups {
	tests:
		for _, tv := range tg.Tests {
			for _, id := range badNonceTestIDs {
				if id == tv.TcId {
					continue tests
				}
			}
			// IvSize is in bits, but NonceSize is in bytes, so divide by 8
			if tg.IvSize/8 != chacha20poly1305.NonceSize {
				t.Fatalf("#%d: bad nonce length: %d", tv.TcId, tg.IvSize)
			}
			aead, err := chacha20poly1305.New(decodeHex(tv.Key))
			if err != nil {
				t.Fatalf("#%d: %v", tv.TcId, err)
			}

			// Encrypt the message, then decrypt the new ciphertext and validate
			// the decrypted message
			ciphertext := aead.Seal(nil, decodeHex(tv.Iv), decodeHex(tv.Msg), decodeHex(tv.Aad))
			msg, err := aead.Open(nil, decodeHex(tv.Iv), ciphertext, decodeHex(tv.Aad))
			if got, want := hex.EncodeToString(msg), tv.Msg; got != want {
				t.Errorf("#%d: bad message after encrypting and decrypting: %s, want %v", tv.TcId, got, want)
			}

			// Decrypt the ciphertext and validate the decrypted message
			tv.Ct += tv.Tag // append the tag to the ciphertext
			msg2, err := aead.Open(nil, decodeHex(tv.Iv), decodeHex(tv.Ct), decodeHex(tv.Aad))
			if wantPass := shouldPass(tv.Result, tv.Flags, nil); (err == nil) != wantPass {
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
