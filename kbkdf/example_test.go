// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package kbkdf_test

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"golang.org/x/crypto/kbkdf"
)

// Usage example that expands one primary secret into three other
// cryptographically secure keys.
func Example_usage() {
	// Underlying hash function for HMAC.
	h := sha256.New

	// Cryptographically secure primary secret.
	secret := []byte{0x00, 0x01, 0x02, 0x03} // i.e. NOT this.

	// Non-secret label identifying the purpose, optional (can be nil).
	label := []byte("kbkdf example")

	// Generate three 128-bit derived keys.
	for i := 0; i < 3; i++ {
		// Non-secret derivation context, optional (can be nil).
		// Recommended: hash-length random value.
		context := make([]byte, h().Size())
		if _, err := rand.Read(context); err != nil {
			panic(err)
		}
		key := kbkdf.HMACCounter(sha256.New, 16, secret, label, context)
		fmt.Printf("Key #%d: %v\n", i+1, !bytes.Equal(key, make([]byte, 16)))
	}

	// Output:
	// Key #1: true
	// Key #2: true
	// Key #3: true
}
