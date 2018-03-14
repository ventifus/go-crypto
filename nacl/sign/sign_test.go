// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sign

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

var testKeys, _ = hex.DecodeString("983c6aa621ccbbb2a7e89794de5ff8118af3331a035c439903132dd7b4c48bb0f63320a3348b7be2feb4e73a54082dd70cb7c0e3bf626c55f0332852f8487dfd")
var testSignedMessage, _ = hex.DecodeString("26a0a47f733d02ddb74589b6cbd6f64a7dab1947db79395a1a9e00e4c902c0f185b119897b89b248d16bab4ea781b5a3798d25c2984aec833dddab57e0891e0d68656c6c6f20776f726c64")
var testMessage = testSignedMessage[Overhead:]
var testPrivateKey [64]byte
var testPublicKey [32]byte

func init() {
	copy(testPrivateKey[:], testKeys)
	copy(testPublicKey[:], testPrivateKey[32:])
}

func TestSign(t *testing.T) {
	var signedMessage = Sign(nil, testMessage, &testPrivateKey)
	if !bytes.Equal(signedMessage, testSignedMessage) {
		t.Fatalf("signed message did not match, got\n%x\n, expected\n%x", signedMessage, testSignedMessage)
	}
}

func TestOpen(t *testing.T) {
	var message, ok = Open(nil, testSignedMessage, &testPublicKey)
	if !ok {
		t.Fatalf("valid signed message not successfully verified")
	}
	if !bytes.Equal(message, testMessage) {
		t.Fatalf("message did not match, got\n%x\n, expected\n%x", message, testMessage)
	}
	message, ok = Open(nil, testSignedMessage[1:], &testPublicKey)
	if ok {
		t.Fatalf("invalid signed message successfully verified")
	}
}

func TestGenerateSignOpen(t *testing.T) {
	var publicKey, privateKey, _ = GenerateKey(rand.Reader)
	var signedMessage = Sign(nil, testMessage, privateKey)
	var message, ok = Open(nil, signedMessage, publicKey)
	if !ok {
		t.Fatalf("failed to verify signed message")
	}
	if !bytes.Equal(message, testMessage) {
		t.Fatalf("verified message does not match signed messge, got\n%x\n, expected\n%x", message, testMessage)
	}
}
