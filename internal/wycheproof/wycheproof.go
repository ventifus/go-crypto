// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package wycheproof runs a set of the Wycheproof tests
// provided by https://github.com/google/wycheproof.
package wycheproof

import (
	"crypto"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"hash"
	"io/ioutil"
)

func readTestVector(f string) []byte {
	b, err := ioutil.ReadFile(fmt.Sprintf("vendor/testvectors/%s", f))
	if err != nil {
		panic(fmt.Sprintf("failed to read json file: %v", err))
	}
	return b
}

func decodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func decodeKey(der string) interface{} {
	d := decodeHex(der)
	pub, err := x509.ParsePKIXPublicKey(d)
	if err != nil {
		panic(fmt.Sprintf("failed to parse DER encoded public key: %v", err))
	}
	return pub
}

func parseHash(h string) (hash.Hash, crypto.Hash) {
	switch h {
	case "SHA-1":
		return sha1.New(), crypto.SHA1
	case "SHA-256":
		return sha256.New(), crypto.SHA256
	case "SHA-224":
		return sha256.New224(), crypto.SHA224
	case "SHA-384":
		return sha512.New384(), crypto.SHA384
	case "SHA-512":
		return sha512.New(), crypto.SHA512
	case "SHA-512/224":
		return sha512.New512_224(), crypto.SHA512_224
	case "SHA-512/256":
		return sha512.New512_256(), crypto.SHA512_256
	default:
		panic(fmt.Sprintf("could not identify SHA hash algorithm: %q", h))
	}
}

func shouldPass(result string, flags []string, flagsShouldPass map[string]bool) bool {
	switch result {
	case "valid":
		return true
	case "invalid":
		return false
	case "acceptable":
		for _, flag := range flags {
			pass, ok := flagsShouldPass[flag]
			if !ok {
				panic(fmt.Sprintf("unspecified flag: %q", flag))
			}
			if !pass {
				return false
			}
		}
		return true // There are no flags, or all are meant to pass.
	default:
		panic(fmt.Sprintf("unexpected result: %v", result))
	}
}

// Notes a description of the labels used in the test vectors
type Notes struct {
}

// SignatureTestVector
type SignatureTestVector struct {

	// A brief description of the test case
	Comment string `json:"comment,omitempty"`

	// A list of flags
	Flags []string `json:"flags,omitempty"`

	// The message to sign
	Msg string `json:"msg,omitempty"`

	// Test result
	Result string `json:"result,omitempty"`

	// A signature for msg
	Sig string `json:"sig,omitempty"`

	// Identifier of the test case
	TcId int `json:"tcId,omitempty"`
}
