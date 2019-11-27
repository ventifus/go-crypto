// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wycheproof

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"
)

func TestEddsa(t *testing.T) {
	b := readTestVector("eddsa_test.json")
	var root EddsaRoot
	if err := json.Unmarshal(b, &root); err != nil {
		t.Fatalf("failed to unmarshal json file: %v", err)
	}
	for _, tg := range root.TestGroups {
		pub := decodeKey(tg.KeyDer).(ed25519.PublicKey)
		for _, sig := range tg.Tests {
			got := ed25519.Verify(pub, decodeHex(sig.Msg), decodeHex(sig.Sig))
			want := shouldPass(sig.Result, sig.Flags, nil)
			if got != want {
				t.Errorf("tcid=%d, type: %s, comment: %q, wanted success = %t", sig.TcId, sig.Result, sig.Comment, want)
			}
		}
	}
}

// EddsaTestGroup
type EddsaTestGroup struct {

	// the private key in webcrypto format
	Jwk *Jwk `json:"jwk,omitempty"`

	// unencoded key pair
	Key *Key `json:"key,omitempty"`

	// Asn encoded public key
	KeyDer string `json:"keyDer,omitempty"`

	// Pem encoded public key
	KeyPem string                 `json:"keyPem,omitempty"`
	Tests  []*SignatureTestVector `json:"tests,omitempty"`
	Type   interface{}            `json:"type,omitempty"`
}

// Jwk the private key in webcrypto format
type Jwk struct {
}

// Key unencoded key pair
type Key struct {
}

// EddsaRoot
type EddsaRoot struct {

	// the primitive tested in the test file
	Algorithm string `json:"algorithm,omitempty"`

	// the version of the test vectors.
	GeneratorVersion string `json:"generatorVersion,omitempty"`

	// additional documentation
	Header []string `json:"header,omitempty"`

	// a description of the labels used in the test vectors
	Notes *Notes `json:"notes,omitempty"`

	// the number of test vectors in this test
	NumberOfTests int               `json:"numberOfTests,omitempty"`
	Schema        interface{}       `json:"schema,omitempty"`
	TestGroups    []*EddsaTestGroup `json:"testGroups,omitempty"`
}
