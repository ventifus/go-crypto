// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"crypto"
	"crypto/dsa"
	"encoding/pem"
	"reflect"
	"testing"
)

func TestNewPublicKeyV2(t *testing.T) {
	for _, k := range testSigners {
		raw := rawKey(k.PublicKey())
		// Skip certificates, as NewPublicKey does not support them.
		if _, ok := raw.(*Certificate); ok {
			continue
		}
		// Skip DSA keys, not supported in V2.
		if _, ok := raw.(*dsa.PublicKey); ok {
			continue
		}
		pub, err := newPublicKeyV2(raw)
		if err != nil {
			t.Errorf("NewPublicKey(%#v): %v", raw, err)
		}
		if !reflect.DeepEqual(k.PublicKey(), pub) {
			t.Errorf("NewPublicKey(%#v) = %#v, want %#v", raw, pub, k.PublicKey())
		}
	}
}

func TestMarshalPrivateKeyV2(t *testing.T) {
	tests := []struct {
		name string
	}{
		{"rsa-openssh-format"},
		{"ed25519"},
		{"p256-openssh-format"},
		{"p384-openssh-format"},
		{"p521-openssh-format"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k, ok := testPrivateKeys[tt.name]
			if !ok {
				t.Fatalf("cannot find key %s", tt.name)
			}
			expected, ok := k.(crypto.Signer)
			if !ok {
				t.Fatalf("key %s isn't a crypto.Signer", tt.name)
			}

			block, err := MarshalPrivateKeyV2(expected, &MarshalPrivateKeyOptionsV2{Comment: "test@golang.org"})
			if err != nil {
				t.Fatalf("cannot marshal %s: %v", tt.name, err)
			}

			key, err := ParsePrivateKeyV2(pem.EncodeToMemory(block), nil)
			if err != nil {
				t.Fatalf("cannot parse %s: %v", tt.name, err)
			}

			if !reflect.DeepEqual(expected, key) {
				t.Errorf("unexpected marshaled key %s", tt.name)
			}
		})
	}
}

func TestMarshalPrivateKeyWithPassphraseV2(t *testing.T) {
	tests := []struct {
		name string
	}{
		{"rsa-openssh-format"},
		{"ed25519"},
		{"p256-openssh-format"},
		{"p384-openssh-format"},
		{"p521-openssh-format"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k, ok := testPrivateKeys[tt.name]
			if !ok {
				t.Fatalf("cannot find key %s", tt.name)
			}
			expected, ok := k.(crypto.Signer)
			if !ok {
				t.Fatalf("key %s isn't a crypto.Signer", tt.name)
			}
			block, err := MarshalPrivateKeyV2(expected, &MarshalPrivateKeyOptionsV2{
				Comment:    "test@golang.org",
				Passphrase: "test-passphrase",
				SaltRounds: 32,
			})
			if err != nil {
				t.Fatalf("cannot marshal %s: %v", tt.name, err)
			}

			key, err := ParsePrivateKeyV2(pem.EncodeToMemory(block), &ParsePrivateKeyOptionsV2{Passphrase: "test-passphrase"})
			if err != nil {
				t.Fatalf("cannot parse %s: %v", tt.name, err)
			}

			if !reflect.DeepEqual(expected, key) {
				t.Errorf("unexpected marshaled key %s", tt.name)
			}
		})
	}
}
