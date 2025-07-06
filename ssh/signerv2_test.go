// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"crypto/dsa"
	"crypto/rand"
	"encoding/pem"
	"reflect"
	"slices"
	"testing"

	"golang.org/x/crypto/ssh/testdata"
)

func TestNewSignerV2(t *testing.T) {
	for name, key := range testdata.PEMBytes {
		if name == "dsa" {
			continue
		}
		signer, err := ParsePrivateKeyV2(key, nil)
		if err != nil {
			t.Fatalf("unable to parse private key %q: %v", name, err)
		}
		if signer.PublicKey().Type() == KeyAlgoRSA {
			algorithms := signer.Algorithms()
			if len(algorithms) != 2 {
				t.Fatalf("unexpected number of algorithms for ssh-rsa key type: expected 2, got %d", len(algorithms))
			}
			if algorithms[0] != KeyAlgoRSASHA256 {
				t.Errorf("unexpected first algorithm for ssh-rsa key type: expected %q, got %q", KeyAlgoRSASHA256, algorithms[0])
			}
			if algorithms[1] != KeyAlgoRSASHA512 {
				t.Errorf("unexpected second algorithm for ssh-rsa key type: expected %q, got %q", KeyAlgoRSASHA512, algorithms[1])
			}
		} else {
			if len(signer.Algorithms()) != 1 || signer.Algorithms()[0] != signer.PublicKey().Type() {
				t.Fatalf("unexpected algorithms for key %q: expected [%q], got %+v", name, signer.PublicKey().Type(), signer.Algorithms())
			}
		}
	}
}

func TestNewSignerV2WithAlgorithms(t *testing.T) {
	key, err := ParsePrivateKeyV2(testdata.PEMBytes["rsa"], nil)
	if err != nil {
		t.Fatalf("unable to parse RSA private key: %v", err)
	}

	_, err = NewSignerV2WithAlgorithms(key, []string{KeyAlgoECDSA256})
	if err == nil {
		t.Fatal("expected error when creating signer with incompatible algorithms, but got nil")
	}
	signer, err := NewSignerV2WithAlgorithms(key, []string{KeyAlgoRSASHA512})
	if err != nil {
		t.Fatalf("NewSignerV2WithAlgorithms(%#v): %v", key, err)
	}
	if !slices.Equal(signer.Algorithms(), []string{KeyAlgoRSASHA512}) {
		t.Fatalf("unexpected signer algorithms: expected [%q], got %v", KeyAlgoRSASHA512, signer.Algorithms())
	}
}

func TestParsePrivateKeyV2Options(t *testing.T) {
	options := ParsePrivateKeyV2Options{
		SignatureAlgorithms: []string{KeyAlgoRSA, KeyAlgoRSASHA256, KeyAlgoRSASHA512, KeyAlgoED25519},
	}
	signer, err := ParsePrivateKeyV2(testdata.PEMBytes["rsa"], &options)
	if err != nil {
		t.Fatalf("unable to parse RSA private key: %v", err)
	}
	expected := []string{KeyAlgoRSA, KeyAlgoRSASHA256, KeyAlgoRSASHA512}
	if !slices.Equal(signer.Algorithms(), expected) {
		t.Fatalf("unexpected signer algorithms: expected %v, got %v", expected, signer.Algorithms())
	}
}

func TestNewPublicKeyV2(t *testing.T) {
	for _, k := range testSigners {
		raw := rawKey(k.PublicKey())
		// Skip certificates, as NewPublicKey does not support them.
		if _, ok := raw.(*Certificate); ok {
			continue
		}
		// DSA keys are not supported in V2.
		_, isDSA := raw.(*dsa.PublicKey)
		pub, err := newPublicKeyV2(raw)
		if isDSA {
			if err == nil {
				t.Fatal("DSA keys are not supported in V2, parsing should fail")
			}
			continue
		}
		if err != nil {
			t.Fatalf("NewPublicKey(%#v): %v", raw, err)
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
			expected, err := ParsePrivateKeyV2(testdata.PEMBytes[tt.name], nil)
			if err != nil {
				t.Fatal(err)
			}
			block, err := MarshalPrivateKeyV2(expected, &MarshalPrivateKeyV2Options{Comment: "test@golang.org"})
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
			expected, err := ParsePrivateKeyV2(testdata.PEMBytes[tt.name], nil)
			if err != nil {
				t.Fatal(err)
			}
			block, err := MarshalPrivateKeyV2(expected, &MarshalPrivateKeyV2Options{
				Comment:    "test@golang.org",
				Passphrase: "test-passphrase",
				SaltRounds: 32,
			})
			if err != nil {
				t.Fatalf("cannot marshal %s: %v", tt.name, err)
			}

			key, err := ParsePrivateKeyV2(pem.EncodeToMemory(block), &ParsePrivateKeyV2Options{Passphrase: "test-passphrase"})
			if err != nil {
				t.Fatalf("cannot parse %s: %v", tt.name, err)
			}

			if !reflect.DeepEqual(expected, key) {
				t.Errorf("unexpected marshaled key %s", tt.name)
			}
		})
	}
}

func TestCertSignerV2(t *testing.T) {
	signer, err := ParsePrivateKeyV2(testdata.PEMBytes["ed25519"], nil)
	if err != nil {
		t.Fatalf("unable to parse certificate key: %v", err)
	}
	authority, err := ParsePrivateKeyV2(testdata.PEMBytes["ecdsa"], nil)
	if err != nil {
		t.Fatalf("unable to parse authority key: %v", err)
	}

	cert := &Certificate{
		Key:             signer.PublicKey(),
		ValidPrincipals: []string{"test username"},
		CertType:        UserCert,
		ValidBefore:     CertTimeInfinity,
	}
	if err := cert.SignCert(rand.Reader, authority); err != nil {
		t.Fatalf("SignCert: %v", err)
	}

	_, err = NewCertificateSignerV2(cert, signer)
	if err != nil {
		t.Fatalf("NewCertificateSignerV2: %v", err)
	}
}
