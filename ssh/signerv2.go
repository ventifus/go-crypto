// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
)

// A SignerV2 can create signatures that verify against a public key.
type SignerV2 interface {
	// PublicKey returns the associated PublicKey.
	PublicKey() PublicKey

	// Sign returns a signature for the given data. This method will hash the
	// data appropriately first. The signature algorithm is expected to match
	// the key format returned by the PublicKey.Type method (and not to be any
	// alternative algorithm supported by the key format).
	Sign(rand io.Reader, data []byte) (*Signature, error)

	// SignWithAlgorithm is like Signer.Sign, but allows specifying a desired
	// signing algorithm. Callers may pass an empty string for the algorithm in
	// which case the AlgorithmSigner will use a default algorithm. This default
	// doesn't currently control any behavior in this package.
	SignWithAlgorithm(rand io.Reader, data []byte, algorithm string) (*Signature, error)

	// Algorithms returns the available algorithms in preference order. The list
	// must not be empty, and it must not include certificate types.
	Algorithms() []string
}

// NewSignerV2 takes any crypto.Signer implementation and returns a corresponding
// Signer interface. This can be used, for example, with keys kept in hardware
// modules.
func NewSignerV2(signer crypto.Signer) (SignerV2, error) {
	pubKey, err := NewPublicKey(signer.Public())
	if err != nil {
		return nil, err
	}

	return &wrappedSigner{signer, pubKey}, nil
}

// NewPublicKeyV2 takes an *rsa.PublicKey, *ecdsa.PublicKey or ed25519.PublicKey
// returns a corresponding PublicKey instance. ECDSA keys must use P-256, P-384
// or P-521.
func NewPublicKeyV2(key crypto.PublicKey) (PublicKey, error) {
	switch key := key.(type) {
	case *rsa.PublicKey:
		return (*rsaPublicKey)(key), nil
	case *ecdsa.PublicKey:
		if !supportedEllipticCurve(key.Curve) {
			return nil, errors.New("ssh: only P-256, P-384 and P-521 EC keys are supported")
		}
		return (*ecdsaPublicKey)(key), nil
	case ed25519.PublicKey:
		if l := len(key); l != ed25519.PublicKeySize {
			return nil, fmt.Errorf("ssh: invalid size %d for Ed25519 public key", l)
		}
		return ed25519PublicKey(key), nil
	default:
		return nil, fmt.Errorf("ssh: unsupported key type %T", key)
	}
}

// MarshalPrivateKeyOptionsV2 defines the available options to Marshal a private
// key in OpenSSH format.
type MarshalPrivateKeyOptionsV2 struct {
	Comment string
	// If set the key will be encrypted.
	Passphrase string
	// Defines the number of rounds for key derivation. The default value is 24.
	// Increasing the number of rounds enhances security but also slows down key
	// derivation.
	SaltRounds int
}

// MarshalPrivateKeyV2 returns a PEM block with the private key serialized in the
// OpenSSH format.
func MarshalPrivateKeyV2(key crypto.PrivateKey, options *MarshalPrivateKeyOptionsV2) (*pem.Block, error) {
	if options.Passphrase != "" {
		if options.SaltRounds <= 0 {
			// See here: https://github.com/openssh/openssh-portable/blob/e048230/sshkey.c#L2855.
			options.SaltRounds = 24
		}
		return marshalOpenSSHPrivateKey(key, options.Comment,
			passphraseProtectedOpenSSHMarshaler([]byte(options.Passphrase), uint32(options.SaltRounds)))
	}
	return marshalOpenSSHPrivateKey(key, options.Comment, unencryptedOpenSSHMarshaler)
}
