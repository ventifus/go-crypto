// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"slices"
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

	// PrivateKey returns the underlying [crypto.Signer] used for signing
	// operations, if available. Implementations may return nil if the private
	// key cannot be accessed directly.
	PrivateKey() crypto.Signer
}

// NewSignerV2WithAlgorithms takes any crypto.Signer implementation and returns
// a corresponding Signer interface restricted to the specified algorithms.
func NewSignerV2WithAlgorithms(signer SignerV2, algorithms []string) (SignerV2, error) {
	if len(algorithms) == 0 {
		return nil, errors.New("ssh: please specify at least one valid signing algorithm")
	}
	supportedAlgos := algorithmsForKeyFormat(underlyingAlgo(signer.PublicKey().Type()))

	for _, algo := range algorithms {
		if !contains(supportedAlgos, algo) {
			return nil, fmt.Errorf("ssh: algorithm %q is not supported for key type %q",
				algo, signer.PublicKey().Type())
		}
	}
	return &wrappedSignerWithAlgorithms{wrappedSigner{signer.PrivateKey(), signer.PublicKey()}, algorithms}, nil
}

// NewCertificateSignerV2 returns a SignerV2 that signs with the given
// Certificate, whose private key is held by signer. It returns an error if the
// public key in cert doesn't match the key used by signer.
func NewCertificateSignerV2(cert *Certificate, signer SignerV2) (SignerV2, error) {
	if !bytes.Equal(cert.Key.Marshal(), signer.PublicKey().Marshal()) {
		return nil, errors.New("ssh: signer and cert have different public key")
	}
	return &multiAlgorithmSigner{
		privateKey: signer.PrivateKey(),
		AlgorithmSigner: &algorithmOpenSSHCertSigner{
			&openSSHCertSigner{cert, signer}, signer},
		supportedAlgorithms: signer.Algorithms(),
	}, nil
}

// newPublicKeyV2 takes an *rsa.PublicKey, *ecdsa.PublicKey or ed25519.PublicKey
// returns a corresponding PublicKey instance. ECDSA keys must use P-256, P-384
// or P-521.
func newPublicKeyV2(key crypto.PublicKey) (PublicKey, error) {
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

type wrappedSignerWithAlgorithms struct {
	wrappedSigner
	supportedAlgorithms []string
}

func (s *wrappedSignerWithAlgorithms) Algorithms() []string {
	return s.supportedAlgorithms
}

// MarshalPrivateKeyV2Options defines the available options to Marshal a private
// key in OpenSSH format.
type MarshalPrivateKeyV2Options struct {
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
func MarshalPrivateKeyV2(key SignerV2, options *MarshalPrivateKeyV2Options) (*pem.Block, error) {
	if options == nil {
		options = &MarshalPrivateKeyV2Options{}
	}
	if options.Passphrase != "" {
		if options.SaltRounds <= 0 {
			// See here: https://github.com/openssh/openssh-portable/blob/e048230/sshkey.c#L2855.
			options.SaltRounds = 24
		}
		return marshalOpenSSHPrivateKey(key.PrivateKey(), options.Comment,
			passphraseProtectedOpenSSHMarshaler([]byte(options.Passphrase), uint32(options.SaltRounds)))
	}
	return marshalOpenSSHPrivateKey(key.PrivateKey(), options.Comment, unencryptedOpenSSHMarshaler)
}

// ParsePrivateKeyV2Options defines the available options to Parse a PEM encoded
// private key .
type ParsePrivateKeyV2Options struct {
	// If set the key will be encrypted.
	Passphrase string
}

// ParsePrivateKeyV2 parses a PEM-encoded private key and returns a SignerV2.
// The provided key must implement the [crypto.Signer] interface.
func ParsePrivateKeyV2(pemBytes []byte, options *ParsePrivateKeyV2Options) (SignerV2, error) {
	if options == nil {
		options = &ParsePrivateKeyV2Options{}
	}
	var key any
	var err error

	if options.Passphrase != "" {
		key, err = parseRawPrivateKeyWithPassphrase(pemBytes, []byte(options.Passphrase))
	} else {
		key, err = parseRawPrivateKey(pemBytes)
	}

	if err != nil {
		return nil, err
	}

	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("ssh: unsupported key type %T", key)
	}

	pubKey, err := newPublicKeyV2(signer.Public())
	if err != nil {
		return nil, err
	}
	algorithms := algorithmsForKeyFormat(underlyingAlgo(pubKey.Type()))
	algorithms = slices.DeleteFunc(algorithms, func(algorithm string) bool {
		return algorithm == KeyAlgoRSA
	})

	return &wrappedSignerWithAlgorithms{wrappedSigner{signer, pubKey}, algorithms}, nil
}

func parseRawPrivateKey(pemBytes []byte) (any, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("ssh: no key found")
	}

	if encryptedBlock(block) {
		return nil, &PassphraseMissingError{}
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	// RFC5208 - https://tools.ietf.org/html/rfc5208
	case "PRIVATE KEY":
		return x509.ParsePKCS8PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "OPENSSH PRIVATE KEY":
		return parseOpenSSHPrivateKey(block.Bytes, unencryptedOpenSSHKey)
	default:
		return nil, fmt.Errorf("ssh: unsupported key type %q", block.Type)
	}
}

func parseRawPrivateKeyWithPassphrase(pemBytes, passphrase []byte) (interface{}, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("ssh: no key found")
	}

	if block.Type == "OPENSSH PRIVATE KEY" {
		return parseOpenSSHPrivateKey(block.Bytes, passphraseProtectedOpenSSHKey(passphrase))
	}

	if !encryptedBlock(block) || !x509.IsEncryptedPEMBlock(block) {
		return nil, errors.New("ssh: not an encrypted key")
	}

	buf, err := x509.DecryptPEMBlock(block, passphrase)
	if err != nil {
		if err == x509.IncorrectPasswordError {
			return nil, err
		}
		return nil, fmt.Errorf("ssh: cannot decode encrypted private keys: %v", err)
	}

	var result interface{}

	switch block.Type {
	case "RSA PRIVATE KEY":
		result, err = x509.ParsePKCS1PrivateKey(buf)
	case "EC PRIVATE KEY":
		result, err = x509.ParseECPrivateKey(buf)
	default:
		err = fmt.Errorf("ssh: unsupported key type %q", block.Type)
	}
	// Because of deficiencies in the format, DecryptPEMBlock does not always
	// detect an incorrect password. In these cases decrypted DER bytes is
	// random noise. If the parsing of the key returns an asn1.StructuralError
	// we return x509.IncorrectPasswordError.
	if _, ok := err.(asn1.StructuralError); ok {
		return nil, x509.IncorrectPasswordError
	}

	return result, err
}
