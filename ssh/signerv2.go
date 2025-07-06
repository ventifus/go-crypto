// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
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

	// SignContext is like Signer.Sign, but allows specifying a context and a
	// desired signing algorithm. Callers may pass an empty string for the
	// algorithm in which case the Signer will use a default algorithm. This
	// default doesn't currently control any behavior in this package. This
	// package prioritizes SignContext if available, falling back to
	// SignWithAlgorithm (for backward compatibility), and then to Sign.
	SignContext(ctx context.Context, rand io.Reader, data []byte, algorithm string) (*Signature, error)

	// Algorithms returns the available algorithms in preference order. The list
	// must not be empty, and it must not include certificate types.
	Algorithms() []string

	// PrivateKey returns the underlying [crypto.Signer] used for signing
	// operations, if available. PrivateKey may return an error wrapping
	// [errors.ErrUnsupported]. Otherwise, PrivateKey must always return a nil
	// error.
	PrivateKey() (crypto.Signer, error)
}

// NewSignerV2 wraps any crypto.Signer implementation and returns a
// corresponding Signer interface. This is useful, for example, when working
// with keys stored in hardware security modules (HSMs). For RSA signers, SHA-1
// algorithms are excluded by default. If you need to specify which algorithms
// to use, consider using [NewSignerV2WithAlgorithms] instead.
func NewSignerV2(signer crypto.Signer) (SignerV2, error) {
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

// NewSignerV2WithAlgorithms wraps an existing SignerV2 implementation and
// returns a new SignerV2 that is restricted to the specified signature
// algorithms.
func NewSignerV2WithAlgorithms(signer SignerV2, algorithms []string) (SignerV2, error) {
	privateKey, err := signer.PrivateKey()
	if err != nil {
		return nil, fmt.Errorf("ssh: the provided signer failed to return a private key: %w", err)
	}
	if len(algorithms) == 0 {
		return nil, fmt.Errorf("ssh: please specify at least one valid signing algorithm for key type %q",
			signer.PublicKey().Type())
	}
	supportedAlgos := algorithmsForKeyFormat(underlyingAlgo(signer.PublicKey().Type()))

	for _, algo := range algorithms {
		if !contains(supportedAlgos, algo) {
			return nil, fmt.Errorf("ssh: algorithm %q is not supported for key type %q",
				algo, signer.PublicKey().Type())
		}
	}
	return &wrappedSignerWithAlgorithms{wrappedSigner{privateKey, signer.PublicKey()}, algorithms}, nil
}

// NewCertificateSignerV2 returns a SignerV2 that signs with the given
// Certificate, whose private key is held by signer. It returns an error if the
// public key in cert doesn't match the key used by signer.
func NewCertificateSignerV2(cert *Certificate, signer SignerV2) (SignerV2, error) {
	privateKey, err := signer.PrivateKey()
	if err != nil {
		return nil, fmt.Errorf("ssh: the provided signer failed to return a private key: %w", err)
	}
	if !bytes.Equal(cert.Key.Marshal(), signer.PublicKey().Marshal()) {
		return nil, errors.New("ssh: signer and cert have different public key")
	}
	return &multiAlgorithmSigner{
		privateKey: privateKey,
		AlgorithmSigner: &algorithmOpenSSHCertSigner{
			&openSSHCertSigner{cert, signer}, &wrappedSignerV2{signer}},
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
	privateKey, err := key.PrivateKey()
	if err != nil {
		return nil, fmt.Errorf("ssh: the provided signer failed to return a private key: %w", err)
	}
	if options == nil {
		options = &MarshalPrivateKeyV2Options{}
	}
	if options.Passphrase != "" {
		if options.SaltRounds <= 0 {
			// See here: https://github.com/openssh/openssh-portable/blob/e048230/sshkey.c#L2855.
			options.SaltRounds = 24
		}
		return marshalOpenSSHPrivateKey(privateKey, options.Comment,
			passphraseProtectedOpenSSHMarshaler([]byte(options.Passphrase), uint32(options.SaltRounds)))
	}
	return marshalOpenSSHPrivateKey(privateKey, options.Comment, unencryptedOpenSSHMarshaler)
}

// ParsePrivateKeyV2Options defines the available options to Parse a PEM encoded
// private key.
type ParsePrivateKeyV2Options struct {
	// If set the key will be encrypted.
	Passphrase string

	// SignatureAlgorithms is a list of supported signature algorithms of which
	// the return of SignerV2 algorithms will be a subset. If nil a list of safe
	// defaults will be used. This list may change over time.
	SignatureAlgorithms []string
}

// ParsePrivateKeyV2 parses a PEM-encoded private key and returns a SignerV2.
// The key must implement the [crypto.Signer] interface and be one of the
// following types: *rsa.PrivateKey, ed25519.PrivateKey, or *ecdsa.PrivateKey.
// For encrypted private keys, the OpenSSH format is currently supported.
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

	cryptoSigner, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("ssh: unsupported key type %T", key)
	}

	signer, err := NewSignerV2(cryptoSigner)
	if err != nil {
		return nil, err
	}
	if len(options.SignatureAlgorithms) == 0 {
		return signer, nil
	}

	pubKey, err := newPublicKeyV2(cryptoSigner.Public())
	if err != nil {
		return nil, err
	}
	supportedAlgorithms := algorithmsForKeyFormat(underlyingAlgo(pubKey.Type()))
	algorithms := slices.DeleteFunc(options.SignatureAlgorithms, func(signAlgo string) bool {
		return !slices.Contains(supportedAlgorithms, signAlgo)
	})
	return NewSignerV2WithAlgorithms(signer, algorithms)
}

func parseRawPrivateKey(pemBytes []byte) (any, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("ssh: no key found")
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

	return nil, fmt.Errorf("ssh: unsupported key type %q", block.Type)
}

// wrappedSignerV2 wraps a SignerV2 and adds the SignWithAlgorithm method for
// compatibility with interfaces expecting it.
type wrappedSignerV2 struct {
	SignerV2
}

func (s *wrappedSignerV2) SignWithAlgorithm(rand io.Reader, data []byte, algorithm string) (*Signature, error) {
	return s.SignContext(context.Background(), rand, data, algorithm)
}

func signWithSigner(signer Signer, rand io.Reader, data []byte, algorithm string) (*Signature, error) {
	switch s := signer.(type) {
	case SignerV2:
		return s.SignContext(context.Background(), rand, data, algorithm)
	case AlgorithmSigner:
		return s.SignWithAlgorithm(rand, data, algorithm)
	default:
		return s.Sign(rand, data)
	}
}
