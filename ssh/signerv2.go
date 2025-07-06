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

	return NewSignerV2WithAlgorithms(signer, algorithms)
}

// NewSignerV2WithAlgorithms takes any crypto.Signer implementation and returns
// a corresponding Signer interface restricted to the specified algorithms.
func NewSignerV2WithAlgorithms(signer crypto.Signer, algorithms []string) (SignerV2, error) {
	if len(algorithms) == 0 {
		return nil, errors.New("ssh: please specify at least one valid signing algorithm")
	}
	pubKey, err := newPublicKeyV2(signer.Public())
	if err != nil {
		return nil, err
	}
	supportedAlgos := algorithmsForKeyFormat(underlyingAlgo(pubKey.Type()))

	for _, algo := range algorithms {
		if !contains(supportedAlgos, algo) {
			return nil, fmt.Errorf("ssh: algorithm %q is not supported for key type %q",
				algo, pubKey.Type())
		}
	}
	return &wrappedSignerWithAlgorithms{wrappedSigner{signer, pubKey}, algorithms}, nil
}

// NewCertificateSignerV2 returns a SignerV2 that signs with the given
// Certificate, whose private key is held by signer. It returns an error if the
// public key in cert doesn't match the key used by signer.
func NewCertificateSignerV2(cert *Certificate, signer SignerV2) (SignerV2, error) {
	if !bytes.Equal(cert.Key.Marshal(), signer.PublicKey().Marshal()) {
		return nil, errors.New("ssh: signer and cert have different public key")
	}
	return &multiAlgorithmSigner{
		AlgorithmSigner: &algorithmOpenSSHCertSigner{
			&openSSHCertSigner{cert, signer}, signer},
		supportedAlgorithms: signer.Algorithms(),
	}, nil
}

// SignCertV2 signs the certificate with an authority, setting the Nonce,
// SignatureKey, and Signature fields. If the authority implements the
// MultiAlgorithmSigner interface the first algorithm in the list is used. This
// is useful if you want to sign with a specific algorithm. As specified in
// [SSH-CERTS], Section 2.1.1, authority can't be a [Certificate].
func (c *Certificate) SignCertV2(rand io.Reader, authority SignerV2) error {
	c.Nonce = make([]byte, 32)
	if _, err := io.ReadFull(rand, c.Nonce); err != nil {
		return err
	}
	// The Type() function is intended to return only certificate key types, but
	// we use certKeyAlgoNames anyway for safety, to match [Certificate.Type].
	if _, ok := certKeyAlgoNames[authority.PublicKey().Type()]; ok {
		return fmt.Errorf("ssh: certificates cannot be used as authority (public key type %q)",
			authority.PublicKey().Type())
	}
	c.SignatureKey = authority.PublicKey()

	if len(authority.Algorithms()) == 0 {
		return errors.New("the provided authority has no signature algorithm")
	}
	// Use the first algorithm in the list.
	sig, err := authority.SignWithAlgorithm(rand, c.bytesForSigning(), authority.Algorithms()[0])
	if err != nil {
		return err
	}
	c.Signature = sig
	return nil
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
func MarshalPrivateKeyV2(key crypto.Signer, options *MarshalPrivateKeyOptionsV2) (*pem.Block, error) {
	if options == nil {
		options = &MarshalPrivateKeyOptionsV2{}
	}
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

// ParsePrivateKeyOptionsV2 defines the available options to Parse a PEM encoded
// private key .
type ParsePrivateKeyOptionsV2 struct {
	// If set the key will be encrypted.
	Passphrase string
}

// ParsePrivateKeyV2 returns a crypto.Signer from a PEM encoded private key.
func ParsePrivateKeyV2(pemBytes []byte, options *ParsePrivateKeyOptionsV2) (crypto.Signer, error) {
	if options == nil {
		// FIXME: don't use a pointer?
		options = &ParsePrivateKeyOptionsV2{}
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

	if signer, ok := key.(crypto.Signer); ok {
		return signer, nil
	}
	return nil, fmt.Errorf("ssh: unsupported key type %T", key)
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
