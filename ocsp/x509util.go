// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ocsp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	encoding_asn1 "encoding/asn1"
	"errors"
	"fmt"
	"math/big"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

// marshalCertID returns a serialised CertID structure for the given serial
// number using hashFunc to hash the name and key from issuer. If hashFunc is
// zero, SHA-1 is used.
func marshalCertID(hashFunc crypto.Hash, serial *big.Int, issuer *x509.Certificate) ([]byte, error) {
	if hashFunc == 0 {
		hashFunc = crypto.SHA1
	}

	hashOID := getOIDFromHashAlgorithm(hashFunc)
	if hashOID == nil {
		return nil, errors.New("ocsp: unsupported issuer hash algorithm")
	}

	if !hashFunc.Available() {
		return nil, fmt.Errorf("ocsp: hash algorithm %v (for hashing issuer name and key) not linked into binary", hashFunc)
	}

	h := hashFunc.New()

	var pubKeyBytes []byte
	var spkiSeq cryptobyte.String
	spki := cryptobyte.String(issuer.RawSubjectPublicKeyInfo)
	if !spki.ReadASN1(&spkiSeq, asn1.SEQUENCE) ||
		!spki.Empty() ||
		!spkiSeq.SkipASN1(asn1.SEQUENCE) ||
		!spkiSeq.ReadASN1BitStringAsBytes(&pubKeyBytes) {
		return nil, ParseError("ocsp: failed to parse SPKI from issuer certificate")
	}

	h.Write(pubKeyBytes)
	issuerKeyHash := h.Sum(nil)

	h.Reset()
	h.Write(issuer.RawSubject)
	issuerNameHash := h.Sum(nil)

	var certIDBuilder cryptobyte.Builder
	certIDBuilder.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		// hashAlgorithm
		b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(hashOID)
			b.AddASN1NULL()
		})
		b.AddASN1OctetString(issuerNameHash)
		b.AddASN1OctetString(issuerKeyHash)
		b.AddASN1BigInt(serial)
	})

	return certIDBuilder.Bytes()
}

var (
	idPKIXOCSPBasic             = encoding_asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 1}
	oidSignatureMD2WithRSA      = encoding_asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 2}
	oidSignatureMD5WithRSA      = encoding_asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 4}
	oidSignatureSHA1WithRSA     = encoding_asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
	oidSignatureSHA256WithRSA   = encoding_asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSignatureSHA384WithRSA   = encoding_asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidSignatureSHA512WithRSA   = encoding_asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	oidSignatureDSAWithSHA1     = encoding_asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 3}
	oidSignatureDSAWithSHA256   = encoding_asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 2}
	oidSignatureECDSAWithSHA1   = encoding_asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 1}
	oidSignatureECDSAWithSHA256 = encoding_asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidSignatureECDSAWithSHA384 = encoding_asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidSignatureECDSAWithSHA512 = encoding_asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
)

var hashOIDs = map[crypto.Hash]encoding_asn1.ObjectIdentifier{
	crypto.SHA1:   encoding_asn1.ObjectIdentifier([]int{1, 3, 14, 3, 2, 26}),
	crypto.SHA256: encoding_asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 2, 1}),
	crypto.SHA384: encoding_asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 2, 2}),
	crypto.SHA512: encoding_asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 2, 3}),
}

// TODO(rlb): This is also from crypto/x509, so same comment as AGL's below
var signatureAlgorithmDetails = []struct {
	algo       x509.SignatureAlgorithm
	oid        encoding_asn1.ObjectIdentifier
	pubKeyAlgo x509.PublicKeyAlgorithm
	hash       crypto.Hash
}{
	{x509.MD2WithRSA, oidSignatureMD2WithRSA, x509.RSA, crypto.Hash(0) /* no value for MD2 */},
	{x509.MD5WithRSA, oidSignatureMD5WithRSA, x509.RSA, crypto.MD5},
	{x509.SHA1WithRSA, oidSignatureSHA1WithRSA, x509.RSA, crypto.SHA1},
	{x509.SHA256WithRSA, oidSignatureSHA256WithRSA, x509.RSA, crypto.SHA256},
	{x509.SHA384WithRSA, oidSignatureSHA384WithRSA, x509.RSA, crypto.SHA384},
	{x509.SHA512WithRSA, oidSignatureSHA512WithRSA, x509.RSA, crypto.SHA512},
	{x509.DSAWithSHA1, oidSignatureDSAWithSHA1, x509.DSA, crypto.SHA1},
	{x509.DSAWithSHA256, oidSignatureDSAWithSHA256, x509.DSA, crypto.SHA256},
	{x509.ECDSAWithSHA1, oidSignatureECDSAWithSHA1, x509.ECDSA, crypto.SHA1},
	{x509.ECDSAWithSHA256, oidSignatureECDSAWithSHA256, x509.ECDSA, crypto.SHA256},
	{x509.ECDSAWithSHA384, oidSignatureECDSAWithSHA384, x509.ECDSA, crypto.SHA384},
	{x509.ECDSAWithSHA512, oidSignatureECDSAWithSHA512, x509.ECDSA, crypto.SHA512},
}

// TODO(rlb): This is also from crypto/x509, so same comment as AGL's below
func signingParamsForPublicKey(pub interface{}, requestedSigAlgo x509.SignatureAlgorithm) (hashFunc crypto.Hash, sigAlgoBytes []byte, err error) {
	var pubType x509.PublicKeyAlgorithm
	var algoOID []int
	var nullParameters bool

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		pubType = x509.RSA
		hashFunc = crypto.SHA256
		algoOID = oidSignatureSHA256WithRSA
		nullParameters = true

	case *ecdsa.PublicKey:
		pubType = x509.ECDSA

		switch pub.Curve {
		case elliptic.P224(), elliptic.P256():
			hashFunc = crypto.SHA256
			algoOID = oidSignatureECDSAWithSHA256
		case elliptic.P384():
			hashFunc = crypto.SHA384
			algoOID = oidSignatureECDSAWithSHA384
		case elliptic.P521():
			hashFunc = crypto.SHA512
			algoOID = oidSignatureECDSAWithSHA512
		default:
			err = errors.New("x509: unknown elliptic curve")
		}

	default:
		err = errors.New("x509: only RSA and ECDSA keys supported")
	}

	if err != nil {
		return
	}

	if requestedSigAlgo != 0 {
		found := false
		for _, details := range signatureAlgorithmDetails {
			if details.algo == requestedSigAlgo {
				if details.pubKeyAlgo != pubType {
					err = errors.New("x509: requested SignatureAlgorithm does not match private key type")
					return
				}
				algoOID, hashFunc = details.oid, details.hash
				if hashFunc == 0 {
					err = errors.New("x509: cannot sign with hash function requested")
					return
				}
				found = true
				break
			}
		}

		if !found {
			err = errors.New("x509: unknown SignatureAlgorithm")
		}
	}

	var algoBuilder cryptobyte.Builder
	algoBuilder.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1ObjectIdentifier(algoOID)
		if nullParameters {
			b.AddASN1NULL()
		}
	})

	sigAlgoBytes, err = algoBuilder.Bytes()
	if err != nil {
		return crypto.Hash(0), nil, err
	}

	return
}

// TODO(agl): this is taken from crypto/x509 and so should probably be exported
// from crypto/x509 or crypto/x509/pkix.
func getSignatureAlgorithmFromOID(oid encoding_asn1.ObjectIdentifier) x509.SignatureAlgorithm {
	for _, details := range signatureAlgorithmDetails {
		if oid.Equal(details.oid) {
			return details.algo
		}
	}
	return x509.UnknownSignatureAlgorithm
}

// TODO(rlb): This is not taken from crypto/x509, but it's of the same general form.
func getHashAlgorithmFromOID(target encoding_asn1.ObjectIdentifier) crypto.Hash {
	for hash, oid := range hashOIDs {
		if oid.Equal(target) {
			return hash
		}
	}
	return crypto.Hash(0)
}

func getOIDFromHashAlgorithm(target crypto.Hash) encoding_asn1.ObjectIdentifier {
	for hash, oid := range hashOIDs {
		if hash == target {
			return oid
		}
	}
	return nil
}
