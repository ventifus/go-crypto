// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package ocsp parses OCSP responses as specified in RFC 2560. OCSP responses
// are signed messages attesting to the validity of a certificate for a small
// period of time. This is used to manage revocation for X.509 certificates.
package ocsp

import (
	"crypto"
	"crypto/cryptobyte"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"time"
)

var idPKIXOCSPBasic = asn1.ObjectIdentifier([]int{1, 3, 6, 1, 5, 5, 7, 48, 1, 1})

const asn1ContextSpecific = 0x80
const asn1Constructed = 0x20
const asn1Sequence = asn1.TagSequence | asn1Constructed

// ResponseStatus contains the result of an OCSP request. See
// https://tools.ietf.org/html/rfc6960#section-2.3
type ResponseStatus int

const (
	Success       ResponseStatus = 0
	Malformed     ResponseStatus = 1
	InternalError ResponseStatus = 2
	TryLater      ResponseStatus = 3
	// Status code four is unused in OCSP. See
	// https://tools.ietf.org/html/rfc6960#section-4.2.1
	SignatureRequired ResponseStatus = 5
	Unauthorized      ResponseStatus = 6
)

func (r ResponseStatus) String() string {
	switch r {
	case Success:
		return "success"
	case Malformed:
		return "malformed"
	case InternalError:
		return "internal error"
	case TryLater:
		return "try later"
	case SignatureRequired:
		return "signature required"
	case Unauthorized:
		return "unauthorized"
	default:
		return "unknown OCSP status: " + strconv.Itoa(int(r))
	}
}

// ResponseError is an error that may be returned by ParseResponse to indicate
// that the response itself is an error, not just that its indicating that a
// certificate is revoked, unknown, etc.
type ResponseError struct {
	Status ResponseStatus
}

func (r ResponseError) Error() string {
	return "ocsp: error from server: " + r.Status.String()
}

// These are internal structures that reflect the ASN.1 structure of an OCSP
// response. See RFC 2560, section 4.2.

/*
   CertID          ::=     SEQUENCE {
       hashAlgorithm       AlgorithmIdentifier,
       issuerNameHash      OCTET STRING, -- Hash of Issuer's DN
       issuerKeyHash       OCTET STRING, -- Hash of Issuers public key
       serialNumber        CertificateSerialNumber }
*/
type certID struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	NameHash      []byte
	IssuerKeyHash []byte
	SerialNumber  *big.Int
}

func (c *certID) unmarshal(b *cryptobyte.String) bool {
	var cert cryptobyte.String
	c.SerialNumber = new(big.Int)
	if !b.ReadASN1(&cert, asn1Sequence) ||
		!readAlgorithmIdentifier(&cert, &c.HashAlgorithm) ||
		!cert.ReadASN1((*cryptobyte.String)(&c.NameHash), asn1.TagOctetString) ||
		!cert.ReadASN1((*cryptobyte.String)(&c.IssuerKeyHash), asn1.TagOctetString) ||
		!cert.ReadASN1Integer(c.SerialNumber) ||
		!cert.Empty() {
		return false
	}
	return true
}

func (c *certID) Marshal(b *cryptobyte.Builder) error {
	// TODO(martinkr): Make pkix use cryptobyte.
	b.AddASN1(asn1Sequence, func(cert *cryptobyte.Builder) {
		cert.MarshalASN1(c.HashAlgorithm)
		cert.AddASN1(asn1.TagOctetString, func(nameHash *cryptobyte.Builder) {
			nameHash.AddBytes(c.NameHash)
		})
		cert.AddASN1(asn1.TagOctetString, func(keyHash *cryptobyte.Builder) {
			keyHash.AddBytes(c.IssuerKeyHash)
		})
		cert.AddASN1BigInt(c.SerialNumber)
	})
	return nil
}

/*
   OCSPRequest     ::=     SEQUENCE {
       tbsRequest                  TBSRequest,
       optionalSignature   [0]     EXPLICIT Signature OPTIONAL }
*/
type ocspRequest struct {
	TBSRequest tbsRequest
}

func (r *ocspRequest) unmarshal(b *cryptobyte.String) bool {
	var ocsp, sigIgnored cryptobyte.String
	if !b.ReadASN1(&ocsp, asn1Sequence) ||
		!r.TBSRequest.unmarshal(&ocsp) ||
		!ocsp.ReadOptionalASN1(&sigIgnored, nil /* present */, asn1Constructed|asn1ContextSpecific|0) ||
		!ocsp.Empty() {
		return false
	}
	return true
}

func (r *ocspRequest) Marshal(b *cryptobyte.Builder) error {
	b.AddASN1(asn1Sequence, func(ocsp *cryptobyte.Builder) {
		ocsp.AddValue(&r.TBSRequest)
	})
	return nil
}

/*
   TBSRequest      ::=     SEQUENCE {
       version             [0]     EXPLICIT Version DEFAULT v1,
       requestorName       [1]     EXPLICIT GeneralName OPTIONAL,
       requestList                 SEQUENCE OF Request,
       requestExtensions   [2]     EXPLICIT Extensions OPTIONAL }
*/
type tbsRequest struct {
	Version       int              `asn1:"explicit,tag:0,default:0,optional"`
	RequestorName pkix.RDNSequence `asn1:"explicit,tag:1,optional"`
	RequestList   []request
}

func (r *tbsRequest) unmarshal(b *cryptobyte.String) bool {
	var tbs, requestorName, requestList, ignoredExtensions cryptobyte.String
	var reqNamePresent bool
	if !b.ReadASN1(&tbs, asn1Sequence) ||
		!tbs.ReadOptionalASN1Integer(&r.Version, asn1Constructed|asn1ContextSpecific|0, 0) ||
		!tbs.ReadOptionalASN1(&requestorName, &reqNamePresent, asn1Constructed|asn1ContextSpecific|1) ||
		!tbs.ReadASN1(&requestList, asn1Sequence) ||
		!tbs.ReadOptionalASN1(&ignoredExtensions, nil /* present */, asn1Constructed|asn1ContextSpecific|2) ||
		!tbs.Empty() {
		return false
	}

	if reqNamePresent {
		// TODO(martinkr): Make pkix use cryptobyte.
		if rest, err := asn1.Unmarshal(requestorName, &r.RequestorName); err != nil || len(rest) > 0 {
			return false
		}
	}

	// TODO(martinkr): Can we handle SEQUENCE OF better?
	for !requestList.Empty() {
		var req request
		if !req.unmarshal(&requestList) {
			return false
		}
		r.RequestList = append(r.RequestList, req)
	}

	return true
}

func (r *tbsRequest) Marshal(b *cryptobyte.Builder) error {
	b.AddASN1(asn1Sequence, func(tbs *cryptobyte.Builder) {
		if r.Version != 0 {
			tbs.AddASN1(asn1ContextSpecific|asn1Constructed|0, func(version *cryptobyte.Builder) {
				version.AddASN1Int64(int64(r.Version))
			})
		}
		if len(r.RequestorName) > 0 {
			tbs.AddASN1(asn1ContextSpecific|asn1Constructed|1, func(requestor *cryptobyte.Builder) {
				requestor.MarshalASN1(&r.RequestorName)
			})
		}
		tbs.AddASN1(asn1Sequence, func(requestList *cryptobyte.Builder) {
			for _, req := range r.RequestList {
				requestList.AddValue(&req)
			}
		})
	})
	return nil
}

/*
   Request         ::=     SEQUENCE {
       reqCert                     CertID,
       singleRequestExtensions     [0] EXPLICIT Extensions OPTIONAL }
*/
type request struct {
	Cert certID
}

func (r *request) unmarshal(b *cryptobyte.String) bool {
	var cert, extIgnored cryptobyte.String
	if !b.ReadASN1(&cert, asn1Sequence) ||
		!r.Cert.unmarshal(&cert) ||
		!cert.ReadOptionalASN1(&extIgnored, nil /* present */, asn1Constructed|asn1ContextSpecific|0) ||
		!cert.Empty() {
		return false
	}
	return true
}

func (r *request) Marshal(b *cryptobyte.Builder) error {
	b.AddASN1(asn1Sequence, func(req *cryptobyte.Builder) {
		req.AddValue(&r.Cert)
	})
	return nil
}

/*
   OCSPResponse ::= SEQUENCE {
      responseStatus         OCSPResponseStatus,
      responseBytes          [0] EXPLICIT ResponseBytes OPTIONAL }
*/
type responseASN1 struct {
	Status   asn1.Enumerated // TODO(martinkr): change into ResponseStatus
	Response responseBytes   `asn1:"explicit,tag:0,optional"`
}

func (r *responseASN1) unmarshal(b *cryptobyte.String) bool {
	var ocsp, respBytes cryptobyte.String
	var respPresent bool
	if !b.ReadASN1(&ocsp, asn1Sequence) ||
		!ocsp.ReadASN1Enum((*int)(&r.Status)) ||
		!ocsp.ReadOptionalASN1(&respBytes, &respPresent, asn1Constructed|asn1ContextSpecific|0) ||
		(respPresent && !r.Response.unmarshal(&respBytes)) ||
		!respBytes.Empty() ||
		!ocsp.Empty() {
		return false
	}
	return true
}

func (r *responseASN1) Marshal(b *cryptobyte.Builder) error {
	b.AddASN1(asn1Sequence, func(ocsp *cryptobyte.Builder) {
		ocsp.AddASN1Enum(int64(r.Status))
		if len(r.Response.Response) > 0 {
			ocsp.AddASN1(asn1ContextSpecific|asn1Constructed|0, func(resp *cryptobyte.Builder) {
				resp.AddValue(&r.Response)
			})
		}
	})
	return nil
}

/*
   ResponseBytes ::=       SEQUENCE {
       responseType   OBJECT IDENTIFIER,
       response       OCTET STRING }
*/
type responseBytes struct {
	ResponseType asn1.ObjectIdentifier
	Response     []byte
}

func (r *responseBytes) unmarshal(b *cryptobyte.String) bool {
	var resp cryptobyte.String
	if !b.ReadASN1(&resp, asn1Sequence) ||
		!resp.ReadASN1ObjectIdentifier(&r.ResponseType) ||
		!resp.ReadASN1((*cryptobyte.String)(&r.Response), asn1.TagOctetString) ||
		!resp.Empty() {
		return false
	}
	return true
}

func (r *responseBytes) Marshal(b *cryptobyte.Builder) error {
	b.AddASN1(asn1Sequence, func(resp *cryptobyte.Builder) {
		resp.MarshalASN1(r.ResponseType)
		resp.AddASN1OctetString(r.Response)
	})
	return nil
}

/*
   BasicOCSPResponse       ::= SEQUENCE {
      tbsResponseData      ResponseData,
      signatureAlgorithm   AlgorithmIdentifier,
      signature            BIT STRING,
      certs                [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }
*/
type basicResponse struct {
	TBSResponseData    responseData
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          asn1.BitString
	Certificates       []asn1.RawValue `asn1:"explicit,tag:0,optional"`
}

func (r *basicResponse) unmarshal(b *cryptobyte.String) bool {
	var resp, certs cryptobyte.String
	var certsPresent bool
	if !b.ReadASN1(&resp, asn1Sequence) ||
		!r.TBSResponseData.unmarshal(&resp) ||
		!readAlgorithmIdentifier(&resp, &r.SignatureAlgorithm) ||
		!resp.ReadASN1BitString(&r.Signature) ||
		!resp.ReadOptionalASN1(&certs, &certsPresent, asn1Constructed|asn1ContextSpecific|0) ||
		!resp.Empty() {
		return false
	}
	if certsPresent {
		// TODO(martinkr): Add ReadASN1RawValue?
		if rest, err := asn1.Unmarshal(certs, &r.Certificates); err != nil || len(rest) > 0 {
			return false
		}
	}
	return true
}

func (r *basicResponse) Marshal(b *cryptobyte.Builder) error {
	b.AddASN1(asn1Sequence, func(resp *cryptobyte.Builder) {
		resp.AddValue(&r.TBSResponseData)
		resp.MarshalASN1(r.SignatureAlgorithm)
		resp.AddASN1BitString(r.Signature)
		if len(r.Certificates) > 0 {
			resp.AddASN1(asn1ContextSpecific|asn1Constructed|0, func(certs *cryptobyte.Builder) {
				certs.MarshalASN1(r.Certificates)
			})
		}
	})
	return nil
}

/*
   ResponseData ::= SEQUENCE {
      version              [0] EXPLICIT Version DEFAULT v1,
      responderID              ResponderID,
      producedAt               GeneralizedTime,
      responses                SEQUENCE OF SingleResponse,
      responseExtensions   [1] EXPLICIT Extensions OPTIONAL }
*/
type responseData struct {
	Raw     asn1.RawContent
	Version int `asn1:"optional,default:0,explicit,tag:0"`
	// TODO(martinkr): Flatten this CHOICE.
	RawResponderID asn1.RawValue
	ProducedAt     time.Time `asn1:"generalized"`
	Responses      []singleResponse
}

func (r *responseData) unmarshal(b *cryptobyte.String) bool {
	var raw, resp, responderID, responses, extIgnored cryptobyte.String
	if !b.ReadASN1Element(&raw, asn1Sequence) {
		return false
	}
	r.Raw = []byte(raw)
	if !raw.ReadASN1(&resp, asn1Sequence) || !raw.Empty() ||
		!resp.ReadOptionalASN1Integer(&r.Version, asn1Constructed|asn1ContextSpecific|0, 0) ||
		!resp.ReadAnyASN1Element(&responderID, nil /* tag */) ||
		!resp.ReadASN1GeneralizedTime(&r.ProducedAt) ||
		!resp.ReadASN1(&responses, asn1Sequence) ||
		!resp.ReadOptionalASN1(&extIgnored, nil, asn1Constructed|asn1ContextSpecific|1) ||
		!resp.Empty() {
		return false
	}
	// TODO(martinkr): Add ReadASN1RawValue?
	if rest, err := asn1.Unmarshal(responderID, &r.RawResponderID); err != nil || len(rest) > 0 {
		return false
	}
	for !responses.Empty() {
		var sr singleResponse
		if !sr.unmarshal(&responses) {
			return false
		}
		r.Responses = append(r.Responses, sr)
	}
	return true
}

func (r *responseData) Marshal(b *cryptobyte.Builder) error {
	b.AddASN1(asn1Sequence, func(resp *cryptobyte.Builder) {
		if r.Version != 0 {
			resp.AddASN1(asn1ContextSpecific|asn1Constructed|0, func(version *cryptobyte.Builder) {
				version.AddASN1Int64(int64(r.Version))
			})
		}
		resp.MarshalASN1(r.RawResponderID) // N.B. RawValue.FullBytes may not be set.
		resp.AddASN1GeneralizedTime(r.ProducedAt)
		resp.AddASN1(asn1Sequence, func(responses *cryptobyte.Builder) {
			for _, resp := range r.Responses {
				responses.AddValue(&resp)
			}
		})
	})
	return nil
}

/*
   SingleResponse ::= SEQUENCE {
      certID                       CertID,
      certStatus                   CertStatus,
      thisUpdate                   GeneralizedTime,
      nextUpdate         [0]       EXPLICIT GeneralizedTime OPTIONAL,
      singleExtensions   [1]       EXPLICIT Extensions OPTIONAL }
*/
type singleResponse struct {
	CertID           certID
	Good             asn1.Flag        `asn1:"tag:0,optional"`
	Revoked          revokedInfo      `asn1:"tag:1,optional"`
	Unknown          asn1.Flag        `asn1:"tag:2,optional"`
	ThisUpdate       time.Time        `asn1:"generalized"`
	NextUpdate       time.Time        `asn1:"generalized,explicit,tag:0,optional"`
	SingleExtensions []pkix.Extension `asn1:"explicit,tag:1,optional"`
}

func (r *singleResponse) unmarshal(b *cryptobyte.String) bool {
	var resp, certID, nextUpdate, ext cryptobyte.String
	var nextUpdatePresent, extPresent bool
	if !b.ReadASN1(&resp, asn1Sequence) ||
		!resp.ReadASN1Element(&certID, asn1Sequence) ||
		!r.CertID.unmarshal(&certID) ||
		!certID.Empty() ||
		!r.unmarshalCertStatusChoice(&resp) ||
		!resp.ReadASN1GeneralizedTime(&r.ThisUpdate) ||
		!resp.ReadOptionalASN1(&nextUpdate, &nextUpdatePresent, asn1Constructed|asn1ContextSpecific|0) ||
		(nextUpdatePresent && !nextUpdate.ReadASN1GeneralizedTime(&r.NextUpdate)) ||
		!nextUpdate.Empty() ||
		!resp.ReadOptionalASN1(&ext, &extPresent, asn1Constructed|asn1ContextSpecific|1) ||
		!resp.Empty() {
		return false
	}
	if extPresent {
		// TODO(martinkr): Make pkix use cryptobyte.
		if rest, err := asn1.Unmarshal(ext, &r.SingleExtensions); err != nil || len(rest) > 0 {
			return false
		}
	}
	return true
}

/*
   CertStatus ::= CHOICE {
       good        [0]     IMPLICIT NULL,
       revoked     [1]     IMPLICIT RevokedInfo,
       unknown     [2]     IMPLICIT UnknownInfo }
*/
func (r *singleResponse) unmarshalCertStatusChoice(b *cryptobyte.String) bool {
	const (
		goodTag    = 0 | asn1ContextSpecific
		revokedTag = 1 | asn1ContextSpecific | asn1Constructed
		unknownTag = 2 | asn1ContextSpecific
	)
	var status cryptobyte.String
	var tag uint8
	if !b.ReadAnyASN1(&status, &tag) {
		return false
	}
	switch tag {
	case goodTag:
		if !status.Empty() {
			return false
		}
		r.Good = true
	case revokedTag:
		// TODO(martinkr): N.B. the IMPLICIT tag has already been stripped. Figure
		// out how unmarshal should handle leading tags.
		if !r.Revoked.unmarshal(&status) || !status.Empty() {
			return false
		}
	case unknownTag:
		if !status.Empty() {
			return false
		}
		r.Unknown = true
	default:
		return false
	}
	return true
}

func (r *singleResponse) Marshal(b *cryptobyte.Builder) error {
	const (
		goodTag    = 0 | asn1ContextSpecific
		revokedTag = 1 | asn1ContextSpecific | asn1Constructed
		unknownTag = 2 | asn1ContextSpecific
	)
	b.AddASN1(asn1Sequence, func(resp *cryptobyte.Builder) {
		resp.AddValue(&r.CertID)
		// CertStatus CHOICE
		if r.Good {
			resp.AddBytes([]byte{goodTag})
		} else if (r.Revoked != revokedInfo{}) {
			resp.AddASN1(revokedTag, func(revoked *cryptobyte.Builder) {
				revoked.AddValue(&r.Revoked) // N.B. Revoked.Marshal strips the tag.
			})
		} else if r.Unknown {
			resp.AddBytes([]byte{unknownTag})
		}

		resp.AddASN1GeneralizedTime(r.ThisUpdate)
		if (r.NextUpdate != time.Time{}) {
			resp.AddASN1(asn1ContextSpecific|asn1Constructed|0, func(nextUpdate *cryptobyte.Builder) {
				nextUpdate.AddASN1GeneralizedTime(r.NextUpdate)
			})
		}

		if len(r.SingleExtensions) > 0 {
			resp.AddASN1(asn1ContextSpecific|asn1Constructed|1, func(ext *cryptobyte.Builder) {
				ext.MarshalASN1(r.SingleExtensions)
			})
		}
	})
	return nil
}

type revokedInfo struct {
	RevocationTime time.Time       `asn1:"generalized"`
	Reason         asn1.Enumerated `asn1:"explicit,tag:0,optional"`
}

/*
   RevokedInfo ::= SEQUENCE {
       revocationTime              GeneralizedTime,
       revocationReason    [0]     EXPLICIT CRLReason OPTIONAL }
*/
func (r *revokedInfo) unmarshal(b *cryptobyte.String) bool {
	var reason cryptobyte.String
	var reasonPresent bool
	// N.B. the leading tag has already been stripped because it was IMPLICIT.
	if !b.ReadASN1GeneralizedTime(&r.RevocationTime) ||
		!b.ReadOptionalASN1(&reason, &reasonPresent, asn1Constructed|asn1ContextSpecific|0) ||
		(reasonPresent && !reason.ReadASN1Enum((*int)(&r.Reason))) {
		return false
	}
	return true
}

func (r *revokedInfo) Marshal(b *cryptobyte.Builder) error {
	// N.B. the sequence tag is omitted because RevokedInfo occurs implicit.
	b.AddASN1GeneralizedTime(r.RevocationTime)
	if r.Reason != 0 {
		b.AddASN1(asn1ContextSpecific|asn1Constructed|0, func(reason *cryptobyte.Builder) {
			reason.AddASN1Enum(int64(r.Reason))
		})
	}
	return nil
}

var (
	oidSignatureMD2WithRSA      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 2}
	oidSignatureMD5WithRSA      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 4}
	oidSignatureSHA1WithRSA     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
	oidSignatureSHA256WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSignatureSHA384WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidSignatureSHA512WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	oidSignatureDSAWithSHA1     = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 3}
	oidSignatureDSAWithSHA256   = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 2}
	oidSignatureECDSAWithSHA1   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 1}
	oidSignatureECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidSignatureECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidSignatureECDSAWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
)

var hashOIDs = map[crypto.Hash]asn1.ObjectIdentifier{
	crypto.SHA1:   asn1.ObjectIdentifier([]int{1, 3, 14, 3, 2, 26}),
	crypto.SHA256: asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 2, 1}),
	crypto.SHA384: asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 2, 2}),
	crypto.SHA512: asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 2, 3}),
}

// TODO(rlb): This is also from crypto/x509, so same comment as AGL's below
var signatureAlgorithmDetails = []struct {
	algo       x509.SignatureAlgorithm
	oid        asn1.ObjectIdentifier
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
func signingParamsForPublicKey(pub interface{}, requestedSigAlgo x509.SignatureAlgorithm) (hashFunc crypto.Hash, sigAlgo pkix.AlgorithmIdentifier, err error) {
	var pubType x509.PublicKeyAlgorithm

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		pubType = x509.RSA
		hashFunc = crypto.SHA256
		sigAlgo.Algorithm = oidSignatureSHA256WithRSA
		sigAlgo.Parameters = asn1.RawValue{
			Tag: 5,
		}

	case *ecdsa.PublicKey:
		pubType = x509.ECDSA

		switch pub.Curve {
		case elliptic.P224(), elliptic.P256():
			hashFunc = crypto.SHA256
			sigAlgo.Algorithm = oidSignatureECDSAWithSHA256
		case elliptic.P384():
			hashFunc = crypto.SHA384
			sigAlgo.Algorithm = oidSignatureECDSAWithSHA384
		case elliptic.P521():
			hashFunc = crypto.SHA512
			sigAlgo.Algorithm = oidSignatureECDSAWithSHA512
		default:
			err = errors.New("x509: unknown elliptic curve")
		}

	default:
		err = errors.New("x509: only RSA and ECDSA keys supported")
	}

	if err != nil {
		return
	}

	if requestedSigAlgo == 0 {
		return
	}

	found := false
	for _, details := range signatureAlgorithmDetails {
		if details.algo == requestedSigAlgo {
			if details.pubKeyAlgo != pubType {
				err = errors.New("x509: requested SignatureAlgorithm does not match private key type")
				return
			}
			sigAlgo.Algorithm, hashFunc = details.oid, details.hash
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

	return
}

// TODO(agl): this is taken from crypto/x509 and so should probably be exported
// from crypto/x509 or crypto/x509/pkix.
func getSignatureAlgorithmFromOID(oid asn1.ObjectIdentifier) x509.SignatureAlgorithm {
	for _, details := range signatureAlgorithmDetails {
		if oid.Equal(details.oid) {
			return details.algo
		}
	}
	return x509.UnknownSignatureAlgorithm
}

// TODO(rlb): This is not taken from crypto/x509, but it's of the same general form.
func getHashAlgorithmFromOID(target asn1.ObjectIdentifier) crypto.Hash {
	for hash, oid := range hashOIDs {
		if oid.Equal(target) {
			return hash
		}
	}
	return crypto.Hash(0)
}

func getOIDFromHashAlgorithm(target crypto.Hash) asn1.ObjectIdentifier {
	for hash, oid := range hashOIDs {
		if hash == target {
			return oid
		}
	}
	return nil
}

// This is the exposed reflection of the internal OCSP structures.

// The status values that can be expressed in OCSP.  See RFC 6960.
const (
	// Good means that the certificate is valid.
	Good = iota
	// Revoked means that the certificate has been deliberately revoked.
	Revoked
	// Unknown means that the OCSP responder doesn't know about the certificate.
	Unknown
	// ServerFailed is unused and was never used (see
	// https://go-review.googlesource.com/#/c/18944). ParseResponse will
	// return a ResponseError when an error response is parsed.
	ServerFailed
)

// The enumerated reasons for revoking a certificate.  See RFC 5280.
const (
	Unspecified          = iota
	KeyCompromise        = iota
	CACompromise         = iota
	AffiliationChanged   = iota
	Superseded           = iota
	CessationOfOperation = iota
	CertificateHold      = iota
	_                    = iota
	RemoveFromCRL        = iota
	PrivilegeWithdrawn   = iota
	AACompromise         = iota
)

// Request represents an OCSP request. See RFC 6960.
type Request struct {
	HashAlgorithm  crypto.Hash
	IssuerNameHash []byte
	IssuerKeyHash  []byte
	SerialNumber   *big.Int
}

// Marshal marshals the OCSP request to ASN.1 DER encoded form.
func (req *Request) Marshal() ([]byte, error) {
	hashAlg := getOIDFromHashAlgorithm(req.HashAlgorithm)
	if hashAlg == nil {
		return nil, errors.New("Unknown hash algorithm")
	}
	var b cryptobyte.Builder
	b.AddValue(&ocspRequest{
		tbsRequest{
			Version: 0,
			RequestList: []request{
				{
					Cert: certID{
						pkix.AlgorithmIdentifier{
							Algorithm:  hashAlg,
							Parameters: asn1.RawValue{Tag: 5 /* ASN.1 NULL */},
						},
						req.IssuerNameHash,
						req.IssuerKeyHash,
						req.SerialNumber,
					},
				},
			},
		},
	})
	return b.Bytes()
}

// Response represents an OCSP response containing a single SingleResponse. See
// RFC 6960.
type Response struct {
	// Status is one of {Good, Revoked, Unknown}
	Status                                        int
	SerialNumber                                  *big.Int
	ProducedAt, ThisUpdate, NextUpdate, RevokedAt time.Time
	RevocationReason                              int
	Certificate                                   *x509.Certificate
	// TBSResponseData contains the raw bytes of the signed response. If
	// Certificate is nil then this can be used to verify Signature.
	TBSResponseData    []byte
	Signature          []byte
	SignatureAlgorithm x509.SignatureAlgorithm

	// IssuerHash is the hash used to compute the IssuerNameHash and IssuerKeyHash.
	// Valid values are crypto.SHA1, crypto.SHA256, crypto.SHA384, and crypto.SHA512.
	// If zero, the default is crypto.SHA1.
	IssuerHash crypto.Hash

	// RawResponderName optionally contains the DER-encoded subject of the
	// responder certificate. Exactly one of RawResponderName and
	// ResponderKeyHash is set.
	RawResponderName []byte
	// ResponderKeyHash optionally contains the SHA-1 hash of the
	// responder's public key. Exactly one of RawResponderName and
	// ResponderKeyHash is set.
	ResponderKeyHash []byte

	// Extensions contains raw X.509 extensions from the singleExtensions field
	// of the OCSP response. When parsing certificates, this can be used to
	// extract non-critical extensions that are not parsed by this package. When
	// marshaling OCSP responses, the Extensions field is ignored, see
	// ExtraExtensions.
	Extensions []pkix.Extension

	// ExtraExtensions contains extensions to be copied, raw, into any marshaled
	// OCSP response (in the singleExtensions field). Values override any
	// extensions that would otherwise be produced based on the other fields. The
	// ExtraExtensions field is not populated when parsing certificates, see
	// Extensions.
	ExtraExtensions []pkix.Extension
}

// These are pre-serialized error responses for the various non-success codes
// defined by OCSP. The Unauthorized code in particular can be used by an OCSP
// responder that supports only pre-signed responses as a response to requests
// for certificates with unknown status. See RFC 5019.
var (
	MalformedRequestErrorResponse = []byte{0x30, 0x03, 0x0A, 0x01, 0x01}
	InternalErrorErrorResponse    = []byte{0x30, 0x03, 0x0A, 0x01, 0x02}
	TryLaterErrorResponse         = []byte{0x30, 0x03, 0x0A, 0x01, 0x03}
	SigRequredErrorResponse       = []byte{0x30, 0x03, 0x0A, 0x01, 0x05}
	UnauthorizedErrorResponse     = []byte{0x30, 0x03, 0x0A, 0x01, 0x06}
)

// CheckSignatureFrom checks that the signature in resp is a valid signature
// from issuer. This should only be used if resp.Certificate is nil. Otherwise,
// the OCSP response contained an intermediate certificate that created the
// signature. That signature is checked by ParseResponse and only
// resp.Certificate remains to be validated.
func (resp *Response) CheckSignatureFrom(issuer *x509.Certificate) error {
	return issuer.CheckSignature(resp.SignatureAlgorithm, resp.TBSResponseData, resp.Signature)
}

// ParseError results from an invalid OCSP response.
type ParseError string

func (p ParseError) Error() string {
	return string(p)
}

// ParseRequest parses an OCSP request in DER form. It only supports
// requests for a single certificate. Signed requests are not supported.
// If a request includes a signature, it will result in a ParseError.
func ParseRequest(bytes []byte) (*Request, error) {
	var req ocspRequest
	s := cryptobyte.String(bytes)
	if !req.unmarshal(&s) {
		return nil, ParseError("failed to parse OCSP request")
	}
	if !s.Empty() {
		return nil, ParseError("trailing data in OCSP request")
	}

	if len(req.TBSRequest.RequestList) == 0 {
		return nil, ParseError("OCSP request contains no request body")
	}
	innerRequest := req.TBSRequest.RequestList[0]

	hashFunc := getHashAlgorithmFromOID(innerRequest.Cert.HashAlgorithm.Algorithm)
	if hashFunc == crypto.Hash(0) {
		return nil, ParseError("OCSP request uses unknown hash function")
	}

	return &Request{
		HashAlgorithm:  hashFunc,
		IssuerNameHash: innerRequest.Cert.NameHash,
		IssuerKeyHash:  innerRequest.Cert.IssuerKeyHash,
		SerialNumber:   innerRequest.Cert.SerialNumber,
	}, nil
}

// ParseResponse parses an OCSP response in DER form. It only supports
// responses for a single certificate. If the response contains a certificate
// then the signature over the response is checked. If issuer is not nil then
// it will be used to validate the signature or embedded certificate.
//
// Invalid signatures or parse failures will result in a ParseError. Error
// responses will result in a ResponseError.
func ParseResponse(bytes []byte, issuer *x509.Certificate) (*Response, error) {
	return ParseResponseForCert(bytes, nil, issuer)
}

// ParseResponseForCert parses an OCSP response in DER form and searches for a
// Response relating to cert. If such a Response is found and the OCSP response
// contains a certificate then the signature over the response is checked. If
// issuer is not nil then it will be used to validate the signature or embedded
// certificate.
//
// Invalid signatures or parse failures will result in a ParseError. Error
// responses will result in a ResponseError.
func ParseResponseForCert(bytes []byte, cert, issuer *x509.Certificate) (*Response, error) {
	b := cryptobyte.String(bytes)
	var resp responseASN1
	if !resp.unmarshal(&b) {
		return nil, ParseError("failed to parse OCSP response")
	}
	if !b.Empty() {
		return nil, ParseError("trailing data in OCSP response")
	}

	if status := ResponseStatus(resp.Status); status != Success {
		return nil, ResponseError{status}
	}

	if !resp.Response.ResponseType.Equal(idPKIXOCSPBasic) {
		return nil, ParseError("bad OCSP response type")
	}

	var basicResp basicResponse
	basicRespBytes := cryptobyte.String(resp.Response.Response)
	if !basicResp.unmarshal(&basicRespBytes) {
		return nil, ParseError("failed to parse OCSP response")
	}
	if !basicRespBytes.Empty() {
		return nil, ParseError("OCSP response has trailing bytes")
	}

	if len(basicResp.Certificates) > 1 {
		return nil, ParseError("OCSP response contains bad number of certificates")
	}

	if n := len(basicResp.TBSResponseData.Responses); n == 0 || cert == nil && n > 1 {
		return nil, ParseError("OCSP response contains bad number of responses")
	}

	ret := &Response{
		TBSResponseData:    basicResp.TBSResponseData.Raw,
		Signature:          basicResp.Signature.RightAlign(),
		SignatureAlgorithm: getSignatureAlgorithmFromOID(basicResp.SignatureAlgorithm.Algorithm),
	}

	// Handle the ResponderID CHOICE tag. ResponderID can be flattened into
	// TBSResponseData once https://go-review.googlesource.com/34503 has been
	// released.
	rawResponderID := basicResp.TBSResponseData.RawResponderID
	switch rawResponderID.Tag {
	case 1: // Name
		var rdn pkix.RDNSequence
		// TODO(martinkr): Make pkix use cryptobyte.
		if rest, err := asn1.Unmarshal(rawResponderID.Bytes, &rdn); err != nil || len(rest) != 0 {
			return nil, ParseError("invalid responder name")
		}
		ret.RawResponderName = rawResponderID.Bytes
	case 2: // KeyHash
		keyHash := cryptobyte.String(rawResponderID.Bytes)
		if !keyHash.ReadASN1((*cryptobyte.String)(&ret.ResponderKeyHash), asn1.TagOctetString) ||
			!keyHash.Empty() {
			return nil, ParseError("invalid responder key hash")
		}
	default:
		return nil, ParseError("invalid responder id tag")
	}

	var err error
	if len(basicResp.Certificates) > 0 {
		ret.Certificate, err = x509.ParseCertificate(basicResp.Certificates[0].FullBytes)
		if err != nil {
			return nil, err
		}

		if err := ret.CheckSignatureFrom(ret.Certificate); err != nil {
			return nil, ParseError("bad signature on embedded certificate: " + err.Error())
		}

		if issuer != nil {
			if err := issuer.CheckSignature(ret.Certificate.SignatureAlgorithm, ret.Certificate.RawTBSCertificate, ret.Certificate.Signature); err != nil {
				return nil, ParseError("bad OCSP signature: " + err.Error())
			}
		}
	} else if issuer != nil {
		if err := ret.CheckSignatureFrom(issuer); err != nil {
			return nil, ParseError("bad OCSP signature: " + err.Error())
		}
	}

	var r singleResponse
	for _, resp := range basicResp.TBSResponseData.Responses {
		if cert == nil || cert.SerialNumber.Cmp(resp.CertID.SerialNumber) == 0 {
			r = resp
			break
		}
	}

	for _, ext := range r.SingleExtensions {
		if ext.Critical {
			return nil, ParseError("unsupported critical extension")
		}
	}
	ret.Extensions = r.SingleExtensions

	ret.SerialNumber = r.CertID.SerialNumber

	for h, oid := range hashOIDs {
		if r.CertID.HashAlgorithm.Algorithm.Equal(oid) {
			ret.IssuerHash = h
			break
		}
	}
	if ret.IssuerHash == 0 {
		return nil, ParseError("unsupported issuer hash algorithm")
	}

	switch {
	case bool(r.Good):
		ret.Status = Good
	case bool(r.Unknown):
		ret.Status = Unknown
	default:
		ret.Status = Revoked
		ret.RevokedAt = r.Revoked.RevocationTime
		ret.RevocationReason = int(r.Revoked.Reason)
	}

	ret.ProducedAt = basicResp.TBSResponseData.ProducedAt
	ret.ThisUpdate = r.ThisUpdate
	ret.NextUpdate = r.NextUpdate

	return ret, nil
}

// RequestOptions contains options for constructing OCSP requests.
type RequestOptions struct {
	// Hash contains the hash function that should be used when
	// constructing the OCSP request. If zero, SHA-1 will be used.
	Hash crypto.Hash
}

func (opts *RequestOptions) hash() crypto.Hash {
	if opts == nil || opts.Hash == 0 {
		// SHA-1 is nearly universally used in OCSP.
		return crypto.SHA1
	}
	return opts.Hash
}

type subjectPublicKeyInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

func (s *subjectPublicKeyInfo) unmarshal(b *cryptobyte.String) bool {
	var spki cryptobyte.String
	if !b.ReadASN1(&spki, asn1Sequence) ||
		!readAlgorithmIdentifier(&spki, &s.Algorithm) ||
		!spki.ReadASN1BitString(&s.PublicKey) ||
		!spki.Empty() {
		return false
	}
	return true
}

// CreateRequest returns a DER-encoded, OCSP request for the status of cert. If
// opts is nil then sensible defaults are used.
func CreateRequest(cert, issuer *x509.Certificate, opts *RequestOptions) ([]byte, error) {
	hashFunc := opts.hash()

	// OCSP seems to be the only place where these raw hash identifiers are
	// used. I took the following from
	// http://msdn.microsoft.com/en-us/library/ff635603.aspx
	_, ok := hashOIDs[hashFunc]
	if !ok {
		return nil, x509.ErrUnsupportedAlgorithm
	}

	if !hashFunc.Available() {
		return nil, x509.ErrUnsupportedAlgorithm
	}
	h := opts.hash().New()

	rawSPKI := cryptobyte.String(issuer.RawSubjectPublicKeyInfo)
	var spki subjectPublicKeyInfo
	if !spki.unmarshal(&rawSPKI) || !rawSPKI.Empty() {
		return nil, errors.New("failed to parse issuer Certificate SubjectPublicKeyInfo")
	}

	h.Write(spki.PublicKey.RightAlign())
	issuerKeyHash := h.Sum(nil)

	h.Reset()
	h.Write(issuer.RawSubject)
	issuerNameHash := h.Sum(nil)

	req := &Request{
		HashAlgorithm:  hashFunc,
		IssuerNameHash: issuerNameHash,
		IssuerKeyHash:  issuerKeyHash,
		SerialNumber:   cert.SerialNumber,
	}
	return req.Marshal()
}

// CreateResponse returns a DER-encoded OCSP response with the specified contents.
// The fields in the response are populated as follows:
//
// The responder cert is used to populate the responder's name field, and the
// certificate itself is provided alongside the OCSP response signature.
//
// The issuer cert is used to puplate the IssuerNameHash and IssuerKeyHash fields.
//
// The template is used to populate the SerialNumber, RevocationStatus, RevokedAt,
// RevocationReason, ThisUpdate, and NextUpdate fields.
//
// If template.IssuerHash is not set, SHA1 will be used.
//
// The ProducedAt date is automatically set to the current date, to the nearest minute.
func CreateResponse(issuer, responderCert *x509.Certificate, template Response, priv crypto.Signer) ([]byte, error) {
	rawSPKI := cryptobyte.String(issuer.RawSubjectPublicKeyInfo)
	var spki subjectPublicKeyInfo
	if !spki.unmarshal(&rawSPKI) || !rawSPKI.Empty() {
		return nil, errors.New("failed to parse issuer Certificate SubjectPublicKeyInfo")
	}

	if template.IssuerHash == 0 {
		template.IssuerHash = crypto.SHA1
	}
	hashOID := getOIDFromHashAlgorithm(template.IssuerHash)
	if hashOID == nil {
		return nil, errors.New("unsupported issuer hash algorithm")
	}

	if !template.IssuerHash.Available() {
		return nil, fmt.Errorf("issuer hash algorithm %v not linked into binary", template.IssuerHash)
	}
	h := template.IssuerHash.New()
	h.Write(spki.PublicKey.RightAlign())
	issuerKeyHash := h.Sum(nil)

	h.Reset()
	h.Write(issuer.RawSubject)
	issuerNameHash := h.Sum(nil)

	innerResponse := singleResponse{
		CertID: certID{
			HashAlgorithm: pkix.AlgorithmIdentifier{
				Algorithm:  hashOID,
				Parameters: asn1.RawValue{Tag: 5 /* ASN.1 NULL */},
			},
			NameHash:      issuerNameHash,
			IssuerKeyHash: issuerKeyHash,
			SerialNumber:  template.SerialNumber,
		},
		ThisUpdate:       template.ThisUpdate.UTC(),
		NextUpdate:       template.NextUpdate.UTC(),
		SingleExtensions: template.ExtraExtensions,
	}

	switch template.Status {
	case Good:
		innerResponse.Good = true
	case Unknown:
		innerResponse.Unknown = true
	case Revoked:
		innerResponse.Revoked = revokedInfo{
			RevocationTime: template.RevokedAt.UTC(),
			Reason:         asn1.Enumerated(template.RevocationReason),
		}
	}

	rawResponderID := asn1.RawValue{
		Class:      2, // context-specific
		Tag:        1, // Name (explicit tag)
		IsCompound: true,
		Bytes:      responderCert.RawSubject,
	}
	tbsResponseData := responseData{
		Version:        0,
		RawResponderID: rawResponderID,
		ProducedAt:     time.Now().Truncate(time.Minute).UTC(),
		Responses:      []singleResponse{innerResponse},
	}

	var tbsBuilder cryptobyte.Builder
	tbsBuilder.AddValue(&tbsResponseData)
	tbsResponseDataDER, err := tbsBuilder.Bytes()
	if err != nil {
		return nil, err
	}

	hashFunc, signatureAlgorithm, err := signingParamsForPublicKey(priv.Public(), template.SignatureAlgorithm)
	if err != nil {
		return nil, err
	}

	responseHash := hashFunc.New()
	responseHash.Write(tbsResponseDataDER)
	signature, err := priv.Sign(rand.Reader, responseHash.Sum(nil), hashFunc)
	if err != nil {
		return nil, err
	}

	response := basicResponse{
		TBSResponseData:    tbsResponseData,
		SignatureAlgorithm: signatureAlgorithm,
		Signature: asn1.BitString{
			Bytes:     signature,
			BitLength: 8 * len(signature),
		},
	}
	if template.Certificate != nil {
		response.Certificates = []asn1.RawValue{
			asn1.RawValue{FullBytes: template.Certificate.Raw},
		}
	}

	var basicResponseBuilder cryptobyte.Builder
	basicResponseBuilder.AddValue(&response)
	responseDER, err := basicResponseBuilder.Bytes()
	if err != nil {
		return nil, err
	}

	var responseBuilder cryptobyte.Builder
	resp := responseASN1{
		Status: asn1.Enumerated(Success),
		Response: responseBytes{
			ResponseType: idPKIXOCSPBasic,
			Response:     responseDER,
		},
	}
	responseBuilder.AddValue(&resp)
	return responseBuilder.Bytes()
}

func readAlgorithmIdentifier(b *cryptobyte.String, out *pkix.AlgorithmIdentifier) bool {
	var alg cryptobyte.String
	if !b.ReadASN1Element(&alg, asn1Sequence) {
		return false
	}
	// TODO(martinkr): Make pkix use cryptobyte.
	if rest, err := asn1.Unmarshal(alg, out); err != nil || len(rest) != 0 {
		return false
	}
	return true
}
