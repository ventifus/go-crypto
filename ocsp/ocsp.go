// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package ocsp parses OCSP responses as specified in RFC 2560. OCSP responses
// are signed messages attesting to the validity of a certificate for a small
// period of time. This is used to manage revocation for X.509 certificates.
package ocsp

import (
	"bytes"
	"crypto"
	"crypto/rand"
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	encoding_asn1 "encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"time"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

// ParseError results from an invalid OCSP response.
type ParseError string

func (p ParseError) Error() string {
	return string(p)
}

// Request represents an OCSP request. See RFC 6960.
type Request struct {
	HashAlgorithm  crypto.Hash
	IssuerNameHash []byte
	IssuerKeyHash  []byte
	SerialNumber   *big.Int
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

// CreateRequest returns a DER-encoded, OCSP request for the status of cert. If
// opts is nil then sensible defaults are used.
func CreateRequest(cert, issuer *x509.Certificate, opts *RequestOptions) ([]byte, error) {
	certIDBytes, err := marshalCertID(opts.hash(), cert.SerialNumber, issuer)
	if err != nil {
		return nil, err
	}

	var reqBuilder cryptobyte.Builder
	reqBuilder.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
			// See TBSRequest in https://tools.ietf.org/html/rfc6960#section-4.2.1
			b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
				// See Request
				b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
					b.AddBytes(certIDBytes)
				})
			})
		})
	})

	return reqBuilder.Bytes()
}

// ParseRequest parses an OCSP request in DER form. It only supports
// requests for a single certificate. Signed requests are not supported.
// If a request includes a signature, it will result in a ParseError.
func ParseRequest(requestBytes []byte) (*Request, error) {
	req := cryptobyte.String(requestBytes)
	var ocspRequest, tbsRequest, requestList, request cryptobyte.String
	if !req.ReadASN1(&ocspRequest, asn1.SEQUENCE) ||
		!req.Empty() ||
		!ocspRequest.ReadASN1(&tbsRequest, asn1.SEQUENCE) ||
		!ocspRequest.Empty() ||
		// version
		!tbsRequest.SkipOptionalASN1(asn1.Tag(0).ContextSpecific().Constructed()) ||
		// requestorName
		!tbsRequest.SkipOptionalASN1(asn1.Tag(1).ContextSpecific().Constructed()) ||
		!tbsRequest.ReadASN1(&requestList, asn1.SEQUENCE) ||
		!requestList.ReadASN1(&request, asn1.SEQUENCE) {
		return nil, ParseError("failed to parse OCSP request")
	}

	if !requestList.Empty() {
		return nil, ParseError("multiple requests found")
	}

	ret, err := parseCertID(&request)
	if err != nil {
		return nil, err
	}

	return ret, nil
}

func parseCertID(certIDBytes *cryptobyte.String) (*Request, error) {
	ret := &Request{
		SerialNumber: new(big.Int),
	}

	var certID, hashAlgoID cryptobyte.String
	var hashOID encoding_asn1.ObjectIdentifier
	if !certIDBytes.ReadASN1(&certID, asn1.SEQUENCE) ||
		!certID.ReadASN1(&hashAlgoID, asn1.SEQUENCE) ||
		!hashAlgoID.ReadASN1ObjectIdentifier(&hashOID) ||
		!certID.ReadASN1((*cryptobyte.String)(&ret.IssuerNameHash), asn1.OCTET_STRING) ||
		!certID.ReadASN1((*cryptobyte.String)(&ret.IssuerKeyHash), asn1.OCTET_STRING) ||
		!certID.ReadASN1Integer(ret.SerialNumber) ||
		!certID.Empty() {
		return nil, ParseError("failed to parse OCSP CertID")
	}
	ret.HashAlgorithm = getHashAlgorithmFromOID(hashOID)
	if ret.HashAlgorithm == crypto.Hash(0) {
		return nil, ParseError("unknown hash in CertID")
	}
	if !ret.HashAlgorithm.Available() {
		return nil, ParseError("hash " + strconv.Itoa(int(ret.HashAlgorithm)) + " not compiled in")
	}

	return ret, nil
}

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
// that the response itself is an error, not just that it's indicating that a
// certificate is revoked, unknown, etc.
type ResponseError struct {
	Status ResponseStatus
}

func (r ResponseError) Error() string {
	return "ocsp: error from server: " + r.Status.String()
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

// CertStatus ::= CHOICE {
//     good        [0]     IMPLICIT NULL,
//     revoked     [1]     IMPLICIT RevokedInfo,
//     unknown     [2]     IMPLICIT UnknownInfo }
var (
	certStatusGood    = asn1.Tag(0).ContextSpecific()
	certStatusRevoked = asn1.Tag(1).ContextSpecific().Constructed()
	certStatusUnknown = asn1.Tag(2).ContextSpecific()
)

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
	certIDBytes, err := marshalCertID(template.IssuerHash, template.SerialNumber, issuer)
	if err != nil {
		return nil, err
	}

	var tbsBuilder cryptobyte.Builder
	tbsBuilder.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		// See ResponseData in https://tools.ietf.org/html/rfc6960#section-4.2.1.

		// version is left as the default.
		// responderID is byName
		b.AddASN1(asn1.Tag(1).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
			b.AddBytes(responderCert.RawSubject)
		})
		// producedAt
		b.AddASN1GeneralizedTime(time.Now().Truncate(time.Minute).UTC())
		// responses
		b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
				// See SingleResponse in
				// https://tools.ietf.org/html/rfc6960#section-4.2.1.

				b.AddBytes(certIDBytes)

				// certStatus
				switch template.Status {
				case Good:
					b.AddASN1(certStatusGood, nil)
				case Unknown:
					b.AddASN1(certStatusUnknown, nil)
				case Revoked:
					b.AddASN1(certStatusRevoked, func(b *cryptobyte.Builder) {
						b.AddASN1GeneralizedTime(template.RevokedAt.UTC())
						if reason := template.RevocationReason; reason != 0 {
							b.AddASN1(asn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
								b.AddASN1Enum(int64(reason))
							})
						}
					})
				default:
					panic(errors.New("ocsp: unknown value for Status"))
				}

				b.AddASN1GeneralizedTime(template.ThisUpdate.UTC())
				if !template.NextUpdate.IsZero() {
					b.AddASN1(asn1.Tag(0).ContextSpecific().Constructed(), func(nextUpdate *cryptobyte.Builder) {
						nextUpdate.AddASN1GeneralizedTime(template.NextUpdate.UTC())
					})
				}

				if len(template.ExtraExtensions) > 0 {
					b.AddASN1(asn1.Tag(1).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
						b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
							for _, extension := range template.ExtraExtensions {
								b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
									b.AddASN1ObjectIdentifier(extension.Id)
									if extension.Critical {
										b.AddASN1Boolean(true)
									}
									b.AddASN1OctetString(extension.Value)
								})
							}
						})
					})
				}
			})
		})
	})

	tbsResponseDataDER, err := tbsBuilder.Bytes()
	if err != nil {
		return nil, errors.New("ocsp: error building TBSResponse: " + err.Error())
	}

	hashFunc, signatureAlgorithmBytes, err := signingParamsForPublicKey(priv.Public(), template.SignatureAlgorithm)
	if err != nil {
		return nil, err
	}

	if !hashFunc.Available() {
		return nil, fmt.Errorf("ocsp: hash algorithm %v (for signing response) not linked into binary", hashFunc)
	}

	responseHash := hashFunc.New()
	responseHash.Write(tbsResponseDataDER)
	signature, err := priv.Sign(rand.Reader, responseHash.Sum(nil), hashFunc)
	if err != nil {
		return nil, err
	}

	var responseBuilder cryptobyte.Builder
	responseBuilder.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		// See OCSPResponse in https://tools.ietf.org/html/rfc6960#section-4.2.1

		// responseStatus
		b.AddASN1Enum(int64(Success))
		// responseBytes
		b.AddASN1(asn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
			b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
				// See ResponseBytes in https://tools.ietf.org/html/rfc6960#section-4.2.1

				b.AddASN1ObjectIdentifier(idPKIXOCSPBasic)

				b.AddASN1(asn1.OCTET_STRING, func(b *cryptobyte.Builder) {
					// See BasicOCSPResponse in https://tools.ietf.org/html/rfc6960#section-4.2.1
					b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
						b.AddBytes(tbsResponseDataDER)
						b.AddBytes(signatureAlgorithmBytes)
						b.AddASN1BitString(signature)
						if template.Certificate != nil {
							b.AddASN1(asn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
								b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
									b.AddBytes(template.Certificate.Raw)
								})
							})
						}
					})
				})
			})
		})
	})

	return responseBuilder.Bytes()
}

// ParseResponse parses an OCSP response in DER form. It only supports
// responses for a single certificate. If the response contains a certificate
// then the signature over the response is checked. If issuer is not nil then
// it will be used to validate the signature or embedded certificate.
//
// Invalid responses and parse failures will result in a ParseError.
// Error responses will result in a ResponseError.
func ParseResponse(bytes []byte, issuer *x509.Certificate) (*Response, error) {
	return ParseResponseForCert(bytes, nil, issuer)
}

// ParseResponseForCert parses an OCSP response in DER form and searches for a
// Response relating to cert. If such a Response is found and the OCSP response
// contains a certificate then the signature over the response is checked. If
// issuer is not nil then it will be used to validate the signature or embedded
// certificate.
//
// Invalid responses and parse failures will result in a ParseError.
// Error responses will result in a ResponseError.
func ParseResponseForCert(responseDER []byte, cert, issuer *x509.Certificate) (*Response, error) {
	respBytes := cryptobyte.String(responseDER)
	var ocspResponse, responseBytes, responseSeq, basicRespBytes, basicResp, tbsResponse, certsSeq, sigAlgoID cryptobyte.String
	var status ResponseStatus
	if !respBytes.ReadASN1(&ocspResponse, asn1.SEQUENCE) ||
		!respBytes.Empty() ||
		!ocspResponse.ReadASN1Enum((*int)(&status)) ||
		(status != Success && !ocspResponse.Empty()) {
		return nil, ParseError("failed to parse OCSP response")
	}

	if status != Success {
		return nil, ResponseError{status}
	}

	ret := new(Response)
	var respType, sigAlgoOID encoding_asn1.ObjectIdentifier
	var certsPresent bool
	if !ocspResponse.ReadASN1(&responseBytes, asn1.Tag(0).ContextSpecific().Constructed()) ||
		!ocspResponse.Empty() ||
		!responseBytes.ReadASN1(&responseSeq, asn1.SEQUENCE) ||
		!responseBytes.Empty() ||
		!responseSeq.ReadASN1ObjectIdentifier(&respType) ||
		!respType.Equal(idPKIXOCSPBasic) ||
		!responseSeq.ReadASN1(&basicRespBytes, asn1.OCTET_STRING) ||
		!responseSeq.Empty() ||
		!basicRespBytes.ReadASN1(&basicResp, asn1.SEQUENCE) ||
		!basicRespBytes.Empty() ||
		!basicResp.ReadASN1Element(&tbsResponse, asn1.SEQUENCE) ||
		!basicResp.ReadASN1(&sigAlgoID, asn1.SEQUENCE) ||
		!sigAlgoID.ReadASN1ObjectIdentifier(&sigAlgoOID) ||
		!basicResp.ReadASN1BitStringAsBytes(&ret.Signature) ||
		!basicResp.ReadOptionalASN1(&certsSeq, &certsPresent, asn1.Tag(0).ContextSpecific().Constructed()) ||
		!basicResp.Empty() {
		return nil, ParseError("failed to parse OCSP response")
	}

	ret.TBSResponseData = []byte(tbsResponse)
	ret.SignatureAlgorithm = getSignatureAlgorithmFromOID(sigAlgoOID)

	var responderIDContent cryptobyte.String
	var responderIDTag asn1.Tag
	if !tbsResponse.ReadASN1(&tbsResponse, asn1.SEQUENCE) ||
		!tbsResponse.SkipOptionalASN1(asn1.Tag(0).ContextSpecific().Constructed()) ||
		!tbsResponse.ReadAnyASN1(&responderIDContent, &responderIDTag) {
		return nil, ParseError("failed to parse OCSP response")
	}

	switch responderIDTag {
	case asn1.Tag(1).ContextSpecific().Constructed():
		// byName
		ret.RawResponderName = responderIDContent
	case asn1.Tag(2).ContextSpecific().Constructed():
		if !responderIDContent.ReadASN1Bytes(&ret.ResponderKeyHash, asn1.OCTET_STRING) ||
			!responderIDContent.Empty() {
			return nil, ParseError("failed to parse responder key hash")
		}
	default:
		return nil, ParseError("unknown responder ID type")
	}

	var responses cryptobyte.String
	if !tbsResponse.ReadASN1GeneralizedTime(&ret.ProducedAt) ||
		!tbsResponse.ReadASN1(&responses, asn1.SEQUENCE) ||
		!tbsResponse.SkipOptionalASN1(asn1.Tag(1).ContextSpecific().Constructed()) ||
		!tbsResponse.Empty() {
		return nil, ParseError("failed to parse OCSP response")
	}

	var foundSingleResponse bool
	// possibleCertIDError contains an error returning from parsing a
	// CertID. Since this might be because of an unknown hash function, we
	// wish to continue to see whether another SingleResponse matches. If,
	// after all, no matches are found, this error is reported.
	var possibleCertIDError error

	for len(responses) > 0 {
		var response, status cryptobyte.String
		if !responses.ReadASN1(&response, asn1.SEQUENCE) {
			return nil, ParseError("failed to parse OCSP response")
		}
		certID, err := parseCertID(&response)
		if err != nil {
			possibleCertIDError = err
			continue
		}

		if cert != nil {
			if certID.SerialNumber.Cmp(cert.SerialNumber) != 0 {
				continue
			}

			h := certID.HashAlgorithm.New()
			h.Write(cert.RawIssuer)
			nameHash := h.Sum(nil)
			if !bytes.Equal(certID.IssuerNameHash, nameHash) {
				continue
			}
		}

		var statusTag asn1.Tag
		ret.SerialNumber = certID.SerialNumber
		if !response.ReadAnyASN1(&status, &statusTag) {
			return nil, ParseError("failed to parse OCSP response")
		}

		ret.IssuerHash = certID.HashAlgorithm

		switch statusTag {
		case certStatusGood:
			ret.Status = Good
		case certStatusUnknown:
			ret.Status = Unknown
		case certStatusRevoked:
			ret.Status = Revoked

			var reason cryptobyte.String
			var reasonPresent bool
			if !status.ReadASN1GeneralizedTime(&ret.RevokedAt) ||
				!status.ReadOptionalASN1(&reason, &reasonPresent, asn1.Tag(0).ContextSpecific().Constructed()) ||
				(reasonPresent && !reason.ReadASN1Enum(&ret.RevocationReason) ||
					!status.Empty()) {
				return nil, ParseError("failed to parse RevokedInfo")
			}
		default:
			return nil, ParseError("unknown status in SingleResponse: " + strconv.Itoa(int(statusTag)))
		}

		var nextUpdate, extsSeq cryptobyte.String
		var nextUpdatePresent, extsPresent bool
		if !response.ReadASN1GeneralizedTime(&ret.ThisUpdate) ||
			!response.ReadOptionalASN1(&nextUpdate, &nextUpdatePresent, asn1.Tag(0).ContextSpecific().Constructed()) ||
			(nextUpdatePresent && !nextUpdate.ReadASN1GeneralizedTime(&ret.NextUpdate)) ||
			!nextUpdate.Empty() ||
			!response.ReadOptionalASN1(&extsSeq, &extsPresent, asn1.Tag(1).ContextSpecific().Constructed()) ||
			!response.Empty() {
			return nil, ParseError("failed to parse SingleResponse")
		}

		if extsPresent {
			var exts cryptobyte.String
			if !extsSeq.ReadASN1(&exts, asn1.SEQUENCE) {
				return nil, ParseError("failed to parse extensions")
			}

			for !exts.Empty() {
				var ext cryptobyte.String
				var extension pkix.Extension
				if !exts.ReadASN1(&ext, asn1.SEQUENCE) ||
					!ext.ReadASN1ObjectIdentifier(&extension.Id) ||
					!ext.ReadOptionalASN1Boolean(&extension.Critical, false) ||
					!ext.ReadASN1((*cryptobyte.String)(&extension.Value), asn1.OCTET_STRING) ||
					!ext.Empty() {
					return nil, ParseError("failed to parse extension")
				}

				if extension.Critical {
					return nil, ParseError("unsupported critical extension")
				}

				ret.Extensions = append(ret.Extensions, extension)
			}
		}

		foundSingleResponse = true
		break
	}

	if !foundSingleResponse {
		if possibleCertIDError != nil {
			return nil, ParseError("no response matching the supplied certificate, possibily because of error parsing CertID: " + possibleCertIDError.Error())
		}
		if cert == nil {
			return nil, ParseError("no responses found in reply")
		} else {
			return nil, ParseError("no response matching the supplied certificate")
		}
	}

	if certsPresent {
		var certs, cert cryptobyte.String
		if !certsSeq.ReadASN1(&certs, asn1.SEQUENCE) ||
			!certs.ReadASN1Element(&cert, asn1.SEQUENCE) {
			return nil, ParseError("invalid responder certificate")
		}
		if !certs.Empty() {
			return nil, ParseError("bad number of responder certificates")
		}

		var err error
		if ret.Certificate, err = x509.ParseCertificate([]byte(cert)); err != nil {
			return nil, ParseError("while parsing responder certificate: " + err.Error())
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

	return ret, nil
}
