// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package x509roots provides functionality for parsing NSS certdata.txt
// formatted certificate lists and extracting serverAuth roots. The parser
// provided by this package is very opinionated, only returning roots that are
// currently trusted for serverAuth. As such roots returned by this package
// should only be used for making trust decisions about serverAuth certificates,
// as the trust status for other uses is not considered. Using the roots
// returned by this package for trust decisions should be done carefully.
//
// Some roots returned by the parser may include additional constraints
// (currently only NSSDistrustAfter) which need to be considered when verifying
// certificates which chain to them.
//
// ParseNSSCertData is not intended to be a general purpose parser for
// certdata.txt.
package x509roots

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// NSSConstraint is a constraint to be applied to a certificate or
// certificate chain.
type NSSConstraint any

// NSSDistrustAfter is a NSSConstraint that indicates a certificate has a
// CKA_NSS_SERVER_DISTRUST_AFTER constraint. This constraint defines a date
// after which any certificate issued which is rooted by the constrained
// certificate should be distrusted.
type NSSDistrustAfter time.Time

// NSSCert represents a single trusted serverAuth certificate in the NSS
// certdata.txt list. If the entry contains a CKA_NSS_SERVER_DISTRUST_AFTER
// value, DistrustAfter will be non-nil and indicates the date after which
// certificates which chain to Certificate should no longer be trusted.
type NSSCert struct {
	// Certificate is the parsed certificate
	Certificate *x509.Certificate
	// Constraints contains a list of additional constraints that should be
	// applied to any certificates that chain to Certificate. If there are
	// any unknown constraints in the slice, Certificate should not be
	// trusted.
	Constraints []NSSConstraint
}

func parseMulitLineOctal(s *bufio.Scanner) ([]byte, error) {
	buf := bytes.NewBuffer(nil)
	for s.Scan() {
		if s.Text() == "END" {
			break
		}
		b, err := strconv.Unquote(fmt.Sprintf("\"%s\"", s.Text())) // hack hack hack
		if err != nil {
			return nil, err
		}
		buf.Write([]byte(b))
	}
	return buf.Bytes(), nil
}

type certObj struct {
	c             *x509.Certificate
	DistrustAfter *time.Time
}

func parseCertClass(s *bufio.Scanner) ([sha1.Size]byte, *certObj, error) {
	var h [sha1.Size]byte
	co := &certObj{}
	for s.Scan() {
		l := s.Text()
		if l == "" {
			// assume an empty newline indicates the end of a block
			break
		}
		if strings.HasPrefix(l, "CKA_VALUE") {
			b, err := parseMulitLineOctal(s)
			if err != nil {
				return h, nil, err
			}
			co.c, err = x509.ParseCertificate(b)
			if err != nil {
				return h, nil, err
			}
			h = sha1.Sum(b)
		} else if strings.HasPrefix(l, "CKA_NSS_MOZILLA_CA_POLICY CK_BBOOL CK_FALSE") {
			// we don't want it
			return h, nil, nil
		} else if l == "CKA_NSS_SERVER_DISTRUST_AFTER MULTILINE_OCTAL" {
			dateStr, err := parseMulitLineOctal(s)
			if err != nil {
				return h, nil, err
			}
			t, err := time.Parse("060102150405Z0700", string(dateStr))
			if err != nil {
				return h, nil, err
			}
			co.DistrustAfter = &t
		}
	}
	if co.c == nil {
		return h, nil, errors.New("malformed CKO_CERTIFICATE object")
	}
	return h, co, nil
}

type trustObj struct {
	trusted bool
}

func parseTrustClass(s *bufio.Scanner) ([sha1.Size]byte, *trustObj, error) {
	var h [sha1.Size]byte
	to := &trustObj{trusted: false} // default to untrusted

	for s.Scan() {
		l := s.Text()
		if l == "" {
			// assume an empty newline indicates the end of a block
			break
		}
		if l == "CKA_CERT_SHA1_HASH MULTILINE_OCTAL" {
			hash, err := parseMulitLineOctal(s)
			if err != nil {
				return h, nil, err
			}
			copy(h[:], hash)
		} else if l == "CKA_TRUST_SERVER_AUTH CK_TRUST CKT_NSS_TRUSTED_DELEGATOR" {
			// we only care about server auth
			to.trusted = true
		}
	}

	return h, to, nil
}

// ParseNSSCertData parses a NSS certdata.txt formatted file, returning only
// trusted serverAuth roots, as well as any additional constraints.
func ParseNSSCertData(r io.Reader) ([]NSSCert, error) {
	// certdata.txt is a rather strange format. It is essentially a list of
	// textual PKCS#11 objects, delimited by empty lines. There are two main
	// types of objects, certificates (CKO_CERTIFICATE) and trust definitions
	// (CKO_NSS_TRUST). These objects appear to alternatve, but this ordering is
	// not defined anywhere, and should probably not be relied on. A single root
	// certificate requires both the certificate object and the trust definition
	// object in order to be properly understood.
	//
	// The list contains not just serverAuth certificates, so we need to be
	// careful to only extract certificates which have the serverAuth trust bit
	// set. Similarly there are a number of trust related bool fields that
	// appear to _always_ be CKA_TRUE, but it seems unsafe to assume this is the
	// case, so we should always double check.
	//
	// Since we only really care about a couple of fields, this parser throws
	// away a lot of information, essentially just consuming CKA_CLASS objects
	// and looking for the individual fields we care about. We could write a
	// siginificantly more complex parser, which handles the entire format, but
	// it feels like that would be over engineered for the little information
	// that we really care about.

	scanner := bufio.NewScanner(r)

	type nssEntry struct {
		cert  *certObj
		trust *trustObj
	}
	entries := map[[sha1.Size]byte]*nssEntry{}

	for scanner.Scan() {
		// scan until we hit CKA_CLASS
		if !strings.HasPrefix(scanner.Text(), "CKA_CLASS") {
			continue
		}

		f := strings.Fields(scanner.Text())
		if len(f) != 3 {
			return nil, errors.New("malformed CKA_CLASS")
		}
		switch f[2] {
		case "CKO_CERTIFICATE":
			h, co, err := parseCertClass(scanner)
			if err != nil {
				return nil, err
			}
			if co != nil {
				e, ok := entries[h]
				if !ok {
					e = &nssEntry{}
					entries[h] = e
				}
				e.cert = co
			}

		case "CKO_NSS_TRUST":
			h, to, err := parseTrustClass(scanner)
			if err != nil {
				return nil, err
			}
			if to != nil {
				e, ok := entries[h]
				if !ok {
					e = &nssEntry{}
					entries[h] = e
				}
				e.trust = to
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	var certs []NSSCert
	for _, e := range entries {
		if e.cert == nil || e.trust == nil {
			// All certificates should have trust objects, and all trust objects
			// should have certificates. One without the other doesn't really
			// make sense. If we get here it is possible that we've misparsed
			// the SHA-1 hash, or something else strange.
			continue
		}
		if !e.trust.trusted {
			continue
		}
		nssCert := NSSCert{Certificate: e.cert.c}
		if e.cert.DistrustAfter != nil {
			nssCert.Constraints = append(nssCert.Constraints, NSSDistrustAfter(*e.cert.DistrustAfter))
		}
		certs = append(certs, nssCert)
	}

	return certs, nil
}
