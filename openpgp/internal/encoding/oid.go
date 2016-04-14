// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package encoding

import (
	"io"

	"golang.org/x/crypto/openpgp/errors"
)

// OID is used to store a variable-length field with a one-octet size
// prefix. See https://tools.ietf.org/html/rfc6637#section-9.
type OID struct {
	bytes []byte
}

const (
	// maxOID is the maximum number of bytes in a OID.
	maxOID = 254
	// reservedOIDLength1 and reservedOIDLength2 are OID lengths that the RFC
	// specifies are reserved.
	reservedOIDLength1 = 0
	reservedOIDLength2 = 0xff
)

// NewOID returns a OID initialized with bytes.
func NewOID(bytes []byte) *OID {
	switch len(bytes) {
	case reservedOIDLength1, reservedOIDLength2:
		panic("encoding: NewOID argument length is reserved")
	default:
		if len(bytes) > maxOID {
			panic("encoding: NewOID argment too large")
		}
	}

	return &OID{
		bytes: bytes,
	}
}

// Bytes returns the decoded data.
func (b *OID) Bytes() []byte {
	return b.bytes
}

// BitLength is the size in bits of the decoded data.
func (b *OID) BitLength() uint16 {
	return uint16(len(b.bytes) * 8)
}

// EncodedLength is the size in bytes of the encoded data.
func (b *OID) EncodedLength() uint16 {
	return uint16(1 + len(b.bytes))
}

// ReadFrom reads into b the next OID from r.
func (b *OID) ReadFrom(r io.Reader) (int64, error) {
	var buf [1]byte
	n, err := io.ReadFull(r, buf[:])
	if err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return int64(n), err
	}

	switch buf[0] {
	case reservedOIDLength1, reservedOIDLength2:
		return int64(n), errors.UnsupportedError("reserved for future extensions")
	}

	b.bytes = make([]byte, buf[0])

	nn, err := io.ReadFull(r, b.bytes)
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}

	return int64(n) + int64(nn), err
}

// WriteTo serializes b to w.
func (b *OID) WriteTo(w io.Writer) (int64, error) {
	n, err := w.Write([]byte{byte(len(b.bytes))})
	if err != nil {
		return int64(n), err
	}

	nn, err := w.Write(b.bytes)
	return int64(n) + int64(nn), err
}
