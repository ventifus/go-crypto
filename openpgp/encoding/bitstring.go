// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package encoding

import (
	"io"

	"golang.org/x/crypto/openpgp/errors"
)

// BitString is used to store a variable-length field with a one-octet size
// prefix.
type BitString struct {
	bytes []byte
}

// NewBitString returns a BitString initialized with bytes.
func NewBitString(bytes []byte) *BitString {
	return &BitString{
		bytes: bytes,
	}
}

// Bytes returns the decoded data.
func (b *BitString) Bytes() []byte {
	return b.bytes
}

// BitLength is the size in bits of the decoded data.
func (b *BitString) BitLength() uint16 {
	return uint16(len(b.bytes) * 8)
}

// EncodedLength is the size in bytes of the encoded data.
func (b *BitString) EncodedLength() uint16 {
	return uint16(1 + len(b.bytes))
}

// ReadFrom reads into b the next BitString from r.
func (b *BitString) ReadFrom(r io.Reader) (int64, error) {
	buf := make([]byte, 1)
	n, err := io.ReadFull(r, buf)
	if err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return int64(n), err
	}

	if buf[0] == 0 || buf[0] == 0xff {
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
func (b *BitString) WriteTo(w io.Writer) (int64, error) {
	n, err := w.Write([]byte{byte(len(b.bytes))})
	if err != nil {
		return int64(n), err
	}

	nn, err := w.Write(b.bytes)
	return int64(n) + int64(nn), err
}
