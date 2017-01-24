// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cryptobyte

import (
	"encoding/asn1"
	"fmt"
	"math/big"
)

// This file contains ASN.1-related methods for String and Builder.

// Builder

// AddASN1Int64 appends a DER-encoded ASN.1 INTEGER to the byte string.
func (b *Builder) AddASN1Int64(v int64) *Builder {
	b.AddASN1(asn1.TagInteger, func(c *Builder) {
		length := 1
		for i := v; i >= 0x80 || i < -0x80; i >>= 8 {
			length++
		}

		for ; length > 0; length-- {
			i := v >> uint((length-1)*8) & 0xff
			c.AddUint8(uint8(i))
		}
	})
	return b
}

// AddASN1Uint64 appends a DER-encoded ASN.1 INTEGER to the byte string.
func (b *Builder) AddASN1Uint64(v uint64) *Builder {
	b.AddASN1(asn1.TagInteger, func(c *Builder) {
		length := 1
		for i := v; i >= 0x80; i >>= 8 {
			length++
		}

		for ; length > 0; length-- {
			i := v >> uint((length-1)*8) & 0xff
			c.AddUint8(uint8(i))
		}
	})
	return b
}

// AddASN1 adds an ASN.1 object to the byte string. The object is prefixed with
// the given tag. Tags greater than 30 are not supported and result in an error
// (i.e. low-tag-number form only). The child builder passed to the
// BuilderContinuation can be used to build the content of the ASN.1 object.
func (b *Builder) AddASN1(tag uint8, f BuilderContinuation) {
	// Identifiers with 0x1f set indicate high-tag-number format (two or more
	// octets), which we don't support.
	if tag&0x1f == 0x1f {
		b.err = fmt.Errorf("high-tag number identifier octects not supported: 0x%x", tag)
		return
	}

	b.AddUint8(uint8(tag))
	b.addLengthPrefixed(1, true, f)
}

// String

func (s *String) readIntBytes(tag uint8) ([]byte, bool) {
	if tag != asn1.TagInteger && tag != asn1.TagEnum {
		panic("internal error")
	}
	var result []byte
	if !s.ReadASN1((*String)(&result), tag) {
		return nil, false
	}

	length := len(result)
	if length == 0 {
		// An INTEGER is encoded with at least one octet.
		return nil, false
	}
	if length == 1 {
		return result, true
	}
	if result[0] == 0 && result[1]&0x80 == 0 || result[0] == 0xff && result[1]&0x80 == 0x80 {
		// Extra leading zero octet.
		return nil, false
	}
	return result, true
}

var bigOne = big.NewInt(1)

// ReadASN1BigInt decodes an ASN.1 INTEGER into out and advances over it. It
// returns true on success and false one error.
// TODO(martinkr): We could just make one ReadASN1Int that reflects on the
// type of out?
func (s *String) ReadASN1BigInt(out *big.Int) bool {
	bytes, ok := s.readIntBytes(asn1.TagInteger)
	if !ok {
		return false
	}
	if bytes[0]&0x80 == 0x80 {
		// Negative number.
		neg := make([]byte, len(bytes))
		for i := range bytes {
			neg[i] = ^bytes[i]
		}
		out.SetBytes(neg)
		out.Add(out, bigOne)
		out.Neg(out)
		return true
	}
	out.SetBytes(bytes)
	return true
}

func signed(n []byte) (int64, bool) {
	length := len(n)
	if length == 0 || length > 8 {
		// An INTEGER is encoded with at least one octet; an int64 is at most eight.
		return 0, false
	}

	if n[0] == 0 && length > 1 && (n[1]&0x80 == 0) {
		// Extra leading zero octet.
		return 0, false
	}

	var out int64
	for i := 0; i < length; i++ {
		out <<= 8
		out |= int64(n[i])
	}

	// Shift up and down in order to sign extend the result.
	out <<= 64 - uint8(length)*8
	out >>= 64 - uint8(length)*8

	return out, true
}

// ReadASN1Int64 decodes a ASN.1 INTEGER into out and advances over it. It
// returns true on success and false on error.
func (s *String) ReadASN1Int64(out *int64) bool {
	bytes, ok := s.readIntBytes(asn1.TagInteger)
	if !ok {
		return false
	}
	i, ok := signed(bytes)
	if !ok {
		return false
	}
	*out = i
	return true
}

func unsigned(n []byte) (uint64, bool) {
	length := len(n)

	if length == 0 {
		// An INTEGER is encoded with at least one octet.
		return 0, false
	}

	if length > 9 || length == 9 && n[0] != 0 {
		// Too large for uint64.
		return 0, false
	}

	if n[0]&0x80 != 0 {
		// Negative number.
		return 0, false
	}

	if n[0] == 0 && length > 1 && (n[1]&0x80 == 0) {
		// Extra leading zero octet.
		return 0, false
	}

	var out uint64
	for i := 0; i < length; i++ {
		out <<= 8
		out |= uint64(n[i])
	}
	return out, true
}

// ReadASN1Uint64 decodes an ASN.1 INTEGER into out and advances over it. The
// decoded value must be non-negative. It returns true on success and false on
// error.
func (s *String) ReadASN1Uint64(out *uint64) bool {
	bytes, ok := s.readIntBytes(asn1.TagInteger)
	if !ok {
		return false
	}
	i, ok := unsigned(bytes)
	if !ok {
		return false
	}
	*out = i
	return true
}

// ReadASN1Enum decodes an ASN.1 ENUMERATION into out and advances over it.
// It returns true on success and false on error.
func (s *String) ReadASN1Enum(out *int64) bool {
	bytes, ok := s.readIntBytes(asn1.TagEnum)
	if !ok {
		return false
	}
	i, ok := signed(bytes)
	if !ok {
		return false
	}
	*out = i
	return true
}

// ReadASN1ObjectIdentifier decodes an ASN.1 OBJECT IDENTIFIER into out and
// advances over it. It returns true on success and false on error.
func (s *String) ReadASN1ObjectIdentifier(out *asn1.ObjectIdentifier) bool {
	// TODO(martinkr): Implement for real?
	rest, err := asn1.Unmarshal([]byte(*s), out)
	if err != nil {
		return false
	}
	*s = rest
	return true
}

// ReadASN1 reads the contents of a DER-encoded ASN.1 element (not
// including tag and length bytes) int out, and advances over the element. The
// element must match the given tag. It returns true on success and false on
// error.
//
// Tags greater than 30 are not supported (i.e. low-tag-number format only).
func (s *String) ReadASN1(out *String, tag uint8) bool {
	var tagVal uint8
	if !s.ReadAnyASN1(out, &tagVal) || tagVal != tag {
		return false
	}
	return true
}

// ReadASN1Element reads the contents of a DER-encoded ASN.1 element
// (including tag and length bytes) into out, and advances over the element.
// The element must match the given tag. It returns true on success and false
// on error.
//
// Tags greater than 30 are not supported (i.e. low-tag-number format only).
func (s *String) ReadASN1Element(out *String, tag uint8) bool {
	var tagVal uint8
	if !s.ReadAnyASN1Element(out, &tagVal) || tagVal != tag {
		return false
	}
	return true
}

// ReadAnyASN1 reads the contents of a DER-encoded ASN.1 element (not including
// tag and length bytes) into out, sets outTag to its tag, and advances over
// the element. It returns true on success and false on error.
//
// Tags greater than 30 are not supported (i.e. low-tag-number format only).
func (s *String) ReadAnyASN1(out *String, outTag *uint8) bool {
	return s.readASN1(out, outTag, false /* no BER */, true /* skip header */)
}

// ReadAnyASN1Element reads the contents of a DER-encoded ASN.1 element
// (including tag and length bytes) into out, sets outTag to is tag, and
// advances over the element. It returns true on success and false on error.
//
// Tags greater than 30 are not supported (i.e. low-tag-number format only).
func (s *String) ReadAnyASN1Element(out *String, outTag *uint8) bool {
	return s.readASN1(out, outTag, false /* no BER */, false /* include header */)
}

func (s String) PeekASN1Tag(tag uint8) bool {
	if len(s) == 0 {
		return false
	}
	return s[0] == tag
}

// ReadOptionalASN1 attempts to read the contents of a DER-encoded ASN.Element
// (not including tag and length bytes) tagged with the given tag into tag into
// out. It stores whether an element with the tag was found in outPresent,
// unless outPresent is nil. It returns true on success and false on error.
func (s *String) ReadOptionalASN1(out *String, outPresent *bool, tag uint8) bool {
	present := false
	if s.PeekASN1Tag(tag) {
		if !s.ReadASN1(out, tag) {
			return false
		}
		present = true
	}
	if outPresent != nil {
		*outPresent = present
	}
	return true
}

// ReadOptionalASN1Uint64 attempts to read an optional ASN.1 INTEGER explicitly
// tagged with tag into out and advances. If no element with a matching tag is
// present, it writes defaultValue into out instead. It returns true on success
// and false on error.
func (s *String) ReadOptionalASN1Uint64(out *uint64, tag uint8, defaultValue uint64) bool {
	var present bool
	var i String
	if !s.ReadOptionalASN1(&i, &present, tag) {
		return false
	}
	if !present {
		*out = defaultValue
		return true
	}
	if !i.ReadASN1Uint64(out) || !i.Empty() {
		return false
	}
	return true
}

func (s *String) ReadOptionalASN1OctetString(out *[]byte, outPresent *bool, tag uint8) bool {
	var present bool
	var child String
	if !s.ReadOptionalASN1(&child, &present, tag) {
		return false
	}
	if present {
		if !child.ReadASN1((*String)(out), asn1.TagOctetString) || !child.Empty() {
			return false
		}
	} else {
		*out = make([]byte, 0)
	}
	if outPresent != nil {
		*outPresent = present
	}
	return true
}

func (s *String) readASN1(
	out *String, outTag *uint8, allowBER, skipHeader bool) bool {
	if len(*s) < 2 {
		return false
	}
	var tag, lenByte uint8 = (*s)[0], (*s)[1]

	if tag&0x1f == 0x1f {
		// ITU-T X.690 section 8.1.2
		//
		// An identifier octet with a tag part of 0x1f indicates a high-tag-number
		// form identifier with two or more octets. We only support tags less than
		// 31 (i.e. low-tag-number form, single octet identifier).
		return false
	}

	if outTag != nil {
		*outTag = tag
	}

	// ITU-T X.690 section 8.1.3
	//
	// Bit 8 of the first length byte indicates whether the length is short- or
	// long-form.
	var length, headerLen uint32 // length includes headerLen
	if lenByte&0x80 == 0 {
		// Short-form length (section 8.1.3.4), encoded in bits 1-7.
		length = uint32(lenByte) + 2
		headerLen = 2
	} else {
		// Long-form length (section 8.1.3.5). Bits 1-7 encode the number of octets
		// used to encode the length.
		lenLen := lenByte & 0x7f
		var len32 uint32

		if allowBER {
			// TODO(martinkr): Do we need BER support?
		}

		if lenLen == 0 || lenLen > 4 {
			return false
		}

		lenBytes := String((*s)[2 : 2+lenLen])
		if !lenBytes.readUnsigned(&len32, int(lenLen)) {
			return false
		}

		// ITU-T X.690 section 10.1 (DER length forms) requires encoding the length
		// with the minimum number of octets.
		if len32 < 128 {
			// Length should have used short-form encoding.
			return false
		}
		if len32>>(lenLen-1)*8 == 0 {
			// Leading octet is 0. Length should have been at least one byte shorter.
			return false
		}

		headerLen = 2 + uint32(lenLen)
		if headerLen+len32 < len32 {
			// Overflow.
			return false
		}
		length = headerLen + len32
	}

	if !s.ReadBytes((*[]byte)(out), int(length)) {
		return false
	}
	if skipHeader && !out.Skip(int(headerLen)) {
		panic("cryptobyte: internal error")
	}

	return true
}
