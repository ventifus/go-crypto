// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cryptobyte

import (
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"time"
)

// This file contains ASN.1-related methods for String and Builder.

const (
	asn1ContextSpecific = 0x80
	asn1Constructed     = 0x20
)

// Builder

// AddASN1Int64 appends a DER-encoded ASN.1 INTEGER to the byte string.
func (b *Builder) AddASN1Int64(v int64) {
	b.addASN1Signed(asn1.TagInteger, v)
}

// AddASN1Enum appends a DER-encoded ASN.1 ENUMERATION to the byte string.
func (b *Builder) AddASN1Enum(v int64) {
	b.addASN1Signed(asn1.TagEnum, v)
}

func (b *Builder) addASN1Signed(tag uint8, v int64) {
	b.AddASN1(tag, func(c *Builder) {
		length := 1
		for i := v; i >= 0x80 || i < -0x80; i >>= 8 {
			length++
		}

		for ; length > 0; length-- {
			i := v >> uint((length-1)*8) & 0xff
			c.AddUint8(uint8(i))
		}
	})
}

// AddASN1Uint64 appends a DER-encoded ASN.1 INTEGER to the byte string.
func (b *Builder) AddASN1Uint64(v uint64) {
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
}

// AddASN1BigInt appends a DER-encoded ASN.1 INTEGER to the byte string.
func (b *Builder) AddASN1BigInt(n *big.Int) {
	if b.err != nil {
		return
	}
	if n == nil {
		b.err = errors.New("cannot add nil *big.Int")
	}

	b.AddASN1(asn1.TagInteger, func(c *Builder) {
		if n.Sign() < 0 {
			// A negative number has to be converted to two's-complement
			// form. So we'll invert and subtract 1. If the
			// most-significant-bit isn't set then we'll need to pad the
			// beginning with 0xff in order to keep the number negative.
			nMinus1 := new(big.Int).Neg(n)
			nMinus1.Sub(nMinus1, bigOne)
			bytes := nMinus1.Bytes()
			for i := range bytes {
				bytes[i] ^= 0xff
			}
			if len(bytes) == 0 || bytes[0]&0x80 == 0 {
				c.add(byte(0xff))
			}
			c.add(bytes...)
		} else if n.Sign() == 0 {
			// Zero is written as a single 0 zero rather than no bytes.
			c.add(0)
		} else {
			bytes := n.Bytes()
			if len(bytes) > 0 && bytes[0]&0x80 != 0 {
				// We'll have to pad this with 0x00 in order to stop it
				// looking like a negative number.
				c.add(byte(0))
			}
			c.add(bytes...)
		}
	})
}

// AddASN1OctetString appends a DER-encoded ASN.1 OCTET STRING to the byte
// string.
func (b *Builder) AddASN1OctetString(bytes []byte) {
	b.AddASN1(asn1.TagOctetString, func(c *Builder) {
		c.AddBytes(bytes)
	})
}

// AddASN1GeneralizedTime appends a DER-encoded ASN.1 GENERALIZEDTIME to the
// byte string.
func (b *Builder) AddASN1GeneralizedTime(t time.Time) {
	// TODO(martinkr): Implement.
	bytes, err := asn1.Marshal(
		struct {
			T time.Time `asn1:"generalized"`
		}{T: t})
	if err != nil {
		b.err = err
	}
	b.AddBytes(bytes[2:]) // Strip sequence header.
}

// AddASN1BitString appends a DER-encoded ASN.1 BIT STRING to the byte string.
func (b *Builder) AddASN1BitString(s asn1.BitString) {
	// TODO(martinkr): Implement.
	b.MarshalASN1(s)
}

// MarshalASN1 calls asn1.Marshal on its input and appends the result to the
// byte string if successful or records an error if one occurred.
func (b *Builder) MarshalASN1(v interface{}) {
	// NOTE(martinkr): This is somewhat of a hack to allow propagation of
	// asn1.Marshal errors into Builder.err. N.B. if you call MarshalASN1 with a
	// value embedded into a struct, its tag information is lost.
	if b.err != nil {
		return
	}
	bytes, err := asn1.Marshal(v)
	if err != nil {
		b.err = err
		return
	}
	b.AddBytes(bytes)
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

	b.AddUint8(tag)
	b.addLengthPrefixed(1, true, f)
}

// String

var bigIntType = reflect.TypeOf((*big.Int)(nil)).Elem()

// ReadASN1Integer decodes an ASN.1 Integer into out and advances over it. If
// out does not point to an integer or a big.Int, it panics. It returns true on
// success and false on error.
func (s *String) ReadASN1Integer(out interface{}) bool {
	if reflect.TypeOf(out).Kind() != reflect.Ptr {
		panic("out is not a pointer")
	}
	switch reflect.ValueOf(out).Elem().Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		var i int64
		s.readASN1SignedInteger(&i)
		if reflect.ValueOf(out).Elem().OverflowInt(i) {
			return false
		}
		reflect.ValueOf(out).Elem().SetInt(i)
		return true
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		var u uint64
		s.readASN1UnsignedInteger(&u)
		if reflect.ValueOf(out).Elem().OverflowUint(u) {
			return false
		}
		reflect.ValueOf(out).Elem().SetUint(u)
		return true
	case reflect.Struct:
		if reflect.TypeOf(out).Elem() == bigIntType {
			return s.readASN1BigInt(out.(*big.Int))
		}
	}
	panic("out does not point to an integer type")
}

func (s *String) readIntBytes(tag uint8) ([]byte, bool) {
	if tag != asn1.TagInteger && tag != asn1.TagEnum {
		panic("cryptobyte: internal error")
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

func (s *String) readASN1BigInt(out *big.Int) bool {
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
	} else {
		out.SetBytes(bytes)
	}
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

func (s *String) readASN1SignedInteger(out *int64) bool {
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

func (s *String) readASN1UnsignedInteger(out *uint64) bool {
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
func (s *String) ReadASN1Enum(out *int) bool {
	bytes, ok := s.readIntBytes(asn1.TagEnum)
	if !ok {
		return false
	}
	i, ok := signed(bytes)
	if !ok {
		return false
	}
	if int64(int(i)) != i {
		return false
	}
	*out = int(i)
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

// ReadASN1GeneralizedTime decodes an ASN.1 GENERALIZEDTIME into out and advances
// over it. It returns true on success and false on error.
func (s *String) ReadASN1GeneralizedTime(out *time.Time) bool {
	const formatStr = "20060102150405Z0700"
	var bytes String
	if !s.ReadASN1(&bytes, asn1.TagGeneralizedTime) {
		return false
	}
	t := string(bytes)
	res, err := time.Parse(formatStr, t)
	if err != nil {
		return false
	}
	if serialized := res.Format(formatStr); serialized != t {
		return false
	}
	*out = res
	return true
}

// ReadASN1BitString decodes an ASN.1 BIT STRING into out and advances over it.
// It returns true on success and false on error.
func (s *String) ReadASN1BitString(out *asn1.BitString) bool {
	var bytes String
	if !s.ReadASN1(&bytes, asn1.TagBitString) || len(bytes) == 0 {
		return false
	}

	paddingBits := uint8(bytes[0])
	bytes = bytes[1:]
	if paddingBits > 7 ||
		len(bytes) == 0 && paddingBits != 0 ||
		bytes[len(bytes)-1]&(1<<paddingBits-1) != 0 {
		return false
	}

	out.BitLength = len(bytes)*8 - int(paddingBits)
	out.Bytes = bytes
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

// PeekASN1Tag returns true if the next ASN.1 value on the string starts with
// the given tag.
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
	// TODO(martinkr): Figure out how the API should handle non-tag id bits.
	// Optional is always explicit is always context-specific and constructed.
	id := asn1ContextSpecific | asn1Constructed | tag
	present := false
	if s.PeekASN1Tag(id) {
		if !s.ReadASN1(out, id) {
			return false
		}
		present = true
	}
	if outPresent != nil {
		*outPresent = present
	}
	return true
}

// ReadOptionalASN1Integer attempts to read an optional ASN.1 INTEGER
// explicitly tagged with tag into out and advances. If no element with a
// matching tag is present, it writes defaultValue into out instead. If out
// does not point to and integer or big.Int, it panics. It returns true on
// success and false on error.
func (s *String) ReadOptionalASN1Integer(out interface{}, tag uint8, defaultValue interface{}) bool {
	if reflect.TypeOf(out).Kind() != reflect.Ptr {
		panic("out is not a pointer")
	}
	var present bool
	var i String
	if !s.ReadOptionalASN1(&i, &present, tag) {
		return false
	}
	if !present {
		switch reflect.ValueOf(out).Elem().Kind() {
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
			reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			reflect.ValueOf(out).Elem().Set(reflect.ValueOf(defaultValue))
		case reflect.Struct:
			if reflect.TypeOf(out).Elem() != bigIntType {
				panic("invalid integer type")
			}
			if reflect.TypeOf(defaultValue).Kind() != reflect.Ptr ||
				reflect.TypeOf(defaultValue).Elem() != bigIntType {
				panic("out points to big.Int, but defaultValue does not")
			}
			out.(*big.Int).Set(defaultValue.(*big.Int))
		default:
			panic("invalid integer type")
		}
		return true
	}
	if !i.ReadASN1Integer(out) || !i.Empty() {
		return false
	}
	return true
}

// ReadOptionalASN1OctetString attempts to read an optional ASN.1 OCTET STRING
// explicitly tagged with tag into out and advances. If no element with a
// matching tag is present, it writes defaultValue into out instead. It returns
// true on success and false on error.
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
