// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package asn1 contains supporting types for parsing and building ASN.1
// messages with the cryptobyte package.
package asn1 // import "golang.org/x/crypto/cryptobyte/asn1"

// Tag represents an ASN.1 identifier octet, consisting of a tag number
// (indicating a type) and class (such as context-specific or constructed).
//
// Methods in the cryptobyte package only support the low-tag-number form, i.e.
// a single identifier octet with bits 7-8 encoding the class and bits 1-6
// encoding the tag number.
type Tag uint8

const (
	classConstructed     = 0x20
	classContextSpecific = 0x80
)

// Constructed returns t with the constructed class bit set.
func (t Tag) Constructed() Tag { return t | classConstructed }

// ContextSpecific returns t with the context-specific class bit set.
func (t Tag) ContextSpecific() Tag { return t | classContextSpecific }

// The following is a list of standard tag and class combinations.
const (
	TagBoolean         = Tag(1)
	TagInteger         = Tag(2)
	TagBitString       = Tag(3)
	TagOctetString     = Tag(4)
	TagNull            = Tag(5)
	TagOID             = Tag(6)
	TagEnum            = Tag(10)
	TagUTF8String      = Tag(12)
	TagSequence        = Tag(16 | classConstructed)
	TagSet             = Tag(17 | classConstructed)
	TagPrintableString = Tag(19)
	TagT61String       = Tag(20)
	TagIA5String       = Tag(22)
	TagUTCTime         = Tag(23)
	TagGeneralizedTime = Tag(24)
	TagGeneralString   = Tag(27)
)
