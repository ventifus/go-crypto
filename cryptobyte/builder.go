// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cryptobyte

import (
	"errors"
	"fmt"
)

// A Builder builds byte strings from fixed-length and length-prefixed values.
type Builder struct {
	err           error
	result        []byte
	fixedSize     bool
	child         *Builder
	offset        int
	pendingLenLen int
	pendingIsASN1 bool
}

// NewBuilder creates a Builder that appends its output into the given buffer.
// The buffer gets reallocated when writes exceed its capacity.
func NewBuilder(buffer []byte) *Builder {
	return &Builder{
		result: buffer,
	}
}

// NewFixedBuilder creates a Builder that appends its output into the given
// buffer. This builder does not reallocate the output buffer. Writes that
// would exceed the buffer capacity are treated as an error.
func NewFixedBuilder(buffer []byte) *Builder {
	return &Builder{
		result: buffer,
	}
}

// Bytes returns the bytes written by the builder or an error if one has
// occurred during during building.
func (b *Builder) Bytes() ([]byte, error) {
	if b.err != nil {
		return nil, b.err
	}
	return b.result[b.offset:], nil
}

// BytesOrPanic returns the bytes written by the builder or panics if an error
// has occurred during building.
func (b *Builder) BytesOrPanic() []byte {
	if b.err != nil {
		panic(b.err)
	}
	return b.result[b.offset:]
}

// AddUint8 appends an 8-bit value to the byte string.
func (b *Builder) AddUint8(v uint8) {
	b.add(byte(v))
}

// AddUint16 appends a big-endian, 16-bit value to the byte string.
func (b *Builder) AddUint16(v uint16) {
	b.add(byte(v>>8), byte(v))
}

// AddUint24 appends a big-endian, 24-bit value to the byte string. The highest
// byte of the 32-bit input value is silently truncated.
func (b *Builder) AddUint24(v uint32) {
	b.add(byte(v>>16), byte(v>>8), byte(v))
}

// AddUint32 appends a big-endian, 32-bit value to the byte string.
func (b *Builder) AddUint32(v uint32) {
	b.add(byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// AddBytes appends a sequence of bytes to the byte string.
func (b *Builder) AddBytes(v []byte) {
	b.add(v...)
}

// TODO(martinkr): implement ASN.1 building.

// BuilderContinuation is continuation-passing interface for building
// length-prefixed byte sequences. Builder methods for length-prefixed
// sequences (AddUint8LengthPrefixed etc.) will invoke the BuilderContinuation
// supplied to them. The child builder passed to the continuation can be used
// to build the content of the length-prefixed sequence. Example:
//
//   parent := cryptobyte.NewBuilder()
//   parent.AddUint8LengthPrefixed(func (child *Builder) {
//     child.AddUint8(42)
//     child.AddUint8LengthPrefixed(func (grandchild *Builder) {
//       grandchild.AddUint8(5)
//     })
//   })
//
// It is an error to write more bytes to the child than allowed by the reserved
// length prefix. After the continuation returns, the child must be considered
// invalid, i.e. users must not store any copies or references of the child
// that outlive the continuation.
type BuilderContinuation func(child *Builder)

// AddUint8LengthPrefixed adds a 8-bit length-prefixed byte sequence.
func (b *Builder) AddUint8LengthPrefixed(f BuilderContinuation) {
	b.addLengthPrefixed(1, f)
}

// AddUint16LengthPrefixed adds a big-endian, 16-bit length-prefixed byte sequence.
func (b *Builder) AddUint16LengthPrefixed(f BuilderContinuation) {
	b.addLengthPrefixed(2, f)
}

// AddUint24LengthPrefixed adds a big-endian, 24-bit length-prefixed byte sequence.
func (b *Builder) AddUint24LengthPrefixed(f BuilderContinuation) {
	b.addLengthPrefixed(3, f)
}

func (b *Builder) addLengthPrefixed(lenLen int, f BuilderContinuation) {
	// Subsequent writes can be ignored if the builder has encountered an error.
	if b.err != nil {
		return
	}

	offset := len(b.result)
	b.add(make([]byte, lenLen)...)

	b.child = &Builder{
		result:        b.result,
		fixedSize:     b.fixedSize,
		offset:        offset,
		pendingLenLen: lenLen,
	}

	f(b.child)
	b.flushChild()
}

func (b *Builder) flushChild() {
	if b.child == nil {
		return
	}

	b.child.flushChild()
	child := b.child
	b.child = nil

	if child.err != nil {
		b.err = child.err
		return
	}

	length := len(child.result) - child.pendingLenLen - child.offset

	if length < 0 {
		panic("internal error") // result unexpectedly shrunk
	}

	if child.pendingIsASN1 {
		// TODO(martinkr): add ASN.1 support
	}

	l := length
	for i := child.pendingLenLen - 1; i >= 0; i-- {
		child.result[child.offset+i] = uint8(l)
		l >>= 8
	}
	if l != 0 {
		b.err = fmt.Errorf("pending child length %d exceeds %d-byte length prefix",
			length, child.pendingLenLen)
		return
	}

	if !b.fixedSize {
		b.result = child.result // In case child reallocated result.
	}
}

// DiscardPendingChild may reverts the addition of a length-prefixed sequence.
//
// This method must only be called from within a BuilderContinuation and only
// on the parent to which the length-prefixed child sequence is added.
//
// Example:
//
//   parent.AddUint8LengthPrefixed(func (child *Builder) {
//     // add values by calling methods on child...
//     parent.DiscardPendingChild()
//     // child is now invalid
//   })
func (b *Builder) DiscardPendingChild() {
	if b.child == nil {
		panic("no pending child to discard")
	}
	b.result = b.result[:b.child.offset]
	b.child = nil
}

func (b *Builder) add(bytes ...byte) {
	if b.err != nil {
		return
	}
	if b.child != nil {
		panic("attempted write while child is pending")
	}
	if b.fixedSize && len(b.result)+len(bytes) > cap(b.result) {
		b.err = errors.New("Builder is exceeding its fixed-size buffer")
		return
	}
	b.result = append(b.result, bytes...)
}
