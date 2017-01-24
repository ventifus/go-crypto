package cryptobyte

// A Builder builds byte strings from fixed-length and length-prefixed values.
type Builder struct {
	result        []byte
	noResize      bool
	child         *Builder
	offset        int
	pendingLenLen int
	pendingIsASN1 bool
}

// BuilderOpts may be passed to NewBuilder to modify Builder behavior.
type BuilderOpts interface {
	set(*Builder)
}

// FixedSize is a BuilderOpts that prevents the builder target buffer from
// being resized.
var FixedSize = fixedSize{}

type fixedSize struct{}

func (fixedSize) set(b *Builder) { b.noResize = true }

// NewBuilder creates a new Builder from a buffer to which the byte string will
// be appended. Users may want to pre-allocate buffer capacity to avoid
// reallocations as the output gets appended.
func NewBuilder(buffer []byte, opts ...BuilderOpts) *Builder {
	b := &Builder{
		result: buffer,
	}
	for _, o := range opts {
		o.set(b)
	}
	return b
}

// Bytes returns the bytes written to the builder.
func (b *Builder) Bytes() []byte {
	return b.result[b.offset:]
}

// AddU8 appends a big-endian, 8-bit value to the byte string.
func (b *Builder) AddU8(v uint8) {
	b.add(byte(v))
}

// AddU16 appends a big-endian, 16-bit value to the byte string.
func (b *Builder) AddU16(v uint16) {
	b.add(byte(v>>8), byte(v))
}

// AddU24 appends a big-endian, 24-bit value to the byte string. The highest
// byte of the 32-bit input value is silently truncated.
func (b *Builder) AddU24(v uint32) {
	b.add(byte(v>>16), byte(v>>8), byte(v))
}

// AddU32 appends a big-endian, 32-bit value to the byte string.
func (b *Builder) AddU32(v uint32) {
	b.add(byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// AddBytes appends a sequence of bytes to the byte string.
func (b *Builder) AddBytes(v []byte) {
	b.add(v...)
}

// TODO(martinkr): implement ASN.1 building.

// BuilderContinuation is continuation-passing interface for building
// length-prefixed byte sequences. Builder methods for length-prefixed
// sequences (AddU8LengthPrefixed etc.) will invoke the BuilderContinuation
// supplied to them. The child builder passed to the continuation can be used
// to build the content of the length-prefixed sequence. Example:
//
//   parent := cryptobyte.NewBuilder()
//   parent.AddU8LengthPrefixed(func (child *Builder) {
//     child.AddU8(42)
//     child.AddU8LengthPrefixed(func (grandchild *Builder) {
//       grandchild.AddU8(5)
//     })
//   })
//
// The child must be considered invalid after the continutation returns, i.e.
// users must not store any copies or references of the child that outlive the
// continuation.
type BuilderContinuation func(child *Builder)

// AddU8LengthPrefixed adds a big-endian, 8-bit length-prefixed byte sequence.
func (b *Builder) AddU8LengthPrefixed(f BuilderContinuation) {
	b.addLengthPrefixed(1, f)
}

// AddU16LengthPrefixed adds a big-endian, 16-bit length-prefixed byte sequence.
func (b *Builder) AddU16LengthPrefixed(f BuilderContinuation) {
	b.addLengthPrefixed(2, f)
}

// AddU24LengthPrefixed adds a big-endian, 24-bit length-prefixed byte sequence.
func (b *Builder) AddU24LengthPrefixed(f BuilderContinuation) {
	b.addLengthPrefixed(3, f)
}

// AddU32LengthPrefixed adds a big-endian, 32-bit length-prefixed byte sequence.
func (b *Builder) AddU32LengthPrefixed(f BuilderContinuation) {
	b.addLengthPrefixed(4, f)
}

func (b *Builder) addLengthPrefixed(lenLen int, f BuilderContinuation) {
	b.flushChild()
	offset := len(b.result)
	b.add(make([]byte, lenLen)...)

	b.child = &Builder{
		result:        b.result,
		noResize:      b.noResize,
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

	length := len(b.child.result) - b.child.pendingLenLen - b.child.offset

	if length < 0 {
		panic("internal error") // result unexpectedly shrunk
	}

	if b.child.pendingIsASN1 {
		// TODO(martinkr): add ASN.1 support
	}

	for i := b.child.pendingLenLen - 1; i >= 0; i-- {
		b.child.result[b.child.offset+i] = uint8(length)
		length = length >> 8
	}

	if length != 0 {
		panic("internal error") // length exceeds lenLen
	}

	b.result = b.child.result // In case child reallocated result.
	b.child = nil
}

// DiscardPendingChild may reverts the addition of a length-prefixed sequence.
//
// This method must only be called from within a BuilderContinuation and only
// on the parent to which the length-prefixed child sequence is added.
//
// Example:
//
//   parent.AddU8LengthPrefixed(func (child *Builder) {
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
	if b.noResize && len(b.result)+len(bytes) > cap(b.result) {
		panic("Builder is exceeding its fixed-size buffer")
	}
	b.result = append(b.result, bytes...)
}
