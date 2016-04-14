package encoding

import "io"

// Field is an encoded field of an openpgp packet.
type Field interface {
	// Bytes returns the decoded data.
	Bytes() []byte
	// BitLength is the size in bits of the decoded data.
	BitLength() uint16
	// EncodedLength is the size in bytes of the encoded data.
	EncodedLength() uint16

	// ReadFrom reads the next Field from r.
	ReadFrom(r io.Reader) (int64, error)
	// Write serializes the Field to w.
	WriteTo(w io.Writer) (int64, error)
}
