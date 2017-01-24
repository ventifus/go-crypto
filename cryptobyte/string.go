// Package cryptobyte implements building and parsing of byte strings for ASN.1 and TLS messages.
package cryptobyte

// String represents a string of bytes. It provides methods for parsing
// fixed-length and length-prefixed values from it.
type String []byte

// get advances a String by n bytes and returns them.
func (s *String) get(n int) []byte {
	if len(*s) < n {
		return nil
	}
	v := (*s)[:n]
	*s = (*s)[n:]
	return v
}

// ReadUint8 decodes an 8-bit value into out and advances itself over it. It
// returns true on success and false on error.
func (s *String) ReadUint8(out *uint8) bool {
	v := s.get(1)
	if v == nil {
		return false
	}
	*out = uint8(v[0])
	return true
}

// ReadUint16 decodes a big-endian, 16-bit value into out and advances itself
// over it. It returns true on success and false on error.
func (s *String) ReadUint16(out *uint16) bool {
	v := s.get(2)
	if v == nil {
		return false
	}
	*out = uint16(v[0])<<8 | uint16(v[1])
	return true
}

// ReadUint24 decodes a big-endian, 24-bit value into out and advances itself
// over it. It returns true on success and false on error.
func (s *String) ReadUint24(out *uint32) bool {
	v := s.get(3)
	if v == nil {
		return false
	}
	*out = uint32(v[0])<<16 | uint32(v[1])<<8 | uint32(v[2])
	return true
}

// ReadUint32 decodes a big-endian, 32-bit value into out and advances itself
// over it. It returns true on success and false on error.
func (s *String) ReadUint32(out *uint32) bool {
	v := s.get(4)
	if v == nil {
		return false
	}
	*out = uint32(v[0])<<24 | uint32(v[1])<<16 | uint32(v[2])<<8 | uint32(v[3])
	return true
}

func (s *String) getLengthPrefixed(lenLen int, outChild *String) bool {
	lenBytes := s.get(lenLen)
	if lenBytes == nil {
		return false
	}
	var length int
	for _, b := range lenBytes {
		length = length << 8
		length = length | int(b)
	}
	v := s.get(length)
	if v == nil {
		return false
	}
	*outChild = v
	return true
}

// ReadUint8LengthPrefixed reads the content of an 8-bit length-prefixed value
// into out and advances itself over it. It returns true on success and false
// on error.
func (s *String) ReadUint8LengthPrefixed(out *String) bool {
	return s.getLengthPrefixed(1, out)
}

// ReadUint16LengthPrefixed reads the content of a big-endian, 16-bit
// length-prefixed value into out and advances itself over it. It returns true
// on success and false on error.
func (s *String) ReadUint16LengthPrefixed(out *String) bool {
	return s.getLengthPrefixed(2, out)
}

// ReadUint24LengthPrefixed reads the content of a big-endian, 24-bit
// length-prefixed value into out and advances itself over it. It returns true
// on success and false on error.
func (s *String) ReadUint24LengthPrefixed(out *String) bool {
	return s.getLengthPrefixed(3, out)
}

// ReadUint32LengthPrefixed reads the content of a big-endian, 32-bit
// length-prefixed value into out and advances itself over it. It returns true
// on success and false on error.
func (s *String) ReadUint32LengthPrefixed(out *String) bool {
	return s.getLengthPrefixed(4, out)
}

// ReadBytes reads n bytes into out and advances itself over them. It returns
// true on success and false and error.
func (s *String) ReadBytes(out *[]byte, n int) bool {
	v := s.get(n)
	if v == nil {
		return false
	}
	*out = v
	return true
}

// CopyBytes copies len(out) bytes into out and advances itself over them. It
// returns true on success and false on error.
func (s *String) CopyBytes(out []byte) bool {
	n := len(out)
	v := s.get(n)
	if v == nil {
		return false
	}
	return copy(out, v) == n
}

// TODO(martinkr): Add ASN.1 parsing.
