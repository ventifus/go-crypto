// Package cryptobyte implements building and parsing of byte strings for ASN.1 and TLS messages.
package cryptobyte

import (
	"flag"
	"fmt"
	"log"
)

var debugEnabled = flag.Bool("cryptobyte-log", false,
	"If true, log parsing errors for the cryptobyte package.")

// String represents a string of bytes. It provides methods for parsing
// fixed-length and length-prefixed values from it.
type String []byte

// get advances a String by n bytes and returns them.
func (s *String) get(n int) ([]byte, error) {
	if len(*s) < n {
		return nil, fmt.Errorf("tried to read %d bytes, but only %d left", n, len(*s))
	}
	v := (*s)[:n]
	*s = (*s)[n:]
	return v, nil
}

// GetU8 sets out to the next 8-bit value from the string and advances
// itself over it. It returns true on success and false on error.
func (s *String) GetU8(out *uint8) bool {
	v, err := s.get(1)
	if err != nil {
		logln("GetU8: ", err)
		return false
	}
	if out != nil {
		*out = uint8(v[0])
	}
	return true
}

// GetU16 sets out to the next big-endian 16-bit value from the string and
// advances itself over it. It returns true on success and false on error.
func (s *String) GetU16(out *uint16) bool {
	v, err := s.get(2)
	if err != nil {
		logln("GetU16: ", err)
		return false
	}
	if out != nil {
		*out = uint16(v[0])<<8 | uint16(v[1])
	}
	return true
}

// GetU24 sets out to the next big-endian, 24-bit value from the string and
// advances itself over it. It returns true on success and false on error.
func (s *String) GetU24(out *uint32) bool {
	v, err := s.get(3)
	if err != nil {
		logln("GetU24: ", err)
		return false
	}
	if out != nil {
		*out = uint32(v[0])<<16 | uint32(v[1])<<8 | uint32(v[2])
	}
	return true
}

// GetU32 sets out to the next big-endian, 32-bit value from the string and
// advances itself over it. It returns true on success and false on error.
func (s *String) GetU32(out *uint32) bool {
	v, err := s.get(4)
	if err != nil {
		logln("GetU32: ", err)
		return false
	}
	if out != nil {
		*out = uint32(v[0])<<24 | uint32(v[1])<<16 | uint32(v[2])<<8 | uint32(v[3])
	}
	return true
}

func (s *String) getLengthPrefixed(lenLen int, outChild *String) bool {
	lenBytes, err := s.get(lenLen)
	if err != nil {
		logf("getLengthPrefixed(%d) failed to read length field: %v\n", lenLen, err)
		return false
	}
	var length int
	for _, b := range lenBytes {
		length = length << 8
		length = length | int(b)
	}
	v, err := s.get(length)
	if err != nil {
		logf("getLengthPrefixed(%d) failed to read content: %v\n", lenLen, err)
		return false
	}
	if outChild != nil {
		*outChild = v
	}
	return true
}

// GetU8LengthPrefixed reads the content of an 8-bit big-endian length-prefixed
// value into out and advances itself over it. It returns true on success and
// false on error.
func (s *String) GetU8LengthPrefixed(out *String) bool {
	return s.getLengthPrefixed(1, out)
}

// GetU16LengthPrefixed reads the content of an 16-bit big-endian
// length-prefixed value into out and advances itself over it. It returns true
// on success and false on error.
func (s *String) GetU16LengthPrefixed(out *String) bool {
	return s.getLengthPrefixed(2, out)
}

// GetU24LengthPrefixed reads the content of an 24-bit big-endian
// length-prefixed value into out and advances itself over it. It returns true
// on success and false on error.
func (s *String) GetU24LengthPrefixed(out *String) bool {
	return s.getLengthPrefixed(3, out)
}

// GetU32LengthPrefixed reads the content of an 32-bit big-endian
// length-prefixed value into out and advances itself over it. It returns true
// on success and false on error.
func (s *String) GetU32LengthPrefixed(out *String) bool {
	return s.getLengthPrefixed(4, out)
}

// GetBytes reads n bytes into out and advances itself over them. It returns
// true on success and false and error.
func (s *String) GetBytes(out *[]byte, n int) bool {
	v, err := s.get(n)
	if err != nil {
		logln("GetBytes: ", err)
		return false
	}
	*out = v
	return true
}

// CopyBytes copies len(out) bytes into out and advances itself over them. It
// returns true on success and false on error.
func (s *String) CopyBytes(out []byte) bool {
	n := len(out)
	v, err := s.get(n)
	if err != nil {
		logln("CopyBytes: ", err)
		return false
	}
	return copy(out, v) == n
}

// TODO(martinkr): Add ASN.1 parsing.

func logln(v ...interface{}) {
	if !*debugEnabled {
		return
	}
	log.Println(v...)
}

func logf(format string, v ...interface{}) {
	if !*debugEnabled {
		return
	}
	log.Printf(format, v...)
}
