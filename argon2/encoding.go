// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package argon2

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// Format of the PHC string format for argon2.
// See https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md.
const encFormat = "$%s$v=%d$m=%d,t=%d,p=%d$%s$%s"

// encoding expresses all values used by encFormat,
// in types usable by this package.
type encoding struct {
	mode        int
	version     int
	memory      uint32
	time        uint32
	parallelism uint8
	salt        []byte
	key         []byte
}

// String returns the encoded format for argon2.
func (e *encoding) String() string {
	return fmt.Sprintf(encFormat,
		modeString(e.mode),
		e.version,
		e.memory,
		e.time,
		e.parallelism,
		base64.RawStdEncoding.EncodeToString(e.salt),
		base64.RawStdEncoding.EncodeToString(e.key),
	)
}

// Replace all $ for space, so that we can use the format for fmt.Sscanf.
var (
	decFormat = strings.ReplaceAll(encFormat, "$", " ")
)

// decode parses a PHC formatted string.
func decode(encoded string) (*encoding, error) {
	encoded = strings.ReplaceAll(encoded, "$", " ")
	var (
		enc  encoding
		mode string
		salt string
		key  string
	)

	_, err := fmt.Sscanf(encoded, decFormat,
		&mode, &enc.version, &enc.memory, &enc.time, &enc.parallelism, &salt, &key)
	if err != nil {
		return nil, fmt.Errorf("argon2 decode: %w", err)
	}

	enc.mode, err = parseMode(mode)
	if err != nil {
		return nil, err
	}

	enc.salt, err = base64.RawStdEncoding.Strict().DecodeString(salt)
	if err != nil {
		return nil, fmt.Errorf("argon2 decode salt: %w", err)
	}

	enc.key, err = base64.RawStdEncoding.Strict().DecodeString(key)
	if err != nil {
		return nil, fmt.Errorf("argon2 decode key: %w", err)
	}

	return &enc, nil
}
