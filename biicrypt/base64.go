// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package biicrypt

import (
	"encoding/base64"
)

func base64Encode(src []byte) []byte {
	n := base64.StdEncoding.EncodedLen(len(src))
	dst := make([]byte, n)
	base64.StdEncoding.Encode(dst, src)
	for dst[n-1] == '=' {
		n--
	}
	return dst[:n]
}

func base64Decode(src []byte) ([]byte, error) {
	numOfEquals := 4 - (len(src) % 4)
	for i := 0; i < numOfEquals; i++ {
		src = append(src, '=')
	}

	dst := make([]byte, base64.StdEncoding.DecodedLen(len(src)))
	n, err := base64.StdEncoding.Decode(dst, src)
	if err != nil {
		return nil, err
	}
	return dst[:n], nil
}

// This function is used to decode hashes previously encoded with the
// legacy encoding. It should not serve any other purpose.
func reEncodeFromLegacy(src []byte) ([]byte, error) {

	unencoded, err := legacyDecoder(src)
	if err != nil {
		return nil, err
	}

	encodedValue := base64Encode(unencoded)
	return encodedValue, nil
}

// Decoder taken from crypto/bcrypt.
func legacyDecoder(src []byte) ([]byte, error) {

	const alphabet = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

	var bcEncoding = base64.NewEncoding(alphabet)

	numOfEquals := 4 - (len(src) % 4)
	for i := 0; i < numOfEquals; i++ {
		src = append(src, '=')
	}

	dst := make([]byte, bcEncoding.DecodedLen(len(src)))
	n, err := bcEncoding.Decode(dst, src)
	if err != nil {
		return nil, err
	}
	return dst[:n], nil
}
