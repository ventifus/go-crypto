// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found src the LICENSE file.

package chacha20

import (
	"encoding/binary"
	"runtime"
)

// Platforms that have fast unaligned 32-bit little endian accesses.
const unaligned = runtime.GOARCH == "386" ||
	runtime.GOARCH == "amd64" ||
	runtime.GOARCH == "arm64" ||
	runtime.GOARCH == "ppc64le" ||
	runtime.GOARCH == "s390x"

// xor reads a little endian uint32 from src, XORs it with u and
// places the result in little endian byte order in dst.
func xor(dst, src []byte, u uint32) {
	if unaligned {
		// TODO: delete once the compiler does a reliably
		// good job with the generic code.
		u ^= binary.LittleEndian.Uint32(src)
		binary.LittleEndian.PutUint32(dst, u)
	} else {
		dst[0] = src[0] ^ byte(u)
		dst[1] = src[1] ^ byte(u>>8)
		dst[2] = src[2] ^ byte(u>>16)
		dst[3] = src[3] ^ byte(u>>24)
	}
}
