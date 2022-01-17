// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build gc && !purego
// +build gc,!purego

package blake2b

import (
	"runtime"

	"golang.org/x/sys/cpu"
)

func init() {
	useNEON = runtime.GOOS == "darwin" || cpu.ARM64.HasSHA3
}

//go:noescape
func hashBlocksNEON(h *[8]uint64, c *[2]uint64, flag uint64, blocks []byte)

func hashBlocks(h *[8]uint64, c *[2]uint64, flag uint64, blocks []byte) {
	if useNEON {
		hashBlocksNEON(h, c, flag, blocks)
	} else {
		hashBlocksGeneric(h, c, flag, blocks)
	}
}
