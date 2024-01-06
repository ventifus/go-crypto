// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !gc || purego || !s390x

package sha3

import (
	"hash"
)

func new224() hash.Hash {
	return new224Generic()
}

func new256() hash.Hash {
	return new256Generic()
}

func new384() hash.Hash {
	return new384Generic()
}

func new512() hash.Hash {
	return new512Generic()
}
