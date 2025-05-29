// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !linux

package acme_test

func spawnServerProcess(_ *testing.T, _ string, _ string, _ ...string) {
	panic("pebble testing only supported on Linux")
}
