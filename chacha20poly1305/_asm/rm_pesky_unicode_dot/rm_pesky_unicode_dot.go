// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"os"
	"strings"
)

// Avo v0.6.0 does not support the generation of internal assembly functions. Go's unicode
// dot tells the compiler to link a TEXT symbol to a function in the current Go package
// (or another package if specified). Avo unconditionally prepends the unicode dot to all
// TEXT symbols, making it impossible to emit an internal function
//
// rm_pesky_unicode_dot.go strips the dot from the relevant TEXT directives such that they
// can exist as internal assembly functions
//
// There is a pending PR to add internal functions to Avo:
// https://github.com/mmcloughlin/avo/pull/443
//
// If merged it should allow the usage of InternalFunction("NAME") for the symbols found below
func main() {
	var target string
	flag.StringVar(&target, "target", "", "target file")
	flag.Parse()

	if len(target) == 0 {
		panic("no target specified")
	}

	bytes, err := os.ReadFile(target)
	if err != nil {
		panic(err)
	}

	content := string(bytes)
	replace := [][]string{
		{"·polyHashADInternal", "polyHashADInternal"},
	}

	for _, r := range replace {
		from := r[0]
		to := r[1]
		content = strings.ReplaceAll(content, from, to)
	}

	err = os.WriteFile(target, []byte(content), 0644)
	if err != nil {
		panic(err)
	}
}
