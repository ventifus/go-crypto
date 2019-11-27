// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package wycheproof runs a set of the Wycheproof tests
// provided by https://github.com/google/wycheproof.
package wycheproof

import (
	"crypto"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

var wycheproofTestVectorsDir string

const wycheproofModVer = "v0.0.0-20191126014559-06e5e105eeb9"

func TestMain(m *testing.M) {
	// Download the JSON test files from github.com/google/wycheproof
	// using `go mod download -json` so the cached source of the testdata
	// can be used in the following tests.
	path := fmt.Sprintf("github.com/google/wycheproof@%s", wycheproofModVer)
	cmd := exec.Command("go", "mod", "download", "-json", path)
	output, err := cmd.Output()
	if err != nil {
		log.Fatalf("failed to run %q, output: %s", cmd.String(), output)
	}
	type downloadModule struct {
		Path     string // module path
		Version  string // module version
		Error    string // error loading module
		Info     string // absolute path to cached .info file
		GoMod    string // absolute path to cached .mod file
		Zip      string // absolute path to cached .zip file
		Dir      string // absolute path to cached source root directory
		Sum      string // checksum for path, version (as in go.sum)
		GoModSum string // checksum for go.mod (as in go.sum)
	}
	dm := &downloadModule{}
	if err := json.Unmarshal(output, dm); err != nil {
		log.Fatal(err)
	}

	// Now that the module has been downloaded, use the absolute path of the
	// cached source as the root directory for all tests going forward
	wycheproofTestVectorsDir = filepath.Join(dm.Dir, "testvectors")

	os.Exit(m.Run())
}

func readTestVector(f string) []byte {
	b, err := ioutil.ReadFile(filepath.Join(wycheproofTestVectorsDir, f))
	if err != nil {
		panic(fmt.Sprintf("failed to read json file: %v", err))
	}
	return b
}

func decodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func decodeKey(der string) interface{} {
	d := decodeHex(der)
	pub, err := x509.ParsePKIXPublicKey(d)
	if err != nil {
		panic(fmt.Sprintf("failed to parse DER encoded public key: %v", err))
	}
	return pub
}

func parseHash(h string) (hash.Hash, crypto.Hash) {
	switch h {
	case "SHA-1":
		return sha1.New(), crypto.SHA1
	case "SHA-256":
		return sha256.New(), crypto.SHA256
	case "SHA-224":
		return sha256.New224(), crypto.SHA224
	case "SHA-384":
		return sha512.New384(), crypto.SHA384
	case "SHA-512":
		return sha512.New(), crypto.SHA512
	case "SHA-512/224":
		return sha512.New512_224(), crypto.SHA512_224
	case "SHA-512/256":
		return sha512.New512_256(), crypto.SHA512_256
	default:
		panic(fmt.Sprintf("could not identify SHA hash algorithm: %q", h))
	}
}

func shouldPass(result string, flags []string, flagsShouldPass map[string]bool) bool {
	switch result {
	case "valid":
		return true
	case "invalid":
		return false
	case "acceptable":
		for _, flag := range flags {
			pass, ok := flagsShouldPass[flag]
			if !ok {
				panic(fmt.Sprintf("unspecified flag: %q", flag))
			}
			if !pass {
				return false
			}
		}
		return true // There are no flags, or all are meant to pass.
	default:
		panic(fmt.Sprintf("unexpected result: %v", result))
	}
}
