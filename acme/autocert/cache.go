// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package autocert

import (
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
)

// ErrCacheMiss is returned when a certificate is not found in cache.
var ErrCacheMiss = errors.New("certificate cache miss")

// Cache is used by Manager to store and retrieve previously obtained certificates.
type Cache interface {
	// Get returns a public/private key pair for the specified domain name.
	// If the certificate is not cached, Get returns ErrCacheMiss.
	Get(name string) (public, private []byte, err error)

	// Put stores the public/private key pair in the cache under the specified domain name.
	// Inderlying implementations may use any data storage format,
	// as long as the reverse operation, Get, results in the original format.
	Put(name string, public, private []byte) error

	// Delete removes public/private key pair from the cache.
	Delete(name string) error
}

// DirCache implements Cache using a directory on the local filesystem.
type DirCache string

// Get reads public/private key pair from a pair of files matching the name,
// with file extensions .crt and .key, respectively.
// It does not guess data format and returns bytes as read from the files.
func (d DirCache) Get(name string) (public, private []byte, err error) {
	files := []string{
		filepath.Join(string(d), name+".crt"),
		filepath.Join(string(d), name+".key"),
	}
	b := make([][]byte, 2)
	for i, f := range files {
		var err error
		if b[i], err = ioutil.ReadFile(f); err != nil {
			if os.IsNotExist(err) {
				err = ErrCacheMiss
			}
			return nil, nil, err
		}
	}
	return b[0], b[1], nil
}

// Put writes the public/private key pair to a pair of files matching the name,
// with file extensions .crt and .key, respectively.
// It does not format or convert data for writing and uses provided bytes as is.
func (d DirCache) Put(name string, public, private []byte) error {
	if err := os.MkdirAll(string(d), 0700); err != nil {
		return err
	}
	pub := filepath.Join(string(d), name+".crt")
	if err := ioutil.WriteFile(pub, public, 0644); err != nil {
		return err
	}
	prv := filepath.Join(string(d), name+".key")
	return ioutil.WriteFile(prv, private, 0600)
}

// Delete removes a pair of files which would be used by d.Put with the given name.
func (d DirCache) Delete(name string) error {
	prv := filepath.Join(string(d), name+".key")
	pub := filepath.Join(string(d), name+".crt")
	err := os.RemoveAll(prv)
	if err1 := os.RemoveAll(pub); err1 != nil {
		if err == nil {
			err = err1
		}
	}
	return err
}
