// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !windows

package test

// direct-streamlocal functional tests

import (
	"io"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestDialStreamLocal(t *testing.T) {
	server := newServer(t)
	defer server.Shutdown()
	sshConn := server.Dial(clientConfig())
	defer sshConn.Close()

	dir, err := ioutil.TempDir("", "streamlocal")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	addr := filepath.Join(dir, "sock")

	l, err := net.Listen("unix", addr)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer l.Close()

	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				break
			}

			io.WriteString(c, c.RemoteAddr().String())
			c.Close()
		}
	}()

	conn, err := sshConn.Dial("unix", addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
}
