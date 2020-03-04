// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !windows,!solaris,!js

package test

import (
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
)

// Concurrent functional tests.

// This test needs to be executed using the race detector in order to be effective.
// #37607
func TestRunConcurrent(t *testing.T) {
	affectedKex := []string{"diffie-hellman-group-exchange-sha1", "diffie-hellman-group-exchange-sha256"}

	var config ssh.Config
	config.SetDefaults()
	kexOrder := config.KeyExchanges
	// Based on the discussion in #17230, the key exchange algorithms
	// diffie-hellman-group-exchange-sha1 and diffie-hellman-group-exchange-sha256
	// are not included in the default list of supported kex so we have to add them
	// here manually.
	kexOrder = append(kexOrder, affectedKex...)
	for _, kex := range affectedKex {
		t.Run(kex, func(t *testing.T) {
			wg := sync.WaitGroup{}
			for i := 0; i < 3; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					server := newServer(t)
					defer server.Shutdown()

					conf := clientConfig()
					// Don't fail if sshd doesn't have the kex.
					conf.KeyExchanges = append([]string{kex}, kexOrder...)
					conn, err := server.TryDial(conf)
					if err == nil {
						conn.Close()
					} else {
						t.Errorf("failed for kex %q", kex)
					}
				}()
			}
			wg.Wait()
		})
	}
}
