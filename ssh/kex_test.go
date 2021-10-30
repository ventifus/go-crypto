// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

// Key exchange tests.

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log"
	"reflect"
	"sync"
	"testing"
)

// Runs multiple key exchanges concurrent to detect potential data races with
// kex obtained from the global kexAlgoMap.
// This test needs to be executed using the race detector in order to detect
// race conditions.
func TestKexes(t *testing.T) {
	type kexResultErr struct {
		result *kexResult
		err    error
	}

	for name, kex := range kexAlgoMap {
		t.Run(name, func(t *testing.T) {
			wg := sync.WaitGroup{}
			for i := 0; i < 3; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					a, b := memPipe()

					s := make(chan kexResultErr, 1)
					c := make(chan kexResultErr, 1)
					var magics handshakeMagics
					go func() {
						r, e := kex.Client(a, rand.Reader, &magics)
						a.Close()
						c <- kexResultErr{r, e}
					}()
					go func() {
						r, e := kex.Server(b, rand.Reader, &magics, testSigners["ecdsa"])
						b.Close()
						s <- kexResultErr{r, e}
					}()

					clientRes := <-c
					serverRes := <-s
					if clientRes.err != nil {
						t.Errorf("client: %v", clientRes.err)
					}
					if serverRes.err != nil {
						t.Errorf("server: %v", serverRes.err)
					}
					if !reflect.DeepEqual(clientRes.result, serverRes.result) {
						t.Errorf("kex %q: mismatch %#v, %#v", name, clientRes.result, serverRes.result)
					}
				}()
			}
			wg.Wait()
		})
	}
}

func TestParseRawPrivateKeyWithPassphraseSupportsPKCS8EncryptedKeys(t *testing.T) {
	// make a test key and convert it to an encrypted pem block
	pk, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		log.Fatal(err)
	}

	const encPassword = "mypassword"

	x509Enc, _ := x509.MarshalPKCS8PrivateKey(pk)
	eb, err := x509.EncryptPEMBlock(rand.Reader, "PRIVATE KEY", x509Enc, []byte(encPassword), x509.PEMCipherAES256)
	if err != nil {
		t.Fatal(err)
	}
	pemKeyEnc := pem.EncodeToMemory(eb)

	// Parsing the encrypted key
	pkEncrypt, err := ParseRawPrivateKeyWithPassphrase(pemKeyEnc, []byte(encPassword))
	if err != nil {
		log.Fatal(err)
	}

	shouldKey := pk.D
	isKey := pkEncrypt.(*rsa.PrivateKey).D

	if shouldKey.Cmp(isKey) != 0 {
		t.Errorf("decrypted private key differs:\nis:     %v\nshould: %v", isKey, shouldKey)
	}
}
