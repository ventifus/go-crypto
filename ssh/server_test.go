// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestClientAuthRestrictedPublicKeyAlgos(t *testing.T) {
	for _, tt := range []struct {
		name      string
		key       Signer
		wantError bool
	}{
		{"rsa", testSigners["rsa"], false},
		{"dsa", testSigners["dsa"], true},
		{"ed25519", testSigners["ed25519"], true},
	} {
		c1, c2, err := netPipe()
		if err != nil {
			t.Fatalf("netPipe: %v", err)
		}
		defer c1.Close()
		defer c2.Close()
		serverConf := &ServerConfig{
			PublicKeyAuthAlgorithms: []string{KeyAlgoRSASHA256, KeyAlgoRSASHA512},
			PublicKeyCallback: func(conn ConnMetadata, key PublicKey) (*Permissions, error) {
				return nil, nil
			},
		}
		serverConf.AddHostKey(testSigners["ecdsap256"])

		done := make(chan struct{})
		go func() {
			defer close(done)
			NewServerConn(c1, serverConf)
		}()

		clientConf := ClientConfig{
			User: "user",
			Auth: []AuthMethod{
				PublicKeys(tt.key),
			},
			HostKeyCallback: InsecureIgnoreHostKey(),
		}

		_, _, _, err = NewClientConn(c2, "", &clientConf)
		if err != nil {
			if !tt.wantError {
				t.Errorf("%s: got unexpected error %q", tt.name, err.Error())
			}
		} else if tt.wantError {
			t.Errorf("%s: succeeded, but want error", tt.name)
		}
		<-done
	}
}

func TestHostKeyUpdateRotation(t *testing.T) {
	c1, c2, err := netPipe()
	if err != nil {
		t.Fatalf("netPipe: %v", err)
	}
	defer c1.Close()
	defer c2.Close()

	serverConf := &ServerConfig{
		PasswordCallback: func(conn ConnMetadata, password []byte) (*Permissions, error) {
			return &Permissions{}, nil
		},
	}
	mas, err := NewSignerWithAlgorithms(testSigners["rsa"].(AlgorithmSigner), []string{KeyAlgoRSASHA256, KeyAlgoRSASHA512})
	if err != nil {
		t.Fatal(err)
	}
	serverConf.AddHostKey(mas)
	serverConf.AddHostKey(testSigners["ecdsap256"])
	serverConf.AddHostKey(testSigners["ed25519"])

	var wg sync.WaitGroup

	t.Cleanup(wg.Wait)

	wg.Add(1)
	go func() {
		defer wg.Done()

		_, chans, reqs, err := NewServerConn(c1, serverConf)
		if err != nil {
			t.Errorf("server handshake: %v", err)
			return
		}
		wg.Add(1)
		go func() {
			DiscardRequests(reqs)
			wg.Done()
		}()
		// each channel request will be rejected
		for ch := range chans {
			ch.Reject(Prohibited, "")
		}
	}()

	done := make(chan struct{}, 1)

	clientConf := ClientConfig{
		Auth: []AuthMethod{
			Password("123"),
		},
		User:            "user",
		HostKeyCallback: InsecureIgnoreHostKey(),
		HostKeysUpdateCallback: func(keysUpdate []*HostKeyUpdate) {
			// Use a gouroutine to also test for races
			go func() {
				defer close(done)

				if len(keysUpdate) != 3 {
					t.Errorf("expected 3 host keys from hostkeys-00@openssh.com extension, got %d", len(keysUpdate))
				}
				for _, hostKeyUpdate := range keysUpdate {
					var expectedKey PublicKey

					switch hostKeyUpdate.KeyType() {
					case KeyAlgoRSA:
						expectedKey = testPublicKeys["rsa"]
					case KeyAlgoED25519:
						expectedKey = testPublicKeys["ed25519"]
					case KeyAlgoECDSA256:
						expectedKey = testPublicKeys["ecdsap256"]
					}

					if hostKeyUpdate.Fingerprint() != FingerprintSHA256(expectedKey) {
						t.Errorf("unexpected fingerprint for key type %q", hostKeyUpdate.KeyType())
					}
					if !hostKeyUpdate.Equal(expectedKey) {
						t.Errorf("unexpected public key for key type %q", hostKeyUpdate.KeyType())
					}
					if _, err := hostKeyUpdate.PublicKey(); err != nil {
						t.Errorf("unable to prove host key type %q: %v", hostKeyUpdate.KeyType(), err)
					}
				}
			}()
		},
		HostKeyAlgorithms: []string{KeyAlgoRSASHA512},
	}

	c, chans, reqs, err := NewClientConn(c2, "", &clientConf)
	if err != nil {
		t.Fatal(err)
	}

	client := NewClient(c, chans, reqs)
	defer client.Close()

	_, err = client.NewSession()
	if err == nil {
		t.Error("the test server should reject session requests")
	}
	// Prove an unknown host key.
	hostKeyUpdate := HostKeyUpdate{
		key:       testPublicKeys["ecdsap384"],
		sessionID: client.SessionID(),
		mux:       client.Conn.(*connection).mux,
	}
	if _, err = hostKeyUpdate.PublicKey(); err == nil {
		t.Fatal("prove for unknown host key suceeded!")
	}
	// Wait for the HostKeysUpdateCallback.
	<-done
}

func TestNewServerConnValidationErrors(t *testing.T) {
	serverConf := &ServerConfig{
		PublicKeyAuthAlgorithms: []string{CertAlgoRSAv01},
	}
	c := &markerConn{}
	_, _, _, err := NewServerConn(c, serverConf)
	if err == nil {
		t.Fatal("NewServerConn with invalid public key auth algorithms succeeded")
	}
	if !c.isClosed() {
		t.Fatal("NewServerConn with invalid public key auth algorithms left connection open")
	}
	if c.isUsed() {
		t.Fatal("NewServerConn with invalid public key auth algorithms used connection")
	}

	serverConf = &ServerConfig{
		Config: Config{
			KeyExchanges: []string{kexAlgoDHGEXSHA256},
		},
	}
	c = &markerConn{}
	_, _, _, err = NewServerConn(c, serverConf)
	if err == nil {
		t.Fatal("NewServerConn with unsupported key exchange succeeded")
	}
	if !c.isClosed() {
		t.Fatal("NewServerConn with unsupported key exchange left connection open")
	}
	if c.isUsed() {
		t.Fatal("NewServerConn with unsupported key exchange used connection")
	}
}

type markerConn struct {
	closed uint32
	used   uint32
}

func (c *markerConn) isClosed() bool {
	return atomic.LoadUint32(&c.closed) != 0
}

func (c *markerConn) isUsed() bool {
	return atomic.LoadUint32(&c.used) != 0
}

func (c *markerConn) Close() error {
	atomic.StoreUint32(&c.closed, 1)
	return nil
}

func (c *markerConn) Read(b []byte) (n int, err error) {
	atomic.StoreUint32(&c.used, 1)
	if atomic.LoadUint32(&c.closed) != 0 {
		return 0, net.ErrClosed
	} else {
		return 0, io.EOF
	}
}

func (c *markerConn) Write(b []byte) (n int, err error) {
	atomic.StoreUint32(&c.used, 1)
	if atomic.LoadUint32(&c.closed) != 0 {
		return 0, net.ErrClosed
	} else {
		return 0, io.ErrClosedPipe
	}
}

func (*markerConn) LocalAddr() net.Addr  { return nil }
func (*markerConn) RemoteAddr() net.Addr { return nil }

func (*markerConn) SetDeadline(t time.Time) error      { return nil }
func (*markerConn) SetReadDeadline(t time.Time) error  { return nil }
func (*markerConn) SetWriteDeadline(t time.Time) error { return nil }
