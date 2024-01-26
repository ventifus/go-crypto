// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"errors"
	"io"
	"net"
	"slices"
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

func TestBannerError(t *testing.T) {
	serverConfig := &ServerConfig{
		BannerCallback: func(ConnMetadata) string {
			return "banner from BannerCallback"
		},
		NoClientAuth: true,
		NoClientAuthCallback: func(ConnMetadata) (*Permissions, error) {
			return nil, BannerError{
				Err:     errors.New("error from NoClientAuthCallback"),
				Message: "banner from NoClientAuthCallback",
			}
		},
		PasswordCallback: func(conn ConnMetadata, password []byte) (*Permissions, error) {
			return &Permissions{}, nil
		},
		PublicKeyCallback: func(conn ConnMetadata, key PublicKey) (*Permissions, error) {
			return nil, BannerError{
				Err:     errors.New("error from PublicKeyCallback"),
				Message: "banner from PublicKeyCallback",
			}
		},
	}
	serverConfig.AddHostKey(testSigners["rsa"])

	var banners []string
	clientConfig := &ClientConfig{
		User: "test",
		Auth: []AuthMethod{
			PublicKeys(testSigners["rsa"]),
			Password(clientPassword),
		},
		HostKeyCallback: InsecureIgnoreHostKey(),
		BannerCallback: func(msg string) error {
			banners = append(banners, msg)
			return nil
		},
	}

	c1, c2, err := netPipe()
	if err != nil {
		t.Fatalf("netPipe: %v", err)
	}
	defer c1.Close()
	defer c2.Close()
	go newServer(c1, serverConfig)
	c, _, _, err := NewClientConn(c2, "", clientConfig)
	if err != nil {
		t.Fatalf("client connection failed: %v", err)
	}
	defer c.Close()

	wantBanners := []string{
		"banner from BannerCallback",
		"banner from NoClientAuthCallback",
		"banner from PublicKeyCallback",
	}
	if !slices.Equal(banners, wantBanners) {
		t.Errorf("got banners:\n%q\nwant banners:\n%q", banners, wantBanners)
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
