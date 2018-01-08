// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"net"
	"strings"
	"testing"
)

func TestClientVersion(t *testing.T) {
	for _, tt := range []struct {
		version    string
		expected   string
		fakeClient bool
	}{
		{
			version:  packageVersion,
			expected: packageVersion,
		},
		{
			version:  "SSH-2.0-CustomClientVersionString",
			expected: "SSH-2.0-CustomClientVersionString",
		},
		{
			version:    "ignored\r\n" + packageVersion,
			expected:   packageVersion,
			fakeClient: true,
		},
		{
			version:    "ignored\n" + packageVersion,
			expected:   packageVersion,
			fakeClient: true,
		},
	} {
		t.Run(tt.version, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			defer clientConn.Close()
			receivedVersion := make(chan string, 1)
			config := &ClientConfig{
				ClientVersion:   tt.version,
				HostKeyCallback: InsecureIgnoreHostKey(),
			}
			go func() {
				version, err := readVersion(serverConn)
				if err != nil {
					receivedVersion <- err.Error()
				} else {
					receivedVersion <- string(version)
				}
				serverConn.Close()
			}()
			if tt.fakeClient {
				// To test the handling of multi-line versions, we can't use
				// NewClientConn since they aren't allowed there. Instead, we
				// can just send the multi-line version on the conn directly.
				clientConn.Write([]byte(tt.version + "\r\n"))
			} else {
				NewClientConn(clientConn, "", config)
			}
			actual := <-receivedVersion
			if actual != tt.expected {
				t.Fatalf("got %s; want %s", actual, tt.expected)
			}
		})
	}
}

func TestHostKeyCheck(t *testing.T) {
	for _, tt := range []struct {
		name      string
		wantError string
		key       PublicKey
	}{
		{"no callback", "must specify HostKeyCallback", nil},
		{"correct key", "", testSigners["rsa"].PublicKey()},
		{"mismatch", "mismatch", testSigners["ecdsa"].PublicKey()},
	} {
		c1, c2, err := netPipe()
		if err != nil {
			t.Fatalf("netPipe: %v", err)
		}
		defer c1.Close()
		defer c2.Close()
		serverConf := &ServerConfig{
			NoClientAuth: true,
		}
		serverConf.AddHostKey(testSigners["rsa"])

		go NewServerConn(c1, serverConf)
		clientConf := ClientConfig{
			User: "user",
		}
		if tt.key != nil {
			clientConf.HostKeyCallback = FixedHostKey(tt.key)
		}

		_, _, _, err = NewClientConn(c2, "", &clientConf)
		if err != nil {
			if tt.wantError == "" || !strings.Contains(err.Error(), tt.wantError) {
				t.Errorf("%s: got error %q, missing %q", tt.name, err.Error(), tt.wantError)
			}
		} else if tt.wantError != "" {
			t.Errorf("%s: succeeded, but want error string %q", tt.name, tt.wantError)
		}
	}
}

func TestBannerCallback(t *testing.T) {
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
		BannerCallback: func(conn ConnMetadata) string {
			return "Hello World"
		},
	}
	serverConf.AddHostKey(testSigners["rsa"])
	go NewServerConn(c1, serverConf)

	var receivedBanner string
	var bannerCount int
	clientConf := ClientConfig{
		Auth: []AuthMethod{
			Password("123"),
		},
		User:            "user",
		HostKeyCallback: InsecureIgnoreHostKey(),
		BannerCallback: func(message string) error {
			bannerCount++
			receivedBanner = message
			return nil
		},
	}

	_, _, _, err = NewClientConn(c2, "", &clientConf)
	if err != nil {
		t.Fatal(err)
	}

	if bannerCount != 1 {
		t.Errorf("got %d banners; want 1", bannerCount)
	}

	expected := "Hello World"
	if receivedBanner != expected {
		t.Fatalf("got %s; want %s", receivedBanner, expected)
	}
}
