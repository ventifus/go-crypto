// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
)

func doClientServerAuth(t *testing.T, serverConfig *ServerConfig, clientConfig *ClientConfig, serverAuthErrors *[]error) error {
	c1, c2, err := netPipe()
	if err != nil {
		t.Fatalf("netPipe: %v", err)
	}
	defer c1.Close()
	defer c2.Close()

	serverConfig.AddHostKey(testSigners["rsa"])
	serverConfig.AuthLogCallback = func(conn ConnMetadata, method string, err error) {
		*serverAuthErrors = append(*serverAuthErrors, err)
	}
	go newServer(c1, serverConfig)
	_, _, _, err = NewClientConn(c2, "", clientConfig)
	return err
}

func TestMultiStepAuth(t *testing.T) {
	var serverAuthErrors []error
	// This user can login with password, public key or public key + password.
	username := "testuser"
	// This user can login with public key + password only.
	usernameSecondFactor := "testuser_second_factor"
	errPwdAuthFailed := errors.New("password auth failed")
	errWrongSequence := errors.New("wrong sequence")

	serverConfig := &ServerConfig{
		PasswordCallback: func(conn ConnMetadata, password []byte) (*Permissions, error) {
			if conn.User() == usernameSecondFactor {
				return nil, errWrongSequence
			}
			if conn.User() == username && string(password) == clientPassword {
				return nil, nil
			}
			return nil, errPwdAuthFailed
		},
		PublicKeyCallback: func(conn ConnMetadata, key PublicKey) (*Permissions, error) {
			if bytes.Equal(key.Marshal(), testPublicKeys["rsa"].Marshal()) {
				if conn.User() == usernameSecondFactor {
					return nil, &PartialSuccessError{
						PasswordCallback: func(conn ConnMetadata, password []byte) (*Permissions, error) {
							if string(password) == clientPassword {
								return nil, nil
							}
							return nil, errPwdAuthFailed
						},
					}
				}
				return nil, nil
			}
			return nil, fmt.Errorf("pubkey for %q not acceptable", conn.User())
		},
	}

	clientConfig := &ClientConfig{
		User: usernameSecondFactor,
		Auth: []AuthMethod{
			PublicKeys(testSigners["rsa"]),
			Password(clientPassword),
		},
		HostKeyCallback: InsecureIgnoreHostKey(),
	}

	err := doClientServerAuth(t, serverConfig, clientConfig, &serverAuthErrors)
	if err != nil {
		t.Fatalf("client login error: %s", err)
	}

	// the error sequence is:
	// - no auth passed yet
	// - partial success
	// - nil
	if len(serverAuthErrors) != 3 {
		t.Fatalf("unexpected number of server auth errors: %v, errors: %+v", len(serverAuthErrors), serverAuthErrors)
	}
	if !errors.Is(serverAuthErrors[1], &PartialSuccessError{}) {
		t.Fatalf("server not returned partial success: %v", serverAuthErrors)
	}
	// now test a wrong sequence
	serverAuthErrors = nil
	clientConfig.Auth = []AuthMethod{
		Password(clientPassword),
		PublicKeys(testSigners["rsa"]),
	}

	err = doClientServerAuth(t, serverConfig, clientConfig, &serverAuthErrors)
	if err == nil {
		t.Fatal("client login with wrong sequence must fail")
	}
	// the error sequence is:
	// - no auth passed yet
	// - wrong sequence
	// - partial success
	if len(serverAuthErrors) != 3 {
		t.Fatalf("unexpected number of server auth errors: %v, errors: %+v", len(serverAuthErrors), serverAuthErrors)
	}
	if serverAuthErrors[1] != errWrongSequence {
		t.Fatal("server not wrong sequence")
	}
	if !errors.Is(serverAuthErrors[2], &PartialSuccessError{}) {
		t.Fatal("server not returned partial success")
	}
	// now test using a correct sequence but a wrong password before the right one
	serverAuthErrors = nil
	n := 0
	passwords := []string{"WRONG", "WRONG", clientPassword}
	clientConfig.Auth = []AuthMethod{
		PublicKeys(testSigners["rsa"]),
		RetryableAuthMethod(PasswordCallback(func() (string, error) {
			p := passwords[n]
			n++
			return p, nil
		}), 3),
	}

	err = doClientServerAuth(t, serverConfig, clientConfig, &serverAuthErrors)
	if err != nil {
		t.Fatalf("client login error: %s", err)
	}
	// the error sequence is:
	// - no auth passed yet
	// - partial success
	// - wrong password
	// - wrong password
	// - nil
	if len(serverAuthErrors) != 5 {
		t.Fatalf("unexpected number of server auth errors: %v, errors: %+v", len(serverAuthErrors), serverAuthErrors)
	}
	if !errors.Is(serverAuthErrors[1], &PartialSuccessError{}) {
		t.Fatal("server not returned partial success")
	}
	if serverAuthErrors[2] != errPwdAuthFailed {
		t.Fatal("server not returned password authentication failed")
	}
	if serverAuthErrors[3] != errPwdAuthFailed {
		t.Fatal("server not returned password authentication failed")
	}
	// the unrestricted username can do anything
	clientConfig = &ClientConfig{
		User: username,
		Auth: []AuthMethod{
			PublicKeys(testSigners["rsa"]),
			Password(clientPassword),
		},
		HostKeyCallback: InsecureIgnoreHostKey(),
	}

	err = doClientServerAuth(t, serverConfig, clientConfig, &serverAuthErrors)
	if err != nil {
		t.Fatalf("unrestricted client login error: %s", err)
	}

	clientConfig = &ClientConfig{
		User: username,
		Auth: []AuthMethod{
			PublicKeys(testSigners["rsa"]),
		},
		HostKeyCallback: InsecureIgnoreHostKey(),
	}

	err = doClientServerAuth(t, serverConfig, clientConfig, &serverAuthErrors)
	if err != nil {
		t.Fatalf("unrestricted client login error: %s", err)
	}

	clientConfig = &ClientConfig{
		User: username,
		Auth: []AuthMethod{
			Password(clientPassword),
		},
		HostKeyCallback: InsecureIgnoreHostKey(),
	}

	err = doClientServerAuth(t, serverConfig, clientConfig, &serverAuthErrors)
	if err != nil {
		t.Fatalf("unrestricted client login error: %s", err)
	}
}
