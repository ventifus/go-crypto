// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Tests for ssh client multi-auth
//
// These tests run a simple go ssh client against OpenSSH server
// over unix domain sockets.
//
// The OpenSSH server validates passwords against PAM and therefore
// these tests must be run as root.
//
// All tests in this file require a username and password. The
// username must be given as command line argument '-user'. If no
// username is given the tests will be skipped.
//
// The password may be given as command line argument '-password'.
// If no password is given it will be prompted interactively.
//
// To run multi-auth tests:
// sudo go test -v -run TestMultiAuth.* -args -user sami

package test

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
)

// command line args
var multiAuthUser = flag.String("user", "", "username in multi-auth tests")
var multiAuthPassword = flag.String("password", "", "password in multi-auth tests")

// user input
func promptPasswordSafe(prompt string) (string, error) {
	fmt.Print(prompt)
	f, err := os.Open("/dev/tty")
	if err != nil {
		return "", err
	}
	fd := f.Fd()
	bytePassword, err := terminal.ReadPassword(int(fd))
	if err != nil {
		return "", err
	}
	fmt.Print("\n")
	return strings.TrimRight(string(bytePassword), "\n"), nil
}

// reset test data
var password string

func reset(t *testing.T, user string) {
	numPasswordCallbacks = 0
	numKeyboardInteractiveCallbacks = 0

	if multiAuthPassword != nil && len(*multiAuthPassword) > 0 {
		password = *multiAuthPassword
	} else if password == "" {
		var err error
		password, err = promptPasswordSafe(fmt.Sprintf("Logging in as %s\nPassword: ", user))
		if err != nil || password == "" {
			t.Fatal(fmt.Errorf("Failed to read password: %s", err.Error()))
		}
	}
}

// password callback
var numPasswordCallbacks int

func passwordCallback() (secret string, err error) {
	numPasswordCallbacks++
	return password, nil
}

// keyboard-interactive callback
var numKeyboardInteractiveCallbacks int

func keyboardInteractiveCallback(user, instruction string, questions []string, echos []bool) (answers []string, err error) {

	if len(questions) == 0 {
		return []string{}, nil
	}

	numKeyboardInteractiveCallbacks++
	if len(questions) == 1 {
		return []string{password}, nil
	}

	answers = make([]string, len(questions))
	return answers, fmt.Errorf("unsupported keyboard-interactive flow")
}

// TestMultiAuthPasswordPublicKey tests ssh client multi-auth using authentication methods password,publickey
func TestMultiAuthPasswordPublicKey(t *testing.T) {

	if multiAuthUser == nil || len(*multiAuthUser) == 0 {
		t.Skip("user not specified")
	}

	server := newServerForConfig(t, "MultiAuth", map[string]string{"AuthMethods": "password,publickey"}, false)
	defer server.Shutdown()

	clientConfig := clientConfig()
	clientConfig.User = *multiAuthUser

	reset(t, clientConfig.User)

	clientConfig.Auth = append([]ssh.AuthMethod{ssh.RetryableAuthMethod(ssh.PasswordCallback(passwordCallback), 5)},
		clientConfig.Auth[0])

	conn := server.Dial(clientConfig)
	defer conn.Close()

	if numPasswordCallbacks > 1 {
		t.Fatal(fmt.Errorf("passwordCallback was called %d times due to incorrect password specified or a bug in client_auth.go",
			numPasswordCallbacks))
	}
}

// TestMultiAuthPasswordPublicKey tests ssh client multi-auth using authentication methods keyboard-interactive,publickey
func TestMultiAuthKeyboardInteractivePublicKey(t *testing.T) {

	if multiAuthUser == nil || len(*multiAuthUser) == 0 {
		t.Skip("user not specified")
	}

	server := newServerForConfig(t, "MultiAuth", map[string]string{"AuthMethods": "keyboard-interactive,publickey"}, false)
	defer server.Shutdown()

	clientConfig := clientConfig()
	clientConfig.User = *multiAuthUser

	reset(t, clientConfig.User)

	clientConfig.Auth = append([]ssh.AuthMethod{ssh.RetryableAuthMethod(ssh.KeyboardInteractive(keyboardInteractiveCallback), 5)},
		clientConfig.Auth[0])

	conn := server.Dial(clientConfig)
	defer conn.Close()

	if numKeyboardInteractiveCallbacks > 1 {
		t.Fatal(fmt.Errorf("keyboardInteractiveCallback was called %d times due to incorrect password specified or a bug in client_auth.go",
			numKeyboardInteractiveCallbacks))
	}
}

// TestMultiAuthPasswordPublicKey tests ssh client multi-auth using authentication methods publickey,password
func TestMultiAuthPublicKeyPassword(t *testing.T) {

	if multiAuthUser == nil || len(*multiAuthUser) == 0 {
		t.Skip("user not specified")
	}

	server := newServerForConfig(t, "MultiAuth", map[string]string{"AuthMethods": "publickey,password"}, false)
	defer server.Shutdown()

	clientConfig := clientConfig()
	clientConfig.User = *multiAuthUser

	reset(t, clientConfig.User)

	clientConfig.Auth = append(clientConfig.Auth,
		ssh.RetryableAuthMethod(ssh.PasswordCallback(passwordCallback), 5))

	conn := server.Dial(clientConfig)
	defer conn.Close()

	if numPasswordCallbacks > 1 {
		t.Fatal(fmt.Errorf("passwordCallback was called %d times due to incorrect password specified or a bug in client_auth.go",
			numPasswordCallbacks))
	}
}

// TestMultiAuthPasswordPublicKey tests ssh client multi-auth using authentication methods publickey,keyboard-interactive
func TestMultiAuthPublicKeyKeyboardInteractive(t *testing.T) {

	if multiAuthUser == nil || len(*multiAuthUser) == 0 {
		t.Skip("user not specified")
	}

	server := newServerForConfig(t, "MultiAuth", map[string]string{"AuthMethods": "publickey,keyboard-interactive"}, false)
	defer server.Shutdown()

	clientConfig := clientConfig()
	clientConfig.User = *multiAuthUser

	reset(t, clientConfig.User)

	clientConfig.Auth = append(clientConfig.Auth,
		ssh.RetryableAuthMethod(ssh.KeyboardInteractive(keyboardInteractiveCallback), 5))

	conn := server.Dial(clientConfig)
	defer conn.Close()

	if numKeyboardInteractiveCallbacks > 1 {
		t.Fatal(fmt.Errorf("keyboardInteractiveCallback was called %d times due to incorrect password specified or a bug in client_auth.go",
			numKeyboardInteractiveCallbacks))
	}
}
