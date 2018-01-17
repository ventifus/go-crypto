// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Tests for ssh client multi-auth
//
// These tests run a simple go ssh client against OpenSSH server
// over unix domain sockets. The tests use multiple combinations
// of password, keyboard-interactive and publickey authentication
// methods.
//
// A wrapper library for making sshd PAM authentication use test
// passwords is required in ./sshd_test_pw.so. If the library does
// not exist these tests will be skipped. See compile instructions
// (for linux) in file ./sshd_test_pw.c.

package test

import (
	"fmt"
	"testing"

	"golang.org/x/crypto/ssh"
)

// test context
type MultiAuthTestCtx struct {
	password                        string
	numPasswordCallbacks            int
	numKeyboardInteractiveCallbacks int
}

// reset test context
func (ctx *MultiAuthTestCtx) reset(t *testing.T) {
	ctx.numPasswordCallbacks = 0
	ctx.numKeyboardInteractiveCallbacks = 0

	var err error
	ctx.password, err = randomPassword()
	if err != nil {
		t.Fatal(fmt.Errorf("Failed to generate random test password: %s", err.Error()))
	}
}

// password callback
func (ctx *MultiAuthTestCtx) passwordCallback() (secret string, err error) {
	ctx.numPasswordCallbacks++
	return ctx.password, nil
}

// keyboard-interactive callback
func (ctx *MultiAuthTestCtx) keyboardInteractiveCallback(user, instruction string, questions []string, echos []bool) (answers []string, err error) {

	if len(questions) == 0 {
		return []string{}, nil
	}

	ctx.numKeyboardInteractiveCallbacks++
	if len(questions) == 1 {
		return []string{ctx.password}, nil
	}

	answers = make([]string, len(questions))
	return answers, fmt.Errorf("unsupported keyboard-interactive flow")
}

// TestMultiAuthPasswordPublicKey tests ssh client multi-auth using authentication methods password,publickey
func TestMultiAuthPasswordPublicKey(t *testing.T) {

	var ctx MultiAuthTestCtx
	ctx.reset(t)

	server := newServerForConfig(t, "MultiAuth", map[string]string{"AuthMethods": "password,publickey"})
	defer server.Shutdown()

	clientConfig := clientConfig()
	server.setTestPassword(clientConfig.User, ctx.password)

	clientConfig.Auth = append([]ssh.AuthMethod{ssh.RetryableAuthMethod(ssh.PasswordCallback(func() (string, error) {
		return ctx.passwordCallback()
	}), 5)},
		clientConfig.Auth[0])

	conn := server.Dial(clientConfig)
	defer conn.Close()

	if ctx.numPasswordCallbacks != 1 {
		t.Fatal(fmt.Errorf("passwordCallback was unexpected called %d times", ctx.numPasswordCallbacks))
	}
}

// TestMultiAuthPasswordPublicKey tests ssh client multi-auth using authentication methods keyboard-interactive,publickey
func TestMultiAuthKeyboardInteractivePublicKey(t *testing.T) {

	var ctx MultiAuthTestCtx
	ctx.reset(t)

	server := newServerForConfig(t, "MultiAuth", map[string]string{"AuthMethods": "keyboard-interactive,publickey"})
	defer server.Shutdown()

	clientConfig := clientConfig()
	server.setTestPassword(clientConfig.User, ctx.password)

	clientConfig.Auth = append([]ssh.AuthMethod{ssh.RetryableAuthMethod(ssh.KeyboardInteractive(func(u, i string, q []string, e []bool) ([]string, error) {
		return ctx.keyboardInteractiveCallback(u, i, q, e)
	}), 5)},
		clientConfig.Auth[0])

	conn := server.Dial(clientConfig)
	defer conn.Close()

	if ctx.numKeyboardInteractiveCallbacks != 1 {
		t.Fatal(fmt.Errorf("keyboardInteractiveCallback was unexpectedly called %d times", ctx.numKeyboardInteractiveCallbacks))
	}
}

// TestMultiAuthPasswordPublicKey tests ssh client multi-auth using authentication methods publickey,password
func TestMultiAuthPublicKeyPassword(t *testing.T) {

	var ctx MultiAuthTestCtx
	ctx.reset(t)

	server := newServerForConfig(t, "MultiAuth", map[string]string{"AuthMethods": "publickey,password"})
	defer server.Shutdown()

	clientConfig := clientConfig()
	server.setTestPassword(clientConfig.User, ctx.password)

	clientConfig.Auth = append(clientConfig.Auth,
		ssh.RetryableAuthMethod(ssh.PasswordCallback(func() (string, error) {
			return ctx.passwordCallback()
		}), 5))

	conn := server.Dial(clientConfig)
	defer conn.Close()

	if ctx.numPasswordCallbacks != 1 {
		t.Fatal(fmt.Errorf("passwordCallback was unexpectedly called %d times", ctx.numPasswordCallbacks))
	}
}

// TestMultiAuthPasswordPublicKey tests ssh client multi-auth using authentication methods publickey,keyboard-interactive
func TestMultiAuthPublicKeyKeyboardInteractive(t *testing.T) {

	var ctx MultiAuthTestCtx
	ctx.reset(t)

	server := newServerForConfig(t, "MultiAuth", map[string]string{"AuthMethods": "publickey,keyboard-interactive"})
	defer server.Shutdown()

	clientConfig := clientConfig()
	server.setTestPassword(clientConfig.User, ctx.password)

	clientConfig.Auth = append(clientConfig.Auth,
		ssh.RetryableAuthMethod(ssh.KeyboardInteractive(func(u, i string, q []string, e []bool) ([]string, error) {
			return ctx.keyboardInteractiveCallback(u, i, q, e)
		}), 5))

	conn := server.Dial(clientConfig)
	defer conn.Close()

	if ctx.numKeyboardInteractiveCallbacks != 1 {
		t.Fatal(fmt.Errorf("keyboardInteractiveCallback was unexpectedly called %d times", ctx.numKeyboardInteractiveCallbacks))
	}
}

// TestMultiAuthPasswordPassword tests ssh client multi-auth using authentication methods password,password
// While this is not very rational configuration this does test the internal book keeping of used authentication
// methods in clientAuthenticate().
func TestMultiAuthPasswordPassword(t *testing.T) {

	var ctx MultiAuthTestCtx
	ctx.reset(t)

	server := newServerForConfig(t, "MultiAuth", map[string]string{"AuthMethods": "password,password"})
	defer server.Shutdown()

	clientConfig := clientConfig()
	server.setTestPassword(clientConfig.User, ctx.password)

	clientConfig.Auth = append([]ssh.AuthMethod{ssh.RetryableAuthMethod(ssh.PasswordCallback(func() (string, error) {
		return ctx.passwordCallback()
	}), 5)})

	conn := server.Dial(clientConfig)
	defer conn.Close()

	if ctx.numPasswordCallbacks != 2 {
		t.Fatal(fmt.Errorf("passwordCallback was unexpectedly called %d times", ctx.numPasswordCallbacks))
	}
}
