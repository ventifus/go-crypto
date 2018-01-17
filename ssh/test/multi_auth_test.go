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
type multiAuthTestCtx struct {
	password     string
	numPwCbs     int
	numKbdIntCbs int

	authMethods          string
	numExpectedPwCbs     int
	numExpectedKbdIntCbs int
}

// create test context
func newMultiAuthTestCtx(t *testing.T, authMethods string, numExpectedPwCbs, numExpectedKbdIntCbs int) *multiAuthTestCtx {
	password, err := randomPassword()
	if err != nil {
		t.Fatalf("Failed to generate random test password: %s", err.Error())
	}

	return &multiAuthTestCtx{
		password:             password,
		numPwCbs:             0,
		numKbdIntCbs:         0,
		numExpectedPwCbs:     numExpectedPwCbs,
		numExpectedKbdIntCbs: numExpectedKbdIntCbs,
		authMethods:          authMethods,
	}
}

// password callback
func (ctx *multiAuthTestCtx) pwCb() (secret string, err error) {
	ctx.numPwCbs++
	return ctx.password, nil
}

// keyboard-interactive callback
func (ctx *multiAuthTestCtx) kbdIntCb(user, instruction string, questions []string, echos []bool) (answers []string, err error) {
	if len(questions) == 0 {
		return nil, nil
	}

	ctx.numKbdIntCbs++
	if len(questions) == 1 {
		return []string{ctx.password}, nil
	}

	return nil, fmt.Errorf("unsupported keyboard-interactive flow")
}

// TestMultiAuth runs several subtests for different combinations of password, keyboard-interactive and publickey authentication methods
func TestMultiAuth(t *testing.T) {
	testContexts := []*multiAuthTestCtx{
		// Test password,publickey authentication, assert that password callback is called 1 time
		newMultiAuthTestCtx(t, "password,publickey", 1, 0),
		// Test keyboard-interactive,publickey authentication, assert that keyboard-interactive callback is called 1 time
		newMultiAuthTestCtx(t, "keyboard-interactive,publickey", 0, 1),
		// Test publickey,password authentication, assert that password callback is called 1 time
		newMultiAuthTestCtx(t, "publickey,password", 1, 0),
		// Test publickey,keyboard-interactive authentication, assert that keyboard-interactive callback is called 1 time
		newMultiAuthTestCtx(t, "publickey,keyboard-interactive", 0, 1),
		// Test password,password authentication, assert that password callback is called 2 times
		newMultiAuthTestCtx(t, "password,password", 2, 0),
	}

	for _, ctx := range testContexts {
		t.Run(ctx.authMethods, func(t *testing.T) {
			server := newServerForConfig(t, "MultiAuth", map[string]string{"AuthMethods": ctx.authMethods})
			defer server.Shutdown()

			clientConfig := clientConfig()
			server.setTestPassword(clientConfig.User, ctx.password)

			switch ctx.authMethods {
			case "password,publickey":
				clientConfig.Auth = append([]ssh.AuthMethod{ssh.RetryableAuthMethod(ssh.PasswordCallback(ctx.pwCb), 5)},
					clientConfig.Auth[0])

			case "keyboard-interactive,publickey":
				clientConfig.Auth = append([]ssh.AuthMethod{ssh.RetryableAuthMethod(ssh.KeyboardInteractive(ctx.kbdIntCb), 5)},
					clientConfig.Auth[0])

			case "publickey,password":
				clientConfig.Auth = append(clientConfig.Auth,
					ssh.RetryableAuthMethod(ssh.PasswordCallback(ctx.pwCb), 5))

			case "publickey,keyboard-interactive":
				clientConfig.Auth = append(clientConfig.Auth,
					ssh.RetryableAuthMethod(ssh.KeyboardInteractive(ctx.kbdIntCb), 5))

			case "password,password":
				clientConfig.Auth = []ssh.AuthMethod{ssh.RetryableAuthMethod(ssh.PasswordCallback(ctx.pwCb), 5)}

			default:
				t.Fatalf("Unknown authentication method %s", ctx.authMethods)
			}

			conn := server.Dial(clientConfig)
			defer conn.Close()

			if ctx.numPwCbs != ctx.numExpectedPwCbs {
				t.Fatalf("passwordCallback was called %d times, expected %d times", ctx.numPwCbs, ctx.numExpectedPwCbs)
			}

			if ctx.numKbdIntCbs != ctx.numExpectedKbdIntCbs {
				t.Fatalf("keyboardInteractiveCallback was called %d times, expected %d times", ctx.numKbdIntCbs, ctx.numExpectedKbdIntCbs)
			}

		})
	}
}
