// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !js && !wasip1

package test

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestRunCommandSuccess(t *testing.T) {
	test := clientTest{
		name:   "RunCommandSuccess",
		config: recordingsClientConfig(),
		successCallback: func(t *testing.T, client *ssh.Client) {
			session, err := client.NewSession()
			if err != nil {
				t.Fatalf("session failed: %v", err)
			}
			defer session.Close()
			err = session.Run("true")
			if err != nil {
				t.Fatalf("session failed: %v", err)
			}
		},
	}

	runTestAndUpdateIfNeeded(t, test.name, test.run)
}

func TestRunCommandStdin(t *testing.T) {
	test := clientTest{
		name:   "RunCommandStdin",
		config: recordingsClientConfig(),
		successCallback: func(t *testing.T, client *ssh.Client) {
			session, err := client.NewSession()
			if err != nil {
				t.Fatalf("session failed: %v", err)
			}
			defer session.Close()

			r, w := io.Pipe()
			defer r.Close()
			defer w.Close()
			session.Stdin = r

			err = session.Run("true")
			if err != nil {
				t.Fatalf("session failed: %v", err)
			}
		},
	}

	runTestAndUpdateIfNeeded(t, test.name, test.run)
}

func TestRunCommandStdinError(t *testing.T) {
	test := clientTest{
		name:   "RunCommandStdinError",
		config: recordingsClientConfig(),
		successCallback: func(t *testing.T, client *ssh.Client) {
			session, err := client.NewSession()
			if err != nil {
				t.Fatalf("session failed: %v", err)
			}
			defer session.Close()

			r, w := io.Pipe()
			defer r.Close()
			session.Stdin = r
			pipeErr := errors.New("closing write end of pipe")
			w.CloseWithError(pipeErr)

			err = session.Run("true")
			if err != pipeErr {
				t.Fatalf("expected %v, found %v", pipeErr, err)
			}
		},
	}

	runTestAndUpdateIfNeeded(t, test.name, test.run)
}

func TestRunCommandFailed(t *testing.T) {
	test := clientTest{
		name:   "RunCommandFailed",
		config: recordingsClientConfig(),
		successCallback: func(t *testing.T, client *ssh.Client) {
			session, err := client.NewSession()
			if err != nil {
				t.Fatalf("session failed: %v", err)
			}
			defer session.Close()

			// Trigger a failure by attempting to execute a non-existent
			// command.
			err = session.Run(`non-existent command`)
			if err == nil {
				t.Fatalf("session succeeded: %v", err)
			}
		},
	}

	runTestAndUpdateIfNeeded(t, test.name, test.run)
}

func TestWindowChange(t *testing.T) {
	test := clientTest{
		name:   "WindowChange",
		config: recordingsClientConfig(),
		successCallback: func(t *testing.T, client *ssh.Client) {
			session, err := client.NewSession()
			if err != nil {
				t.Fatalf("session failed: %v", err)
			}
			defer session.Close()

			stdout, err := session.StdoutPipe()
			if err != nil {
				t.Fatalf("unable to acquire stdout pipe: %s", err)
			}

			stdin, err := session.StdinPipe()
			if err != nil {
				t.Fatalf("unable to acquire stdin pipe: %s", err)
			}

			tm := ssh.TerminalModes{ssh.ECHO: 0}
			if err = session.RequestPty("xterm", 80, 40, tm); err != nil {
				t.Fatalf("req-pty failed: %s", err)
			}

			if err := session.WindowChange(100, 100); err != nil {
				t.Fatalf("window-change failed: %s", err)
			}

			err = session.Shell()
			if err != nil {
				t.Fatalf("session failed: %s", err)
			}

			stdin.Write([]byte("stty size && exit\n"))

			var buf bytes.Buffer
			if _, err := io.Copy(&buf, stdout); err != nil {
				t.Fatalf("reading failed: %s", err)
			}

			if sttyOutput := buf.String(); !strings.Contains(sttyOutput, "100 100") {
				t.Fatalf("terminal WindowChange failure: expected \"100 100\" stty output, got %s", sttyOutput)
			}
		},
	}

	runTestAndUpdateIfNeeded(t, test.name, test.run)
}
