// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package test

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/testdata"
)

func TestSSHCLIAuth(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping test that executes OpenSSH in -short mode")
	}
	sshCLI := os.Getenv("SSH_CLI_PATH")
	if sshCLI == "" {
		sshCLI = "ssh"
	}
	var err error
	sshCLI, err = exec.LookPath("ssh")
	if err != nil {
		t.Skipf("Can't find an ssh(1) client to test against: %v", err)
	}

	dir := t.TempDir()

	keyPrivPath := filepath.Join(dir, "rsa")
	keyPubPath := filepath.Join(dir, "rsa.pub")
	if err := os.WriteFile(keyPrivPath, testdata.PEMBytes["rsa"], 0600); err != nil {
		t.Fatalf("WriteFile(%q): %v", keyPrivPath, err)
	}
	if err := os.WriteFile(keyPubPath, ssh.MarshalAuthorizedKey(testPublicKeys["rsa"]), 0644); err != nil {
		t.Fatalf("WriteFile(%q): %v", keyPubPath, err)
	}

	certChecker := ssh.CertChecker{
		IsUserAuthority: func(k ssh.PublicKey) bool {
			return bytes.Equal(k.Marshal(), testPublicKeys["ca"].Marshal())
		},
		UserKeyFallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if conn.User() == "testpubkey" && bytes.Equal(key.Marshal(), testPublicKeys["rsa"].Marshal()) {
				return nil, nil
			}

			return nil, fmt.Errorf("pubkey for %q not acceptable", conn.User())
		},
	}

	config := &ssh.ServerConfig{
		PublicKeyCallback: certChecker.Authenticate,
	}
	config.AddHostKey(testSigners["rsa"])

	server, port, err := newTestServer(config)
	if err != nil {
		t.Fatalf("unable to start test server: %v", err)
	}
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// test public key authentication.
	cmd := exec.CommandContext(ctx, sshCLI, "-vvv", "-i", keyPrivPath, "-o", "StrictHostKeyChecking=no",
		"-p", port, "testpubkey@127.0.0.1", "true")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("public key authentication failed, error: %v, command output %q", err, string(out))
	}
	// test SSH user certificate authentication.
	userCertPath := filepath.Join(dir, "rsa-cert.pub")
	err = os.WriteFile(userCertPath, testdata.SSHCertificates["rsa-user-testcertificate"], 0644)
	if err != nil {
		t.Fatal(err)
	}
	// the username must match one of the principals included in the certificate.
	// The above certificate has "testcertificate" as principal.
	cmd = exec.CommandContext(ctx, sshCLI, "-vvv", "-i", keyPrivPath, "-o", "StrictHostKeyChecking=no",
		"-p", port, "testcertificate@127.0.0.1", "true")
	out, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("user certificate authentication failed, error: %v, command output %q", err, string(out))
	}
}
