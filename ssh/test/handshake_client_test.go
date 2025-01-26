// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package test

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/internal/testenv"
	"golang.org/x/crypto/sha3"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/testdata"
)

var (
	storeUsernameOnce sync.Once
)

type clientTest struct {
	// name is a freeform string identifying the test and the file in which
	// the expected results will be stored.
	name string
	// config contains the client configuration to use for this test.
	config *ssh.ClientConfig
}

// connFromCommand starts the reference server process, connects to it and
// returns a recordingConn for the connection. It must be closed before Waiting
// for child.
func (test *clientTest) connFromCommand(t *testing.T, config string) *recordingConn {
	sshd, err := exec.LookPath("sshd")
	if err != nil {
		t.Skipf("skipping test: %v", err)
	}
	dir, err := os.MkdirTemp("", "sshtest")
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(filepath.Join(dir, "sshd_config"))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := configTmpl[config]; ok == false {
		t.Fatal(fmt.Errorf("Invalid server config '%s'", config))
	}
	configVars := map[string]string{
		"Dir": dir,
	}
	err = configTmpl[config].Execute(f, configVars)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()

	writeFile(filepath.Join(dir, "banner"), []byte("Server Banner"))

	for k, v := range testdata.PEMBytes {
		filename := "id_" + k
		writeFile(filepath.Join(dir, filename), v)
		writeFile(filepath.Join(dir, filename+".pub"), ssh.MarshalAuthorizedKey(testPublicKeys[k]))
	}

	var authkeys bytes.Buffer
	for k := range testdata.PEMBytes {
		authkeys.Write(ssh.MarshalAuthorizedKey(testPublicKeys[k]))
	}
	writeFile(filepath.Join(dir, "authorized_keys"), authkeys.Bytes())
	// serverPort contains the port that OpenSSH will listen on. OpenSSH
	// can't take "0" as an argument here so we have to pick a number and
	// hope that it's not in use on the machine. Since this only occurs
	// when -update is given and thus when there's a human watching the
	// test, this isn't too bad.
	const serverPort = 24222
	cmd := testenv.Command(t, sshd, "-D", "-e", "-f", f.Name(), "-p", strconv.Itoa(serverPort))
	cmd.Stdin = nil
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Error(err)
		}
		// Don't check for errors; if it fails it's most
		// likely "os: process already finished", and we don't
		// care about that. Use os.Interrupt, so child
		// processes are killed too.
		cmd.Process.Signal(os.Interrupt)
		cmd.Wait()
		if t.Failed() {
			t.Logf("OpenSSH output:\n\n%s", cmd.Stdout)
		}
	})
	var tcpConn net.Conn
	for i := uint(0); i < 5; i++ {
		tcpConn, err = net.DialTCP("tcp", nil, &net.TCPAddr{
			IP:   net.IPv4(127, 0, 0, 1),
			Port: serverPort,
		})
		if err == nil {
			break
		}
		time.Sleep((1 << i) * 5 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("error connecting to the OpenSSH server: %v (%v)\n\n%s", err, cmd.Wait(), output.Bytes())
	}

	record := &recordingConn{
		Conn:           tcpConn,
		clientToServer: true,
	}

	return record
}

func (test *clientTest) dataPath() string {
	return filepath.Join("..", "testdata", "Client-"+test.name)
}

func (test *clientTest) usernameDataPath() string {
	return filepath.Join("..", "testdata", "Client-username")
}

func (test *clientTest) loadData() (flows [][]byte, err error) {
	in, err := os.Open(test.dataPath())
	if err != nil {
		return nil, err
	}
	defer in.Close()
	return parseTestData(in)
}

func (test *clientTest) storeUsername() (err error) {
	storeUsernameOnce.Do(func() {
		err = os.WriteFile(test.usernameDataPath(), []byte(username()), 0666)
	})
	return err
}

func (test *clientTest) loadUsername() (string, error) {
	data, err := os.ReadFile(test.usernameDataPath())
	return string(data), err
}

func (test *clientTest) run(t *testing.T, write bool) {
	var clientConn net.Conn
	var recordingConn *recordingConn

	if write {
		if err := test.storeUsername(); err != nil {
			t.Fatalf("failed to store username to %q: %v", test.usernameDataPath(), err)
		}
		recordingConn = test.connFromCommand(t, "default")
		clientConn = recordingConn
	} else {
		username, err := test.loadUsername()
		if err != nil {
			t.Fatalf("failed to load username from %q: %v", test.usernameDataPath(), err)
		}
		test.config.User = username
		timer := time.AfterFunc(10*time.Second, func() {
			fmt.Println("This test may be stuck, try running using -timeout 10s")
		})
		t.Cleanup(func() {
			timer.Stop()
		})
		flows, err := test.loadData()
		if err != nil {
			t.Fatalf("failed to load data from %s: %v", test.dataPath(), err)
		}
		clientConn = newReplayingConn(t, flows)
	}
	c, chans, reqs, err := ssh.NewClientConn(clientConn, "", test.config)
	if err != nil {
		t.Fatal(err)
	}
	client := ssh.NewClient(c, chans, reqs)
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}

	if write {
		path := test.dataPath()
		out, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
		if err != nil {
			t.Fatalf("Failed to create output file: %v", err)
		}
		defer out.Close()
		recordingConn.Close()

		recordingConn.WriteTo(out)
		t.Logf("Wrote %s\n", path)
	}
}

func recordingsClientConfig() *ssh.ClientConfig {
	config := clientConfig()
	config.Rand = sha3.NewShake128()
	config.Auth = []ssh.AuthMethod{
		ssh.PublicKeys(testSigners["rsa"]),
	}
	return config
}

func TestClientKeyExchanges(t *testing.T) {
	config := ssh.ClientConfig{}
	config.SetDefaults()

	var keyExchanges []string
	for _, kex := range config.KeyExchanges {
		// Exclude ecdh for now, to make them determistic we should use see a
		// stream of fixed bytes as the random source.
		if !strings.HasPrefix(kex, "ecdh-") {
			keyExchanges = append(keyExchanges, kex)
		}
	}
	// Add diffie-hellman-group-exchange-sha256 as it is not enabled by default.
	keyExchanges = append(keyExchanges, "diffie-hellman-group-exchange-sha256")

	for _, kex := range keyExchanges {
		c := recordingsClientConfig()
		c.KeyExchanges = []string{kex}
		test := clientTest{
			name:   "KEX-" + kex,
			config: c,
		}
		runTestAndUpdateIfNeeded(t, test.name, test.run)
	}
}
