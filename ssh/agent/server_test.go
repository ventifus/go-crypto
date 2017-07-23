// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package agent

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestServer(t *testing.T) {
	c1, c2, err := netPipe()
	if err != nil {
		t.Fatalf("netPipe: %v", err)
	}
	defer c1.Close()
	defer c2.Close()
	client := NewClient(c1)

	go ServeAgent(NewKeyring(), c2)

	testAgentInterface(t, client, testPrivateKeys["rsa"], nil, 0)
}

func TestLockServer(t *testing.T) {
	testLockAgent(NewKeyring(), t)
}

func TestSetupForwardAgent(t *testing.T) {
	a, b, err := netPipe()
	if err != nil {
		t.Fatalf("netPipe: %v", err)
	}

	defer a.Close()
	defer b.Close()

	_, socket, cleanup := startAgent(t)
	defer cleanup()

	serverConf := ssh.ServerConfig{
		NoClientAuth: true,
	}
	serverConf.AddHostKey(testSigners["rsa"])
	incoming := make(chan *ssh.ServerConn, 1)
	go func() {
		conn, _, _, err := ssh.NewServerConn(a, &serverConf)
		if err != nil {
			t.Fatalf("Server: %v", err)
		}
		incoming <- conn
	}()

	conf := ssh.ClientConfig{
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	conn, chans, reqs, err := ssh.NewClientConn(b, "", &conf)
	if err != nil {
		t.Fatalf("NewClientConn: %v", err)
	}
	client := ssh.NewClient(conn, chans, reqs)

	if err := ForwardToRemote(client, socket); err != nil {
		t.Fatalf("SetupForwardAgent: %v", err)
	}

	server := <-incoming
	ch, reqs, err := server.OpenChannel(channelType, nil)
	if err != nil {
		t.Fatalf("OpenChannel(%q): %v", channelType, err)
	}
	go ssh.DiscardRequests(reqs)

	agentClient := NewClient(ch)
	testAgentInterface(t, agentClient, testPrivateKeys["rsa"], nil, 0)
	conn.Close()
}

func TestV1ProtocolMessages(t *testing.T) {
	c1, c2, err := netPipe()
	if err != nil {
		t.Fatalf("netPipe: %v", err)
	}
	defer c1.Close()
	defer c2.Close()
	c := NewClient(c1)

	go ServeAgent(NewKeyring(), c2)

	testV1ProtocolMessages(t, c.(*client))
}

func testV1ProtocolMessages(t *testing.T, c *client) {
	reply, err := c.call([]byte{agentRequestV1Identities})
	if err != nil {
		t.Fatalf("v1 request all failed: %v", err)
	}
	if msg, ok := reply.(*agentV1IdentityMsg); !ok || msg.Numkeys != 0 {
		t.Fatalf("invalid request all response: %#v", reply)
	}

	reply, err = c.call([]byte{agentRemoveAllV1Identities})
	if err != nil {
		t.Fatalf("v1 remove all failed: %v", err)
	}
	if _, ok := reply.(*successAgentMsg); !ok {
		t.Fatalf("invalid remove all response: %#v", reply)
	}
}

func verifyKey(sshAgent Agent) error {
	keys, err := sshAgent.List()
	if err != nil {
		return fmt.Errorf("listing keys: %v", err)
	}

	if len(keys) != 1 {
		return fmt.Errorf("bad number of keys found. expected 1, got %d", len(keys))
	}

	buf := make([]byte, 128)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Errorf("rand: %v", err)
	}

	sig, err := sshAgent.Sign(keys[0], buf)
	if err != nil {
		return fmt.Errorf("sign: %v", err)
	}

	if err := keys[0].Verify(buf, sig); err != nil {
		return fmt.Errorf("verify: %v", err)
	}
	return nil
}

func addKeyToAgent(key crypto.PrivateKey) error {
	sshAgent := NewKeyring()
	if err := sshAgent.Add(AddedKey{PrivateKey: key}); err != nil {
		return fmt.Errorf("add: %v", err)
	}
	return verifyKey(sshAgent)
}

func TestKeyTypes(t *testing.T) {
	for k, v := range testPrivateKeys {
		if err := addKeyToAgent(v); err != nil {
			t.Errorf("error adding key type %s, %v", k, err)
		}
		if err := addCertToAgentSock(v, nil); err != nil {
			t.Errorf("error adding key type %s, %v", k, err)
		}
	}
}

func addCertToAgentSock(key crypto.PrivateKey, cert *ssh.Certificate) error {
	a, b, err := netPipe()
	if err != nil {
		return err
	}
	agentServer := NewKeyring()
	go ServeAgent(agentServer, a)

	agentClient := NewClient(b)
	if err := agentClient.Add(AddedKey{PrivateKey: key, Certificate: cert}); err != nil {
		return fmt.Errorf("add: %v", err)
	}
	return verifyKey(agentClient)
}

func addCertToAgent(key crypto.PrivateKey, cert *ssh.Certificate) error {
	sshAgent := NewKeyring()
	if err := sshAgent.Add(AddedKey{PrivateKey: key, Certificate: cert}); err != nil {
		return fmt.Errorf("add: %v", err)
	}
	return verifyKey(sshAgent)
}

func TestCertTypes(t *testing.T) {
	for keyType, key := range testPublicKeys {
		cert := &ssh.Certificate{
			ValidPrincipals: []string{"gopher1"},
			ValidAfter:      0,
			ValidBefore:     ssh.CertTimeInfinity,
			Key:             key,
			Serial:          1,
			CertType:        ssh.UserCert,
			SignatureKey:    testPublicKeys["rsa"],
			Permissions: ssh.Permissions{
				CriticalOptions: map[string]string{},
				Extensions:      map[string]string{},
			},
		}
		if err := cert.SignCert(rand.Reader, testSigners["rsa"]); err != nil {
			t.Fatalf("signcert: %v", err)
		}
		if err := addCertToAgent(testPrivateKeys[keyType], cert); err != nil {
			t.Fatalf("%v", err)
		}
		if err := addCertToAgentSock(testPrivateKeys[keyType], cert); err != nil {
			t.Fatalf("%v", err)
		}
	}
}

func TestParseConstraints(t *testing.T) {
	var data []byte

	// Test LifetimeSecs
	var secsBytes [4]byte
	secs := uint32(time.Now().UnixNano())
	binary.BigEndian.PutUint32(secsBytes[:], secs)
	data = append(data, agentConstrainLifetime)
	data = append(data, secsBytes[:]...)
	lifetimeSecs, _, _, err := parseConstraints(data)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if lifetimeSecs != secs {
		t.Errorf("expect lifetime %v, found %v", secs, lifetimeSecs)
	}

	// Test ConfirmBeforeUse
	_, confirmBeforeUse, _, err := parseConstraints([]byte{agentConstrainConfirm})
	if err != nil {
		t.Fatalf("%v", err)
	}
	if !confirmBeforeUse {
		t.Errorf("unexpected comfirmBeforeUse: %v", confirmBeforeUse)
	}

	// Test ConstraintExtensions
	data = data[:0]
	var ext1 = constrainExtensionAgentMsg{ExtensionName: "name1", ExtensionDetails: []byte("details1")}
	var ext2 = constrainExtensionAgentMsg{ExtensionName: "name2", ExtensionDetails: []byte("details2")}
	data = append(data, ssh.Marshal(ext1)...)
	data = append(data, ssh.Marshal(ext2)...)
	_, _, extensions, err := parseConstraints(data)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if extensions[0].ExtensionName != "name2" || !bytes.Equal(extensions[0].ExtensionDetails, []byte("details2")) {
		t.Errorf("expect extension %v, found %v", ext1, extensions[0])
	}
	if extensions[1].ExtensionName != "name1" || !bytes.Equal(extensions[1].ExtensionDetails, []byte("details1")) {
		t.Errorf("expect extension %v, found %v", ext2, extensions[1])
	}

	// Test Unknown Constraint
	_, _, _, err = parseConstraints([]byte{128})
	if err == nil || !strings.Contains(err.Error(), "unknown constraint") {
		t.Errorf("unexpected error: %v", err)
	}
}
