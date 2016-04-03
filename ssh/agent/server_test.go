// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package agent

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestServer(t *testing.T) {
	c1, c2, err := netPipe()
	if err != nil {
		t.Fatalf("netPipe: %v", err)
	}
	defer c1.Close()
	defer c2.Close()
	c := NewClient(c1)

	go ServeAgent(NewKeyring(), c2)

	testAgentInterface(t, c, testPrivateKeys["rsa"], nil, 0)
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

	conf := ssh.ClientConfig{}
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

	testAgentInterface(t, c, testPrivateKeys["rsa"], nil, 0)
}

func testV1ProtocolMessages(t *testing.T, c *client) {
	err := testV1ProtocolMessage(c, []byte{agentRequestV1Identities}, ssh.Marshal(agentV1IdentityMsg{0}))
	if err != nil {
		t.Fatalf("v1 request all failed: %v", err)
	}

	err = testV1ProtocolMessage(c, []byte{agentRemoveAllV1Identities}, []byte{agentSuccess})
	if err != nil {
		t.Fatalf("v1 remove all failed: %v", err)
	}
}

func testV1ProtocolMessage(c *client, req, resp []byte) error {
	var err error
	msg := make([]byte, 4+len(req))
	binary.BigEndian.PutUint32(msg, uint32(len(req)))
	copy(msg[4:], req)
	if _, err = c.conn.Write(msg); err != nil {
		return clientErr(err)
	}

	var respSizeBuf [4]byte
	if _, err = io.ReadFull(c.conn, respSizeBuf[:]); err != nil {
		return clientErr(err)
	}
	respSize := binary.BigEndian.Uint32(respSizeBuf[:])
	if respSize > maxAgentResponseBytes {
		return clientErr(err)
	}

	buf := make([]byte, respSize)
	if _, err = io.ReadFull(c.conn, buf); err != nil {
		return clientErr(err)
	}

	if !bytes.Equal(buf, resp) {
		return fmt.Errorf("invalid response. expected: %v; got: %v", resp, buf)
	}
	return nil
}
