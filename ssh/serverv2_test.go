// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"errors"
	"net"
	"testing"
	"time"
)

func TestServerV2WithHandlerFunc(t *testing.T) {
	username := "testuser"
	serverConfig := ServerConfig{
		PasswordCallback: func(conn ConnMetadata, password []byte) (*Permissions, error) {
			if conn.User() == username && string(password) == clientPassword {
				return nil, nil
			}
			return nil, errors.New("invalid credentials")
		},
	}
	serverConfig.AddHostKey(testSigners["rsa"])

	server := ServerV2{
		ServerConfig:     serverConfig,
		HandshakeTimeout: 10 * time.Second,
		ClientHandler: ClientHandlerFuncV2(func(conn *ServerConnV2) {
			conn.Handle(
				ChannelHandlerFuncV2(func(newChannel *NewChannelV2) {
					if newChannel.ChannelType() != "session" {
						newChannel.Reject(UnknownChannelType, "unknown channel type")
						return
					}
					channel, err := newChannel.Accept()
					if err != nil {
						return
					}
					channel.Handle(RequestHandlerFuncV2(func(req *Request) {
						ok := false
						switch req.Type {
						case "exec":
							ok = true
							go func() {
								channel.SendRequest("exit-status", false, Marshal(&exitStatusMsg{Status: 0}))
								channel.Close()
							}()
						}
						if req.WantReply {
							req.Reply(ok, nil)
						}
					}))
				}),
				RequestHandlerFuncV2(func(req *Request) {
					if req != nil && req.WantReply {
						req.Reply(false, nil)
					}
				}),
			)
		}),
	}
	serverConfig.AddHostKey(testSigners["rsa"])

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go server.Serve(listener)

	config := ClientConfig{
		User: username,
		Auth: []AuthMethod{
			Password(clientPassword),
		},
		HostKeyCallback: InsecureIgnoreHostKey(),
	}
	client, err := Dial("tcp", listener.Addr().String(), &config)
	if err != nil {
		t.Fatal(err)
	}
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := session.Run("true"); err != nil {
		t.Fatal(err)
	}
	// Close the server with an active client session.
	server.Close()
	client.Close()
}

func TestServerV2WithHandler(t *testing.T) {
	username := "testuser"
	serverConfig := ServerConfig{
		PasswordCallback: func(conn ConnMetadata, password []byte) (*Permissions, error) {
			if conn.User() == username && string(password) == clientPassword {
				return nil, nil
			}
			return nil, errors.New("invalid credentials")
		},
	}
	serverConfig.AddHostKey(testSigners["rsa"])

	server := ServerV2{
		ServerConfig:     serverConfig,
		HandshakeTimeout: 10 * time.Second,
		ClientHandler:    &clientHandler{},
	}
	serverConfig.AddHostKey(testSigners["rsa"])

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go server.Serve(listener)

	config := ClientConfig{
		User: username,
		Auth: []AuthMethod{
			Password(clientPassword),
		},
		HostKeyCallback: InsecureIgnoreHostKey(),
	}
	client, err := Dial("tcp", listener.Addr().String(), &config)
	if err != nil {
		t.Fatal(err)
	}
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := session.Run("true"); err != nil {
		t.Fatal(err)
	}
	// Close the server with an active client session.
	server.Close()
	client.Close()
}

type clientHandler struct{}

func (h *clientHandler) HandleClient(conn *ServerConnV2) {
	handler := &connHandler{conn: conn}
	conn.Handle(handler, handler)
}

type connHandler struct {
	conn *ServerConnV2
}

func (c *connHandler) NewRequest(req *Request) {
	if req != nil && req.WantReply {
		req.Reply(false, nil)
	}
}

func (c *connHandler) NewChannel(newChannel *NewChannelV2) {
	if newChannel.ChannelType() != "session" {
		newChannel.Reject(UnknownChannelType, "unknown channel type")
		return
	}
	channel, err := newChannel.Accept()
	if err != nil {
		return
	}
	channel.Handle(RequestHandlerFuncV2(func(req *Request) {
		ok := false
		switch req.Type {
		case "exec":
			ok = true
			go func() {
				channel.SendRequest("exit-status", false, Marshal(&exitStatusMsg{Status: 0}))
				channel.Close()
			}()
		}
		if req.WantReply {
			req.Reply(ok, nil)
		}
	}))
}
