// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package test

import (
	"net"

	"golang.org/x/crypto/ssh"
)

type exitStatusMsg struct {
	Status uint32
}

// goServer is a test Go SSH server that accepts public key and certificate
// authentication and replies with a 0 exit status to any exec request without
// running any commands, e.g.
//
// ssh -i <pub key path> -p <server port> username@127.0.0.1 /bin/true
//
// If the client presents a certificate signed by testPublicKeys["ca"], it's
// accepted for any user. If a public key is presented, it's accepted only if
// it's testPublicKeys["rsa"] and the username is testpubkey. The server will
// also store the number of successful public key and certificate
// authentications.
type goTestServer struct {
	listener net.Listener
	config   *ssh.ServerConfig
	port     string
	done     chan struct{}
}

func newTestServer(config *ssh.ServerConfig) (*goTestServer, error) {
	server := &goTestServer{
		config: config,
	}
	err := server.start()
	return server, err
}

func (s *goTestServer) start() error {
	listener, err := net.Listen("tcp", "127.0.0.1:")
	if err != nil {
		return err
	}
	s.listener = listener
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		return err
	}
	s.port = port
	s.done = make(chan struct{}, 1)
	go s.acceptConnections()
	return nil
}

func (s *goTestServer) acceptConnections() {
	defer close(s.done)

	for {
		c, err := s.listener.Accept()
		if err != nil {
			return
		}
		_, chans, reqs, err := ssh.NewServerConn(c, s.config)
		if err != nil {
			return
		}
		go ssh.DiscardRequests(reqs)
		defer c.Close()

		for newChannel := range chans {
			if newChannel.ChannelType() != "session" {
				newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
				continue
			}

			channel, requests, err := newChannel.Accept()
			if err != nil {
				continue
			}

			go func(in <-chan *ssh.Request) {
				for req := range in {
					ok := false
					switch req.Type {
					case "exec":
						ok = true
						go func() {
							channel.SendRequest("exit-status", false, ssh.Marshal(&exitStatusMsg{Status: 0}))
							channel.Close()
						}()
					}
					if req.WantReply {
						req.Reply(ok, nil)
					}
				}
			}(requests)
		}
	}
}

func (s *goTestServer) Close() error {
	err := s.listener.Close()
	// wait for the accept loop to exit
	<-s.done
	return err
}
