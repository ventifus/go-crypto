// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package test

import (
	"bytes"
	"fmt"
	"net"

	"golang.org/x/crypto/ssh"
)

type exitStatusMsg struct {
	Status uint32
}

// goServer is a Go SSH server to use to check public key and
// ssh certificate authentication with ssh CLI.
// The server will reply with a 0 exit status to any exec request, e.g.
//
// ssh -i <pub key path> -p <server port> username@127.0.0.1 /bin/true
//
//  1. if the username is "testuser" the ssh CLI will use public key
//     authentication
//  2. if the username is "test_user" the public key authentication fails
//     and the ssh CLI will try the user certificate authentication.
//     The test user certificate has "username" as Key ID and "test_user"
//     as Principal
type goTestServer struct {
	listener          net.Listener
	config            *ssh.ServerConfig
	publicKeyAuthDone bool
	userCertAuthDone  bool
	done              chan struct{}
}

func (s *goTestServer) Start() (string, error) {
	certChecker := ssh.CertChecker{
		IsUserAuthority: func(k ssh.PublicKey) bool {
			if bytes.Equal(k.Marshal(), testPublicKeys["ca"].Marshal()) {
				s.userCertAuthDone = true
				return true
			}
			return false
		},
		UserKeyFallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if conn.User() == "testuser" && bytes.Equal(key.Marshal(), testPublicKeys["rsa"].Marshal()) {
				s.publicKeyAuthDone = true
				return nil, nil
			}

			return nil, fmt.Errorf("pubkey for %q not acceptable", conn.User())
		},
	}

	s.config = &ssh.ServerConfig{
		PublicKeyCallback: certChecker.Authenticate,
	}
	s.config.AddHostKey(testSigners["rsa"])

	listener, err := net.Listen("tcp", "127.0.0.1:")
	if err != nil {
		return "", err
	}
	s.listener = listener
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		return "", err
	}
	s.done = make(chan struct{}, 1)
	go s.acceptConnections()
	return port, nil
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
	if s.done != nil {
		// wait for the accept loop to exit
		<-s.done
	}
	return err
}
