// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || plan9 || solaris

package ssh

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"sync"
	"testing"
)

func TestStreamLocalForwardRace(t *testing.T) {
	serverConf := &ServerConfig{
		PasswordCallback: func(conn ConnMetadata, password []byte) (*Permissions, error) {
			return &Permissions{}, nil
		},
	}
	serverConf.AddHostKey(&legacyRSASigner{testSigners["rsa"]})

	data := []byte("some test data")
	server, err := newForwardServer(serverConf, data)
	if err != nil {
		t.Fatalf("unable to start test server: %v", err)
	}
	defer server.Close()

	port, err := server.port()
	if err != nil {
		t.Fatalf("unable to get server port: %v", err)
	}

	clientConf := &ClientConfig{
		User:            "test",
		HostKeyCallback: InsecureIgnoreHostKey(),
		Auth:            []AuthMethod{Password("")},
	}
	client, err := Dial("tcp", fmt.Sprintf("127.0.0.1:%s", port), clientConf)
	if err != nil {
		t.Fatalf("unable to connect to the server: %v", err)
	}
	defer client.Close()

	dir := t.TempDir()
	remoteSock := filepath.Join(dir, "remote.sock")

	remoteListener, err := client.Listen("unix", remoteSock)
	if err != nil {
		t.Fatalf("unable to start remote listener: %v", err)
	}
	defer remoteListener.Close()

	readChan := make(chan []byte)

	go func() {
		defer close(readChan)
		conn, err := remoteListener.Accept()
		if err != nil {
			return
		}
		read, err := io.ReadAll(conn)
		if err != nil {
			return
		}
		readChan <- read

	}()

	read := <-readChan

	if !bytes.Equal(data, read) {
		t.Fatal("unexpected data")
	}
}

// forwardServer writes data to the forwarded socket before sending the initial
// reply to the client to simulate a race condition.
type forwardServer struct {
	listener net.Listener
	config   *ServerConfig
	data     []byte
	done     <-chan struct{}
}

func newForwardServer(config *ServerConfig, data []byte) (*forwardServer, error) {
	server := &forwardServer{
		config: config,
		data:   data,
	}
	listener, err := net.Listen("tcp", "127.0.0.1:")
	if err != nil {
		return nil, err
	}
	server.listener = listener
	done := make(chan struct{}, 1)
	server.done = done
	go server.acceptConnections(done)

	return server, nil
}

func (s *forwardServer) port() (string, error) {
	_, port, err := net.SplitHostPort(s.listener.Addr().String())
	return port, err
}

func (s *forwardServer) acceptConnections(done chan<- struct{}) {
	defer close(done)

	for {
		c, err := s.listener.Accept()
		if err != nil {
			return
		}
		sshConn, chans, reqs, err := NewServerConn(c, s.config)
		if err != nil {
			return
		}
		go s.handleSSHRequests(reqs, sshConn)
		defer c.Close()

		for newChannel := range chans {
			newChannel.Reject(Prohibited, "this server does not support channels")
		}
	}
}

func (s *forwardServer) handleSSHRequests(in <-chan *Request, sshConn *ServerConn) {
	for req := range in {
		switch req.Type {
		case "streamlocal-forward@openssh.com":
			go s.handleStreamLocalForwardRequest(req, sshConn)
		default:
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}
}

func (s *forwardServer) handleStreamLocalForwardRequest(req *Request, sshConn *ServerConn) {
	var msg streamLocalChannelForwardMsg
	if err := Unmarshal(req.Payload, &msg); err != nil {
		if req.WantReply {
			req.Reply(false, nil)
		}
		return
	}
	listener, err := net.Listen("unix", msg.SocketPath)
	if err != nil {
		if req.WantReply {
			req.Reply(false, nil)
		}
		return
	}

	// Wait to accept a connection before sending the reply.
	accepted := make(chan struct{}, 1)
	go s.handleStreamLocalRequests(listener, sshConn, msg, accepted)

	errCh := make(chan error, 1)
	go func() {
		defer close(errCh)

		conn, err := net.Dial("unix", msg.SocketPath)
		if err != nil {
			errCh <- fmt.Errorf("net.Dial failed: %v", err)
			return
		}
		defer conn.Close()

		_, err = conn.Write(s.data)
		if err != nil {
			errCh <- fmt.Errorf("sending data failed: %v", err)
		}
	}()

	err = <-errCh
	if err != nil {
		if req.WantReply {
			req.Reply(false, nil)
		}
	}
	<-accepted

	if req.WantReply {
		req.Reply(true, nil)
	}
}

func (s *forwardServer) handleStreamLocalRequests(listener net.Listener, sshConn *ServerConn,
	msg streamLocalChannelForwardMsg, accepted chan struct{},
) {
	defer listener.Close()

	var once sync.Once

	for {
		local, err := listener.Accept()
		if err != nil {
			return
		}

		go func() {
			once.Do(func() {
				close(accepted)
			})
			ch, reqs, err := sshConn.OpenChannel("forwarded-streamlocal@openssh.com", Marshal(&forwardedStreamLocalPayload{
				SocketPath: msg.SocketPath,
			}))
			if err != nil {
				local.Close()
				return
			}
			go DiscardRequests(reqs)

			remote := &chanConn{
				Channel: ch,
			}

			runTunnel(local, remote)
		}()
	}
}

func (s *forwardServer) Close() error {
	err := s.listener.Close()
	// wait for the accept loop to exit
	<-s.done
	return err
}

func runTunnel(local, remote net.Conn) {
	defer local.Close()
	defer remote.Close()
	done := make(chan struct{}, 2)

	go func() {
		io.Copy(local, remote)
		done <- struct{}{}
	}()

	go func() {
		io.Copy(remote, local)
		done <- struct{}{}
	}()

	<-done
}
