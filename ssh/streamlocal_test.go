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
	serverConf.AddHostKey(testSigners["rsa"])

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

	conn, err := remoteListener.Accept()
	if err != nil {
		return
	}
	read, err := io.ReadAll(conn)
	if err != nil {
		return
	}
	if !bytes.Equal(data, read) {
		t.Fatal("unexpected data")
	}
}

// forwardServer writes data to the forwarded socket before sending the initial
// reply to the client to simulate a race condition.
type forwardServer struct {
	// Listener for SSH connections
	listener net.Listener
	// Listner for streamlocal requests
	streamLocalListener net.Listener
	config              *ServerConfig
	data                []byte
	wg                  sync.WaitGroup
}

// newForwardServer returns an ssh server that can handle
// streamlocal-forward@openssh.com requests. Always call the Close method to
// terminate the server and its goroutines.
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

	server.wg.Add(1)
	go server.acceptConnections()

	return server, nil
}

func (s *forwardServer) port() (string, error) {
	_, port, err := net.SplitHostPort(s.listener.Addr().String())
	return port, err
}

func (s *forwardServer) acceptConnections() {
	defer s.wg.Done()

	for {
		c, err := s.listener.Accept()
		if err != nil {
			return
		}

		s.wg.Add(1)
		go s.serveConnection(c)
	}
}

func (s *forwardServer) serveConnection(c net.Conn) {
	defer func() {
		c.Close()
		s.wg.Done()
	}()

	sshConn, chans, reqs, err := NewServerConn(c, s.config)
	if err != nil {
		return
	}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.handleSSHRequests(reqs, sshConn)
	}()

	for newChannel := range chans {
		newChannel.Reject(Prohibited, "this server does not support channels")
	}
}

func (s *forwardServer) handleSSHRequests(in <-chan *Request, sshConn *ServerConn) {
	for req := range in {
		switch req.Type {
		case "streamlocal-forward@openssh.com":
			s.handleStreamLocalForwardRequest(req, sshConn)
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
	s.streamLocalListener = listener

	accepted := make(chan struct{}, 1)

	s.wg.Add(1)
	go s.handleStreamLocalRequests(sshConn, msg, accepted)

	// The socket is now ready to accept connections so send some data before
	// sending the reply to streamlocal-forward@openssh.com request.
	err = s.sendData(msg.SocketPath)
	if err != nil {
		if req.WantReply {
			req.Reply(false, nil)
		}
	}
	// Wait to accept the connection before sending the reply.
	<-accepted

	if req.WantReply {
		req.Reply(true, nil)
	}
}

func (s *forwardServer) sendData(socketPath string) error {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return err
	}
	defer conn.Close()

	_, err = conn.Write(s.data)
	return err
}

func (s *forwardServer) handleStreamLocalRequests(sshConn *ServerConn, msg streamLocalChannelForwardMsg, accepted chan struct{}) {
	defer func() {
		s.streamLocalListener.Close()
		s.wg.Done()
	}()

	var once sync.Once

	for {
		local, err := s.streamLocalListener.Accept()
		if err != nil {
			return
		}

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()

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

			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				DiscardRequests(reqs)
			}()

			remote := &chanConn{
				Channel: ch,
			}

			runTunnel(local, remote)
		}()
	}
}

func (s *forwardServer) Close() error {
	err := s.listener.Close()
	if s.streamLocalListener != nil {
		s.streamLocalListener.Close()
	}
	// Wait for the accept loop and any goroutines to exit.
	s.wg.Wait()
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
