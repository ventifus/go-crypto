// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

// ChannelHandlerV2 defines the interface to handle new channel requests.
type ChannelHandlerV2 interface {
	NewChannel(ch *NewChannelV2)
}

// RequestHandlerV2 efines the interface to handle new [Request].
type RequestHandlerV2 interface {
	NewRequest(req *Request)
}

// ClientHandlerV2 defines the interface to handle authenticated server
// connections.
type ClientHandlerV2 interface {
	// HandleClient is called after the handshake completes and a client
	// authenticates with the server.
	HandleClient(conn *ServerConnV2)
}

// NewRequest calls f(req).
func (f RequestHandlerFuncV2) NewRequest(req *Request) {
	f(req)
}

// ChannelHandlerFuncV2 is an adapter to allow the use of ordinary function as
// [ChannelHandlerV2]. If f is a function with the appropriate signature,
// ChannelHandlerFuncV2(f) is a [ChannelHandlerV2] that calls f.
type ChannelHandlerFuncV2 func(newChannel *NewChannelV2)

// NewChannel calls f(ch).
func (f ChannelHandlerFuncV2) NewChannel(newChannel *NewChannelV2) {
	f(newChannel)
}

// RequestHandlerFuncV2 is an adapter to allow the use of ordinary function as
// [RequestHandlerV2]. If f is a function with the appropriate signature,
// RequestHandlerFuncV2(f) is a [RequestHandlerV2] that calls f.
type RequestHandlerFuncV2 func(req *Request)

// ClientHandlerFuncV2 is an adapter to allow the use of ordinary function as
// [ClientHandlerV2]. If f is a function with the appropriate signature,
// ClientHandlerFuncV2(f) is a [ClientHandler] that calls f.
type ClientHandlerFuncV2 func(conn *ServerConnV2)

// HandleClient calls f(conn).
func (f ClientHandlerFuncV2) HandleClient(conn *ServerConnV2) {
	f(conn)
}

// ServerV2 defines an high level server implementation.
type ServerV2 struct {
	ServerConfig
	// HandshakeTimeout defines the timeout for the initial handshake.
	HandshakeTimeout time.Duration

	// ConnectionFailed, if non-nil, is called to report handshake errors.
	ConnectionFailed func(c net.Conn, err error)

	// ConnectionAdded, if non-nil, is called when a client connects, by
	// returning an error the connection will be refused.
	ConnectionAdded func(c net.Conn) error

	// ClientHandler defines the handler for authenticated clients. It is called
	// if the handshake is successfull. The handler must serve requests and
	// channels using [ServerConnV2.Handle].
	ClientHandler ClientHandlerV2

	listener          net.Listener
	mu                sync.Mutex
	isClosed          bool
	activeConnections []*ServerConnV2
}

// ServerConnV2 is an authenticated SSH connection, as seen from the
// server.
type ServerConnV2 struct {
	*connection

	// If the succeeding authentication callback returned a
	// non-nil Permissions pointer, it is stored here.
	Permissions *Permissions
}

// Handle must be called to handle requests and channels. Handle blocks. If
// channelHandler is nil channels will be rejected. If requestHandler is nil,
// requests will be discarded.
func (c *ServerConnV2) Handle(channelHandler ChannelHandlerV2, requestHandler RequestHandlerV2) error {
	go func() {
		for req := range c.connection.incomingRequests {
			if requestHandler != nil {
				go requestHandler.NewRequest(req)
			} else {
				if req.WantReply {
					req.Reply(false, nil)
				}
			}
		}
	}()

	go func() {
		for newChannel := range c.connection.incomingChannels {
			newChV2 := NewChannelV2{ch: newChannel.(*channel)}
			if channelHandler != nil {
				go channelHandler.NewChannel(&newChV2)
			} else {
				newChV2.Reject(Prohibited, "no channel handler defined")
			}
		}
	}()

	return c.mux.Wait()
}

// ListenAndServe  listens on the TCP network address addr and then calls [Serve].
func (s *ServerV2) ListenAndServe(addr string) error {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	return s.Serve(listener)
}

// Serve accepts incoming connections on the Listener l, creating a new service
// goroutine for each and execute the provided [ClientHandler] implementation.
func (s *ServerV2) Serve(l net.Listener) error {
	s.listener = l
	if err := s.validate(); err != nil {
		return err
	}

	var tempDelay time.Duration // how long to sleep on accept failure

	for {
		conn, err := l.Accept()
		if err != nil {
			// see https://github.com/golang/go/blob/4aa1efed4853ea067d665a952eee77c52faac774/src/net/http/server.go#L3046
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if max := 1 * time.Second; tempDelay > max {
					tempDelay = max
				}
				time.Sleep(tempDelay)
				continue
			}
			return err
		}
		tempDelay = 0

		go s.serveConnection(conn)
	}
}

// Close immediately closes all active connections.
func (s *ServerV2) Close() error {
	var err error
	if s.listener != nil {
		err = s.listener.Close()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.isClosed = true

	for _, c := range s.activeConnections {
		c.Close()
	}
	s.activeConnections = nil

	return err
}

func (s *ServerV2) serveConnection(c net.Conn) {
	if s.ConnectionAdded != nil {
		if err := s.ConnectionAdded(c); err != nil {
			c.Close()
			return
		}
	}
	conn := &connection{
		sshConn: sshConn{conn: c},
	}

	perms, err := s.handshake(conn)
	if err != nil {
		if s.ConnectionFailed != nil {
			s.ConnectionFailed(c, err)
		}
		c.Close()
		return
	}
	serverConn := &ServerConnV2{conn, perms}
	s.mu.Lock()

	if s.isClosed {
		s.mu.Unlock()
		serverConn.Close()
		return
	}

	s.activeConnections = append(s.activeConnections, serverConn)
	s.mu.Unlock()

	s.ClientHandler.HandleClient(serverConn)
}

func (s *ServerV2) handshake(conn *connection) (*Permissions, error) {
	if s.HandshakeTimeout == 0 {
		return conn.serverHandshake(&s.ServerConfig)
	}

	type handshakeResult struct {
		perms *Permissions
		err   error
	}
	ch := make(chan handshakeResult)

	ctx, cancel := context.WithTimeout(context.Background(), s.HandshakeTimeout)
	defer cancel()

	go func() {
		perms, err := conn.serverHandshake(&s.ServerConfig)
		ch <- handshakeResult{
			perms: perms,
			err:   err,
		}
	}()

	var result handshakeResult

	select {
	case result = <-ch:
	case <-ctx.Done():
		return nil, fmt.Errorf("handshake failed: %w", context.Cause(ctx))
	}

	return result.perms, result.err
}

func (s *ServerV2) validate() error {
	s.SetDefaults()
	if s.MaxAuthTries == 0 {
		s.MaxAuthTries = 6
	}
	if len(s.PublicKeyAuthAlgorithms) == 0 {
		s.PublicKeyAuthAlgorithms = supportedPubKeyAuthAlgos
	} else {
		for _, algo := range s.PublicKeyAuthAlgorithms {
			if !contains(supportedPubKeyAuthAlgos, algo) {
				return fmt.Errorf("ssh: unsupported public key authentication algorithm %s", algo)
			}
		}
	}
	// Check if the config contains any unsupported key exchanges
	for _, kex := range s.KeyExchanges {
		if _, ok := serverForbiddenKexAlgos[kex]; ok {
			return fmt.Errorf("ssh: unsupported key exchange %s for server", kex)
		}
	}
	return nil
}
