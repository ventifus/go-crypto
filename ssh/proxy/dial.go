package proxy

import (
	"context"
	"io"
	"net"
	"sync"

	"golang.org/x/crypto/ssh"
)

// ProxyClient is an ssh.Client that's been forwarded through multiple hops.
// Its primary purpose is to keep track of the all the connections that need
// to be closed when the remote ssh.Client is closed.
type ProxyClient struct {
	*ssh.Client

	mu      sync.Mutex
	closers []io.Closer
}

// Close closes all connections associated with this ProxyClient.
func (pc *ProxyClient) Close() error {
	pc.mu.Lock()
	defer pc.mu.Unlock()

	for _, c := range pc.closers {
		c.Close()
	}

	return nil
}

// Dial returns an ssh Client connection to the last host in the addresses slice. It first
// connects to each of the preceding hosts in order.
// This is equivalent to calling ssh A -o ProxyCommand=ssh B -W A:22
func Dial(ctx context.Context, network string, addresses []string, config *ssh.ClientConfig) (*ProxyClient, error) {
	pc := &ProxyClient{mu: sync.Mutex{}}

	// Rather than naming the return arguments, we use retErr to check
	// if we encountered an error setting up the ssh.Client.
	var retErr error
	defer func() {
		if retErr != nil {
			pc.Close()
		}
	}()

	dial := net.Dial
	for _, host := range addresses {
		var conn net.Conn
		conn, err := dial(network, host)
		if err != nil {
			retErr = err
			return nil, err
		}

		sshConn, chans, reqs, err := ssh.NewClientConn(conn, host, config)
		if err != nil {
			retErr = err
			return nil, err
		}

		pc.Client = ssh.NewClient(sshConn, chans, reqs)

		pc.mu.Lock()
		pc.closers = append(pc.closers, []io.Closer{conn, sshConn, pc.Client}...)
		pc.mu.Unlock()

		dial = pc.Client.Dial
	}

	return pc, nil
}
