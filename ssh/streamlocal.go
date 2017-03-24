package ssh

import (
	"errors"
	"io"
	"net"
	"time"
)

// See openssh-portable/PROTOCOL, section 2.4. connection: Unix domain socket forwarding
// https://github.com/openssh/openssh-portable/blob/master/PROTOCOL#L235
type streamLocalChannelOpenDirectMsg struct {
	socketPath string
	reserved0  string
	reserved1  uint32
}

type forwardedStreamLocalPayload struct {
	SocketPath string
	Reserved0  string
}

type streamLocalChannelForwardMsg struct {
	socketPath string
}

// ListenUnix is similar to ListenTCP but uses Unix domain socket
func (c *Client) ListenUnix(socketPath string) (net.Listener, error) {
	m := streamLocalChannelForwardMsg{
		socketPath,
	}
	// send message
	ok, _, err := c.SendRequest("streamlocal-forward@openssh.com", true, Marshal(&m))
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("ssh: streamlocal-forward@openssh.com request denied by peer")
	}
	ch := c.forwards.addStreamLocal(socketPath)

	return &unixListener{socketPath, c, ch}, nil
}

type unixListener struct {
	socketPath string

	conn *Client
	in   <-chan forward
}

// Accept waits for and returns the next connection to the listener.
func (l *unixListener) Accept() (net.Conn, error) {
	s, ok := <-l.in
	if !ok {
		return nil, io.EOF
	}
	ch, incoming, err := s.newCh.Accept()
	if err != nil {
		return nil, err
	}
	go DiscardRequests(incoming)

	return &unixChanConn{
		Channel:    ch,
		socketPath: l.socketPath,
	}, nil
}

// Close closes the listener.
func (l *unixListener) Close() error {
	m := streamLocalChannelForwardMsg{
		l.socketPath,
	}

	// this also closes the listener.
	l.conn.forwards.removeStreamLocal(l.socketPath)
	ok, _, err := l.conn.SendRequest("cancel-streamlocal-forward@openssh.com", true, Marshal(&m))
	if err == nil && !ok {
		err = errors.New("ssh: cancel-streamlocal-forward@openssh.com failed")
	}
	return err
}

// Addr returns the listener's network address.
func (l *unixListener) Addr() net.Addr {
	return &net.UnixAddr{
		Name: l.socketPath,
		Net:  "unix",
	}
}

type unixChanConn struct {
	Channel
	socketPath string
}

// LocalAddr returns the local network address.
func (t *unixChanConn) LocalAddr() net.Addr {
	return &net.UnixAddr{
		Name: t.socketPath,
		Net:  "unix",
	}
}

// RemoteAddr returns the remote network address.
func (t *unixChanConn) RemoteAddr() net.Addr {
	return &net.UnixAddr{
		Name: t.socketPath,
		Net:  "unix",
	}
}

// SetDeadline sets the read and write deadlines associated
// with the connection.
func (t *unixChanConn) SetDeadline(deadline time.Time) error {
	if err := t.SetReadDeadline(deadline); err != nil {
		return err
	}
	return t.SetWriteDeadline(deadline)
}

// SetReadDeadline sets the read deadline.
// A zero value for t means Read will not time out.
// After the deadline, the error from Read will implement net.Error
// with Timeout() == true.
func (t *unixChanConn) SetReadDeadline(deadline time.Time) error {
	return errors.New("ssh: unixChan: deadline not supported")
}

// SetWriteDeadline exists to satisfy the net.Conn interface
// but is not implemented by this type.  It always returns an error.
func (t *unixChanConn) SetWriteDeadline(deadline time.Time) error {
	return errors.New("ssh: unixChan: deadline not supported")
}
