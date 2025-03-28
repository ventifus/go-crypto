// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/*
The mux represents the state of the SSH connection protocol, which
multiplexes multiple channels onto a single packet transport. The mux receives a
handshakeTransport struct as the implementation of the packetConn interface. The
handshakeTransport is created after the connection has been established and the
version has been exchanged, it starts with a mandatory key exchange (KEX) and is
used to wait for the session to be established, the first expected message is
msgNewKeys. After the initial handshake and authentication, a mux is created on
both the server and client sides using newMux. Upon creation, the mux starts the
loop function in a separate goroutine to run the connection machine. The loop
function repeatedly calls the onePacket method until an error is returned. The
onePacket method calls the readPacket method of the packetConn interface (and
thus of the handshakeTransport struct), then handles the received packet based
on its type. If an error occurs during packet handling, the loop ends.

Packet handling in onePacket:

  - msgChannelOpen packets are handled in handleChannelOpen. If the request is
    invalid, an error is returned; otherwise, the new channel is added to
    chanList. Additionally, the channel is added to the Go channel
    incomingChannels, which is a buffered channel with a buffer length set to
    chanSize (16).
  - Global requests and responses are handled in handleGlobalPacket.
    [ssh.Request] packets are added to the Go channel incomingRequests, which
    is a buffered channel with a buffer length set to chanSize (16). Responses
    to global requests are added to globalResponses, which is a buffered
    channel with a buffer length of 1. Global requests are sent using
    [ssh.Conn.SendRequest], which calls the mux's SendRequest method, sending
    the request and receiving the response from the globalResponses channel.
    If the global request expects a reply, the globalSentMu mutex is used to
    ensure that the response received from globalResponses corresponds to the
    message sent.
  - Ping messages are parsed using [ssh.Unmarshal], and a pong reply is sent.

Channel-specific packets are forwarded to the channel they refer to. The channel
is obtained from chanList based on the packet's channel ID. The Go channels
incomingChannels and incomingRequests are returned to the application calling
[ssh.NewServerConn] and [ssh.NewClientConn], and they must be serviced. If not,
the connection will hang. On the client side, [ssh.NewClient] automatically
handles the incoming channels and requests.

If onePacket returns an error, all channels are removed from chanList and
closed. Additionally, the Go channels incomingChannels, incomingRequests, and
globalResponses are closed. The [ssh.Conn.Wait] method can be used to wait for
the mux to end. When the mux loop ends, the errCond sync condition is used to
return from the Wait method. The [ssh.Conn.Close] method can be used to close
the handshakeTransport, which generates an error in the readPacket method used
in onePacket, causing the mux loop to end.

[ssh.Channel] is implemented using the channel struct, which internally
references a mux. Channel-specific data read from onePacket is forwarded to the
referenced channel and stored in channels using the buffer struct, a linked list
used for data exchange between the producer and consumer. For writes,
[ssh.Channel] uses the internal reference to the mux. Therefore, all reads and
writes for both global requests and channel-specific packets go through the mux.
The mux uses the packetConn interface implementation (handshakeTransport) to
perform reads and writes. The handshakeTransport struct uses the keyingTransport
interface, implemented using the transport struct, to perform the reads and
writes that implement the SSH packet protocol. The transport struct wraps the
underlying [net.Conn] within a [bufio.NewReader] and a [bufio.NewWriter]. The
handshakeTransport implements rekeying on top of the keyingTransport and is used
by the mux for actual reads and writes.

The handshakeTransport starts two goroutines:

  - kexLoop: Waits for and replies to KEX requests from the other side of the
    connection and sends KEX requests once the RekeyThreshold is reached.
  - readLoop: Reads incoming packets and adds them to the Go channel incoming,
    which is a buffered channel with a buffer length set to chanSize (16). The
    readPacket method returns packets from the incoming Go channel. Therefore,
    the mux needs to continuously call the readPacket method to prevent the
    incoming channel from becoming full and blocking the read loop.

When the readLoop wants to schedule a KEX, it pings the requestKex Go channel, a
buffered channel with a buffer length set to 1, so that the kexLoop can send the
KEX request. A KEX is scheduled when writeBytesLeft is less than or equal to
zero. If the other side requests or confirms a KEX, its kexInit message is sent
to the startKex unbuffered Go channel and handled in the kexLoop. Writes are
protected using a [sync.Mutex] and the [sync.Cond] writeCond. Specifically,
writeError, sentInitPacket, sentInitMsg, writeBytesLeft, and the writePacket
method are protected by the mutex. While a KEX is in progress, sentInitMsg is
not nil. The write requests, while a KEX is in progress, return nil to the
caller (generally the application using the library) and are queued internally
in pendingPackets until the pendingPackets size is less than maxPendingPackets
(64). Once the pending packets queue is full, the writes wait on the writeCond
condition. When the KEX completes, the pending packets queue is sent, and any
waiting writes are unblocked. Writes waiting on writeCond are also unblocked if
there is a write error or a read error. The read loop records a write error even
if there is a read error. When the read loop ends, it also closes the startKex
channel to unblock the KEX loop if it is waiting for it. The requestKex channel
is not closed when the read loop ends because it may also be written to in
writePacket, which could lead to a panic.

Important: If the read loop of the handshake transport ends, the mux loop ends,
and the connection is closed. The KEX loop can end due to a write error or
because the startKex channel is closed. Before ending, it closes the connection
to unblock the read loop if it is waiting for data to read, drains the startKex
channel, and closes the kexLoopDone, an unbuffered channel, so that Close can
return.

Close closes the connection, waking up the read loop goroutine, closes the
startKex channel, shutting down the KEX loop (if running), and finally waits on
the kexLoopDone channel for the KEX loop to complete. The Close() method then
returns the error from conn.Close().
*/
package ssh

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"sync"
	"sync/atomic"
)

// debugMux, if set, causes messages in the connection protocol to be
// logged.
const debugMux = false

// chanList is a thread safe channel list.
type chanList struct {
	// protects concurrent access to chans
	sync.Mutex

	// chans are indexed by the local id of the channel, which the
	// other side should send in the PeersId field.
	chans []*channel

	// This is a debugging aid: it offsets all IDs by this
	// amount. This helps distinguish otherwise identical
	// server/client muxes
	offset uint32
}

// Assigns a channel ID to the given channel.
func (c *chanList) add(ch *channel) uint32 {
	c.Lock()
	defer c.Unlock()
	for i := range c.chans {
		if c.chans[i] == nil {
			c.chans[i] = ch
			return uint32(i) + c.offset
		}
	}
	c.chans = append(c.chans, ch)
	return uint32(len(c.chans)-1) + c.offset
}

// getChan returns the channel for the given ID.
func (c *chanList) getChan(id uint32) *channel {
	id -= c.offset

	c.Lock()
	defer c.Unlock()
	if id < uint32(len(c.chans)) {
		return c.chans[id]
	}
	return nil
}

func (c *chanList) remove(id uint32) {
	id -= c.offset
	c.Lock()
	if id < uint32(len(c.chans)) {
		c.chans[id] = nil
	}
	c.Unlock()
}

// dropAll forgets all channels it knows, returning them in a slice.
func (c *chanList) dropAll() []*channel {
	c.Lock()
	defer c.Unlock()
	var r []*channel

	for _, ch := range c.chans {
		if ch == nil {
			continue
		}
		r = append(r, ch)
	}
	c.chans = nil
	return r
}

// mux represents the state for the SSH connection protocol, which
// multiplexes many channels onto a single packet transport.
type mux struct {
	conn     packetConn
	chanList chanList

	incomingChannels chan NewChannel

	globalSentMu     sync.Mutex
	globalResponses  chan interface{}
	incomingRequests chan *Request

	errCond *sync.Cond
	err     error
}

// When debugging, each new chanList instantiation has a different
// offset.
var globalOff uint32

func (m *mux) Wait() error {
	m.errCond.L.Lock()
	defer m.errCond.L.Unlock()
	for m.err == nil {
		m.errCond.Wait()
	}
	return m.err
}

// newMux returns a mux that runs over the given connection.
func newMux(p packetConn) *mux {
	m := &mux{
		conn:             p,
		incomingChannels: make(chan NewChannel, chanSize),
		globalResponses:  make(chan interface{}, 1),
		incomingRequests: make(chan *Request, chanSize),
		errCond:          newCond(),
	}
	if debugMux {
		m.chanList.offset = atomic.AddUint32(&globalOff, 1)
	}

	go m.loop()
	return m
}

func (m *mux) sendMessage(msg interface{}) error {
	p := Marshal(msg)
	if debugMux {
		log.Printf("send global(%d): %#v", m.chanList.offset, msg)
	}
	return m.conn.writePacket(p)
}

func (m *mux) SendRequest(name string, wantReply bool, payload []byte) (bool, []byte, error) {
	if wantReply {
		m.globalSentMu.Lock()
		defer m.globalSentMu.Unlock()
	}

	if err := m.sendMessage(globalRequestMsg{
		Type:      name,
		WantReply: wantReply,
		Data:      payload,
	}); err != nil {
		return false, nil, err
	}

	if !wantReply {
		return false, nil, nil
	}

	msg, ok := <-m.globalResponses
	if !ok {
		return false, nil, io.EOF
	}
	switch msg := msg.(type) {
	case *globalRequestFailureMsg:
		return false, msg.Data, nil
	case *globalRequestSuccessMsg:
		return true, msg.Data, nil
	default:
		return false, nil, fmt.Errorf("ssh: unexpected response to request: %#v", msg)
	}
}

// ackRequest must be called after processing a global request that
// has WantReply set.
func (m *mux) ackRequest(ok bool, data []byte) error {
	if ok {
		return m.sendMessage(globalRequestSuccessMsg{Data: data})
	}
	return m.sendMessage(globalRequestFailureMsg{Data: data})
}

func (m *mux) Close() error {
	return m.conn.Close()
}

// loop runs the connection machine. It will process packets until an
// error is encountered. To synchronize on loop exit, use mux.Wait.
func (m *mux) loop() {
	var err error
	for err == nil {
		err = m.onePacket()
	}

	for _, ch := range m.chanList.dropAll() {
		ch.close()
	}

	close(m.incomingChannels)
	close(m.incomingRequests)
	close(m.globalResponses)

	m.conn.Close()

	m.errCond.L.Lock()
	m.err = err
	m.errCond.Broadcast()
	m.errCond.L.Unlock()

	if debugMux {
		log.Println("loop exit", err)
	}
}

// onePacket reads and processes one packet.
func (m *mux) onePacket() error {
	packet, err := m.conn.readPacket()
	if err != nil {
		return err
	}

	if debugMux {
		if packet[0] == msgChannelData || packet[0] == msgChannelExtendedData {
			log.Printf("decoding(%d): data packet - %d bytes", m.chanList.offset, len(packet))
		} else {
			p, _ := decode(packet)
			log.Printf("decoding(%d): %d %#v - %d bytes", m.chanList.offset, packet[0], p, len(packet))
		}
	}

	switch packet[0] {
	case msgChannelOpen:
		return m.handleChannelOpen(packet)
	case msgGlobalRequest, msgRequestSuccess, msgRequestFailure:
		return m.handleGlobalPacket(packet)
	case msgPing:
		var msg pingMsg
		if err := Unmarshal(packet, &msg); err != nil {
			return fmt.Errorf("failed to unmarshal ping@openssh.com message: %w", err)
		}
		return m.sendMessage(pongMsg(msg))
	}

	// assume a channel packet.
	if len(packet) < 5 {
		return parseError(packet[0])
	}
	id := binary.BigEndian.Uint32(packet[1:])
	ch := m.chanList.getChan(id)
	if ch == nil {
		return m.handleUnknownChannelPacket(id, packet)
	}

	return ch.handlePacket(packet)
}

func (m *mux) handleGlobalPacket(packet []byte) error {
	msg, err := decode(packet)
	if err != nil {
		return err
	}

	switch msg := msg.(type) {
	case *globalRequestMsg:
		m.incomingRequests <- &Request{
			Type:      msg.Type,
			WantReply: msg.WantReply,
			Payload:   msg.Data,
			mux:       m,
		}
	case *globalRequestSuccessMsg, *globalRequestFailureMsg:
		m.globalResponses <- msg
	default:
		panic(fmt.Sprintf("not a global message %#v", msg))
	}

	return nil
}

// handleChannelOpen schedules a channel to be Accept()ed.
func (m *mux) handleChannelOpen(packet []byte) error {
	var msg channelOpenMsg
	if err := Unmarshal(packet, &msg); err != nil {
		return err
	}

	if msg.MaxPacketSize < minPacketLength || msg.MaxPacketSize > 1<<31 {
		failMsg := channelOpenFailureMsg{
			PeersID:  msg.PeersID,
			Reason:   ConnectionFailed,
			Message:  "invalid request",
			Language: "en_US.UTF-8",
		}
		return m.sendMessage(failMsg)
	}

	c := m.newChannel(msg.ChanType, channelInbound, msg.TypeSpecificData)
	c.remoteId = msg.PeersID
	c.maxRemotePayload = msg.MaxPacketSize
	c.remoteWin.add(msg.PeersWindow)
	m.incomingChannels <- c
	return nil
}

func (m *mux) OpenChannel(chanType string, extra []byte) (Channel, <-chan *Request, error) {
	ch, err := m.openChannel(chanType, extra)
	if err != nil {
		return nil, nil, err
	}

	return ch, ch.incomingRequests, nil
}

func (m *mux) openChannel(chanType string, extra []byte) (*channel, error) {
	ch := m.newChannel(chanType, channelOutbound, extra)

	ch.maxIncomingPayload = channelMaxPacket

	open := channelOpenMsg{
		ChanType:         chanType,
		PeersWindow:      ch.myWindow,
		MaxPacketSize:    ch.maxIncomingPayload,
		TypeSpecificData: extra,
		PeersID:          ch.localId,
	}
	if err := m.sendMessage(open); err != nil {
		return nil, err
	}

	switch msg := (<-ch.msg).(type) {
	case *channelOpenConfirmMsg:
		return ch, nil
	case *channelOpenFailureMsg:
		return nil, &OpenChannelError{msg.Reason, msg.Message}
	default:
		return nil, fmt.Errorf("ssh: unexpected packet in response to channel open: %T", msg)
	}
}

func (m *mux) handleUnknownChannelPacket(id uint32, packet []byte) error {
	msg, err := decode(packet)
	if err != nil {
		return err
	}

	switch msg := msg.(type) {
	// RFC 4254 section 5.4 says unrecognized channel requests should
	// receive a failure response.
	case *channelRequestMsg:
		if msg.WantReply {
			return m.sendMessage(channelRequestFailureMsg{
				PeersID: msg.PeersID,
			})
		}
		return nil
	default:
		return fmt.Errorf("ssh: invalid channel %d", id)
	}
}
