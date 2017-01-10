// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
)

// debugHandshake, if set, prints messages sent and received.  Key
// exchange messages are printed as if DH were used, so the debug
// messages are wrong when using ECDH.
const debugHandshake = false // true

// keyingTransport is a packet based transport that supports key
// changes. It need not be thread-safe. It should pass through
// msgNewKeys in both directions.
type keyingTransport interface {
	packetConn

	// prepareKeyChange sets up a key change. The key change for a
	// direction will be effected if a msgNewKeys message is sent
	// or received.
	prepareKeyChange(*algorithms, *kexResult) error
}

// handshakeTransport implements rekeying on top of a keyingTransport
// and offers a thread-safe writePacket() interface.
type handshakeTransport struct {
	conn   keyingTransport
	config *Config

	serverVersion []byte
	clientVersion []byte

	// hostKeys is non-empty if we are the server. In that case,
	// it contains all host keys that can be used to sign the
	// connection.
	hostKeys []Signer

	// hostKeyAlgorithms is non-empty if we are the client. In that case,
	// we accept these key types from the server as host key.
	hostKeyAlgorithms []string

	// On read error, incoming is closed, and readError is set.
	incoming  chan []byte
	readError error

	mu         sync.Mutex
	writeError error
	outgoing   chan []byte

	// If we receive a packet here, send out a kex message.
	requestKex chan struct{}

	// If the other side requests or confirms a kex, its kexInit
	// packet is sent here.
	startKex chan *pendingKex

	// data for host key checking
	hostKeyCallback func(hostname string, remote net.Addr, key PublicKey) error
	dialAddress     string
	remoteAddr      net.Addr

	readSinceKex uint64

	sentInitPacket  []byte
	sentInitMsg     *kexInitMsg
	writtenSinceKex uint64

	// The session ID or nil if first kex did not complete yet.
	sessionID []byte
}

type pendingKex struct {
	otherInit []byte
	done      chan error
}

func newHandshakeTransport(conn keyingTransport, config *Config, clientVersion, serverVersion []byte) *handshakeTransport {
	t := &handshakeTransport{
		conn:          conn,
		serverVersion: serverVersion,
		clientVersion: clientVersion,
		incoming:      make(chan []byte, 16),
		outgoing:      make(chan []byte, 16),
		requestKex:    make(chan struct{}, 1),
		startKex:      make(chan *pendingKex, 1),

		config: config,
	}
	return t
}

func newClientTransport(conn keyingTransport, clientVersion, serverVersion []byte, config *ClientConfig, dialAddr string, addr net.Addr) *handshakeTransport {
	t := newHandshakeTransport(conn, &config.Config, clientVersion, serverVersion)
	t.dialAddress = dialAddr
	t.remoteAddr = addr
	t.hostKeyCallback = config.HostKeyCallback
	if config.HostKeyAlgorithms != nil {
		t.hostKeyAlgorithms = config.HostKeyAlgorithms
	} else {
		t.hostKeyAlgorithms = supportedHostKeyAlgos
	}
	go t.readLoop()
	go t.writeLoop()
	return t
}

func newServerTransport(conn keyingTransport, clientVersion, serverVersion []byte, config *ServerConfig) *handshakeTransport {
	t := newHandshakeTransport(conn, &config.Config, clientVersion, serverVersion)
	t.hostKeys = config.hostKeys
	go t.readLoop()
	go t.writeLoop()
	return t
}

func (t *handshakeTransport) getSessionID() []byte {
	return t.sessionID
}

// waitSession waits for the session to be established. This should be
// the first thing to call after instantiating handshakeTransport.
func (t *handshakeTransport) waitSession() error {
	p, err := t.readPacket()
	if err != nil {
		return err
	}
	if p[0] != msgNewKeys {
		return fmt.Errorf("ssh: first packet should be msgNewKeys")
	}

	return nil
}

func (t *handshakeTransport) id() string {
	if len(t.hostKeys) > 0 {
		return "server"
	}
	return "client"
}

func (t *handshakeTransport) printPacket(p []byte, write bool) {
	action := "got"
	if write {
		action = "sent"
	}
	if p[0] == msgChannelData || p[0] == msgChannelExtendedData {
		log.Printf("%s %s data (packet %d bytes)", t.id(), action, len(p))
	} else {
		msg, err := decode(p)
		log.Printf("%s %s %T %v (%v)", t.id(), action, msg, msg, err)
	}
}

func (t *handshakeTransport) readPacket() ([]byte, error) {
	p, ok := <-t.incoming
	if !ok {
		return nil, t.readError
	}
	return p, nil
}

func (t *handshakeTransport) readLoop() {
	first := true
	for {
		p, err := t.readOnePacket(first)
		first = false
		if err != nil {
			log.Println("readloop exit", t.id())
			t.readError = err
			close(t.incoming)
			break
		}
		if p[0] == msgIgnore || p[0] == msgDebug {
			continue
		}
		t.incoming <- p
	}

	// Stop writers too.
	t.recordWriteError(t.readError)

	// Unblock the writer should he wait for this.
	close(t.requestKex)
	close(t.startKex)
}

func (t *handshakeTransport) pushPacket(p []byte) error {
	if debugHandshake {
		t.printPacket(p, true)
	}
	return t.conn.writePacket(p)
}

func (t *handshakeTransport) recordWriteError(err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.writeError == nil && err != nil {
		t.writeError = err
	}
}

func (t *handshakeTransport) requestKeyExchange() {
	t.requestKex <- struct{}{}
}

func (t *handshakeTransport) writeLoop() {
	// We always start with the mandatory key exchange.
	if _, _, err := t.sendKexInit(); err != nil {
		t.recordWriteError(err)
	}

write:
	for t.writeError == nil {
		var request *pendingKex

		if t.sentInitMsg == nil {
			select {
			case request = <-t.startKex:
				break
			case <-t.requestKex:
				_, _, err := t.sendKexInit()
				t.recordWriteError(err)
				log.Println(t.id(), "request kex")
				break
			case p := <-t.outgoing:
				if p == nil {
					// error.
					break write
				}
				if err := t.pushPacket(p); err != nil {
					t.writeError = err
					break
				}
				t.writtenSinceKex += uint64(len(p))
				if t.writtenSinceKex > t.config.RekeyThreshold {
					_, _, t.writeError = t.sendKexInit()
				}
			}
		}

		if request == nil && t.sentInitMsg == nil {
			continue write
		}

		// Blocking writers can lead to deadlock, since the
		// writers may be driven from our read loop. To avoid
		// deadlock, keep collecting outgoing packets.
		var pendingPackets [][]byte
		stopCollecting := make(chan struct{}, 1)
		collectionDone := make(chan struct{}, 1)
		go func() {
			defer close(collectionDone)
			for {
				select {
				case p := <-t.outgoing:
					if p == nil {
						return
					}
					pendingPackets = append(pendingPackets, p)
				case <-t.requestKex:
					// Keep draining the
					// requestKex channel, just to
					// avoid deadlocks.
				case <-stopCollecting:
					return
				}
			}
		}()

		// Something wants to start a key exchange. If it's
		// us, wait for the remote side to acknowledge.
		if request == nil {
			request = <-t.startKex
			if request == nil {
				stopCollecting <- struct{}{}
				break
			}
		}

		// The read side received a kex packet, which means
		// that the read loop has stopped reading from t.conn,
		// so we can freely use it to execute the kex.
		log.Println("enter-kex", t.id())

		t.recordWriteError(t.enterKeyExchange(request.otherInit))
		t.sentInitPacket = nil
		t.sentInitMsg = nil
		t.writtenSinceKex = 0
		request.done <- t.writeError

		stopCollecting <- struct{}{}
		<-collectionDone

		// kex finished. Push packets that we received while
		// the kex was in progress. Don't look at t.startKex
		// and don't increment writtenSinceKex: if we trigger
		// another kex while we are still busy with the last
		// one, things will become very confusing.
		for _, p := range pendingPackets {
			if t.writeError != nil {
				break write
			}
			if err := t.pushPacket(p); err != nil {
				t.recordWriteError(err)
			}
		}
	}

	// drain channels.
	go func() {
		for range t.outgoing {
		}
	}()
	go func() {
		for range t.requestKex {
		}
	}()
	go func() {
		for range t.startKex {
		}
	}()

	t.conn.Close()
}

func (t *handshakeTransport) readOnePacket(first bool) ([]byte, error) {
	if t.readSinceKex > t.config.RekeyThreshold {
		t.requestKex <- struct{}{}
	}

	p, err := t.conn.readPacket()
	if err != nil {
		return nil, err
	}

	t.readSinceKex += uint64(len(p))
	if debugHandshake {
		t.printPacket(p, false)
	}

	if first && p[0] != msgKexInit {
		return nil, fmt.Errorf("ssh: first packet should be msgKexInit")
	}

	if p[0] != msgKexInit {
		return p, nil
	}

	firstKex := t.sessionID == nil

	kex := pendingKex{
		done:      make(chan error, 1),
		otherInit: p,
	}
	t.startKex <- &kex
	err = <-kex.done

	if debugHandshake {
		log.Printf("%s exited key exchange (first %v), err %v", t.id(), firstKex, err)
	}

	if err != nil {
		return nil, err
	}

	t.readSinceKex = 0

	// By default, a key exchange is hidden from higher layers by
	// translating it into msgIgnore.
	successPacket := []byte{msgIgnore}
	if firstKex {
		// sendKexInit() for the first kex waits for
		// msgNewKeys so the authentication process is
		// guaranteed to happen over an encrypted transport.
		successPacket = []byte{msgNewKeys}
	}

	return successPacket, nil
}

// sendKexInitLocked sends a key change message.
func (t *handshakeTransport) sendKexInit() (*kexInitMsg, []byte, error) {
	// kexInits may be sent either in response to the other side,
	// or because our side wants to initiate a key change, so we
	// may have already sent a kexInit. In that case, don't send a
	// second kexInit.
	if t.sentInitMsg != nil {
		return t.sentInitMsg, t.sentInitPacket, nil
	}

	msg := &kexInitMsg{
		KexAlgos:                t.config.KeyExchanges,
		CiphersClientServer:     t.config.Ciphers,
		CiphersServerClient:     t.config.Ciphers,
		MACsClientServer:        t.config.MACs,
		MACsServerClient:        t.config.MACs,
		CompressionClientServer: supportedCompressions,
		CompressionServerClient: supportedCompressions,
	}
	io.ReadFull(rand.Reader, msg.Cookie[:])

	if len(t.hostKeys) > 0 {
		for _, k := range t.hostKeys {
			msg.ServerHostKeyAlgos = append(
				msg.ServerHostKeyAlgos, k.PublicKey().Type())
		}
	} else {
		msg.ServerHostKeyAlgos = t.hostKeyAlgorithms
	}
	packet := Marshal(msg)

	// writePacket destroys the contents, so save a copy.
	packetCopy := make([]byte, len(packet))
	copy(packetCopy, packet)

	if err := t.pushPacket(packetCopy); err != nil {
		return nil, nil, err
	}

	t.sentInitMsg = msg
	t.sentInitPacket = packet
	return msg, packet, nil
}

func (t *handshakeTransport) writePacket(p []byte) error {
	switch p[0] {
	case msgKexInit:
		return errors.New("ssh: only handshakeTransport can send kexInit")
	case msgNewKeys:
		return errors.New("ssh: only handshakeTransport can send newKeys")
	}

	t.mu.Lock()
	if t.writeError != nil {
		t.mu.Unlock()
		return t.writeError
	}
	t.mu.Unlock()

	t.outgoing <- p
	return nil
}

func (t *handshakeTransport) Close() error {
	close(t.outgoing)
	return nil
}

func (t *handshakeTransport) enterKeyExchange(otherInitPacket []byte) error {
	if debugHandshake {
		log.Printf("%s entered key exchange", t.id())
	}
	myInit, myInitPacket, err := t.sendKexInit()
	if err != nil {
		return err
	}

	otherInit := &kexInitMsg{}
	if err := Unmarshal(otherInitPacket, otherInit); err != nil {
		return err
	}

	magics := handshakeMagics{
		clientVersion: t.clientVersion,
		serverVersion: t.serverVersion,
		clientKexInit: otherInitPacket,
		serverKexInit: myInitPacket,
	}

	clientInit := otherInit
	serverInit := myInit
	if len(t.hostKeys) == 0 {
		clientInit = myInit
		serverInit = otherInit

		magics.clientKexInit = myInitPacket
		magics.serverKexInit = otherInitPacket
	}

	algs, err := findAgreedAlgorithms(clientInit, serverInit)
	if err != nil {
		return err
	}

	// We don't send FirstKexFollows, but we handle receiving it.
	//
	// RFC 4253 section 7 defines the kex and the agreement method for
	// first_kex_packet_follows. It states that the guessed packet
	// should be ignored if the "kex algorithm and/or the host
	// key algorithm is guessed wrong (server and client have
	// different preferred algorithm), or if any of the other
	// algorithms cannot be agreed upon". The other algorithms have
	// already been checked above so the kex algorithm and host key
	// algorithm are checked here.
	if otherInit.FirstKexFollows && (clientInit.KexAlgos[0] != serverInit.KexAlgos[0] || clientInit.ServerHostKeyAlgos[0] != serverInit.ServerHostKeyAlgos[0]) {
		// other side sent a kex message for the wrong algorithm,
		// which we have to ignore.
		if _, err := t.conn.readPacket(); err != nil {
			return err
		}
	}

	kex, ok := kexAlgoMap[algs.kex]
	if !ok {
		return fmt.Errorf("ssh: unexpected key exchange algorithm %v", algs.kex)
	}

	var result *kexResult
	if len(t.hostKeys) > 0 {
		result, err = t.server(kex, algs, &magics)
	} else {
		result, err = t.client(kex, algs, &magics)
	}

	if err != nil {
		return err
	}

	if t.sessionID == nil {
		t.sessionID = result.H
	}
	result.SessionID = t.sessionID

	t.conn.prepareKeyChange(algs, result)
	if err = t.conn.writePacket([]byte{msgNewKeys}); err != nil {
		return err
	}
	if packet, err := t.conn.readPacket(); err != nil {
		return err
	} else if packet[0] != msgNewKeys {
		return unexpectedMessageError(msgNewKeys, packet[0])
	}

	return nil
}

func (t *handshakeTransport) server(kex kexAlgorithm, algs *algorithms, magics *handshakeMagics) (*kexResult, error) {
	var hostKey Signer
	for _, k := range t.hostKeys {
		if algs.hostKey == k.PublicKey().Type() {
			hostKey = k
		}
	}

	r, err := kex.Server(t.conn, t.config.Rand, magics, hostKey)
	return r, err
}

func (t *handshakeTransport) client(kex kexAlgorithm, algs *algorithms, magics *handshakeMagics) (*kexResult, error) {
	result, err := kex.Client(t.conn, t.config.Rand, magics)
	if err != nil {
		return nil, err
	}

	hostKey, err := ParsePublicKey(result.HostKey)
	if err != nil {
		return nil, err
	}

	if err := verifyHostKeySignature(hostKey, result); err != nil {
		return nil, err
	}

	if t.hostKeyCallback != nil {
		err = t.hostKeyCallback(t.dialAddress, t.remoteAddr, hostKey)
		if err != nil {
			return nil, err
		}
	}

	return result, nil
}
