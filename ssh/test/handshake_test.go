// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package test

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// SSH reference tests run a connection against a reference implementation
// (OpenSSH) of SSH and record the bytes of the resulting connection. The Go
// code, during a test, is configured with deterministic randomness and so the
// reference test can be reproduced exactly in the future.
//
// In order to save everyone who wishes to run the tests from needing the
// reference implementation installed, the reference connections are saved in
// files in the testdata directory. Thus running the tests involves nothing
// external, but creating and updating them requires the reference
// implementation.
//
// Tests can be updated by running them with the -update flag. This will cause
// the test files for failing tests to be regenerated. Since the reference
// implementation will always generate fresh random numbers, large parts of the
// reference connection will always change.

var (
	update = flag.Bool("update", false, "update golden files on failure")
)

func runTestAndUpdateIfNeeded(t *testing.T, name string, run func(t *testing.T, update bool)) {
	success := t.Run(name, func(t *testing.T) {
		if !*update {
			t.Parallel()
		}
		run(t, false)
	})

	if !success && *update {
		t.Run(name+"#update", func(t *testing.T) {
			run(t, true)
		})
	}
}

// recordingConn is a net.Conn that records the traffic that passes through it.
// WriteTo can be used to produce output that can be later be loaded with
// ParseTestData.
type recordingConn struct {
	net.Conn
	clientToServer bool
	sync.Mutex
	flows   [][]byte
	reading bool
}

func (r *recordingConn) Read(b []byte) (n int, err error) {
	if n, err = r.Conn.Read(b); n == 0 {
		return
	}
	b = b[:n]

	r.Lock()
	defer r.Unlock()

	if l := len(r.flows); l == 0 || !r.reading {
		buf := make([]byte, len(b))
		copy(buf, b)
		r.flows = append(r.flows, buf)
	} else {
		r.flows[l-1] = append(r.flows[l-1], b[:n]...)
	}
	r.reading = true
	return
}

func (r *recordingConn) Write(b []byte) (n int, err error) {
	if n, err = r.Conn.Write(b); n == 0 {
		return
	}
	b = b[:n]

	r.Lock()
	defer r.Unlock()

	if l := len(r.flows); l == 0 || r.reading {
		buf := make([]byte, len(b))
		copy(buf, b)
		r.flows = append(r.flows, buf)
	} else {
		r.flows[l-1] = append(r.flows[l-1], b[:n]...)
	}
	r.reading = false
	return
}

// WriteTo writes Go source code to w that contains the recorded traffic.
func (r *recordingConn) WriteTo(w io.Writer) (int64, error) {
	var written int64
	for i, flow := range r.flows {
		source, dest := "client", "server"
		if !r.clientToServer {
			source, dest = dest, source
		}
		n, err := fmt.Fprintf(w, ">>> Flow %d (%s to %s)\n", i+1, source, dest)
		written += int64(n)
		if err != nil {
			return written, err
		}
		dumper := hex.Dumper(w)
		n, err = dumper.Write(flow)
		written += int64(n)
		if err != nil {
			return written, err
		}
		err = dumper.Close()
		if err != nil {
			return written, err
		}
		r.clientToServer = !r.clientToServer
	}
	return written, nil
}

func parseTestData(r io.Reader) (flows [][]byte, err error) {
	var currentFlow []byte

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		// If the line starts with ">>> " then it marks the beginning
		// of a new flow.
		if strings.HasPrefix(line, ">>> ") {
			if len(currentFlow) > 0 || len(flows) > 0 {
				flows = append(flows, currentFlow)
				currentFlow = nil
			}
			continue
		}

		// Otherwise the line is a line of hex dump that looks like:
		// 00000170  fc f5 06 bf (...)  |.....X{&?......!|
		// (Some bytes have been omitted from the middle section.)
		_, after, ok := strings.Cut(line, " ")
		if !ok {
			return nil, errors.New("invalid test data")
		}
		line = after

		before, _, ok := strings.Cut(line, "|")
		if !ok {
			return nil, errors.New("invalid test data")
		}
		line = before

		hexBytes := strings.Fields(line)
		for _, hexByte := range hexBytes {
			val, err := strconv.ParseUint(hexByte, 16, 8)
			if err != nil {
				return nil, errors.New("invalid hex byte in test data: " + err.Error())
			}
			currentFlow = append(currentFlow, byte(val))
		}
	}

	if len(currentFlow) > 0 {
		flows = append(flows, currentFlow)
	}

	return flows, nil
}

func newReplayingConn(t testing.TB, flows [][]byte, reading bool) net.Conn {
	r := &replayingConn{
		t:       t,
		flows:   flows,
		reading: reading,
		//readyToRead: make(chan struct{}, 2),
	}
	r.readCond = sync.NewCond(&r.Mutex)
	return r
}

// replayingConn is a net.Conn that replays flows recorded by recordingConn.
type replayingConn struct {
	t testing.TB
	sync.Mutex
	flows   [][]byte
	reading bool
	// SSH channels use a read loop goroutine, we use this condition to wait
	// until we are ready to read/write.
	readCond *sync.Cond
	//readyToRead chan struct{}
}

var _ net.Conn = (*replayingConn)(nil)

// mettere un time afterfunc che dopo 10 secondi stampa "the test may be stuck try using -5 seconds"
// fare il cleanup del timer. Metterlo nel test in generale
func (r *replayingConn) Read(b []byte) (n int, err error) {
	r.Lock()
	defer r.Unlock()

	for !r.reading {
		r.readCond.Wait()
	}

	n = copy(b, r.flows[0])
	r.flows[0] = r.flows[0][n:]
	if len(r.flows[0]) == 0 {
		r.flows = r.flows[1:]
		r.reading = false
		r.readCond.Broadcast()
		if len(r.flows) == 0 {
			return n, io.EOF
		}
	}
	return n, nil
}

func (r *replayingConn) Write(b []byte) (n int, err error) {
	r.Lock()
	defer r.Unlock()

	for r.reading {
		r.readCond.Wait()
	}

	if !bytes.HasPrefix(r.flows[0], b) {
		r.t.Errorf("write mismatch: expected %x, got %x", r.flows[0], b)
		r.reading = true
		r.readCond.Broadcast()
		return 0, fmt.Errorf("write mismatch")
	}
	r.flows[0] = r.flows[0][len(b):]
	if len(r.flows[0]) == 0 {
		r.flows = r.flows[1:]
		r.reading = true
		r.readCond.Broadcast()
	}
	return len(b), nil
}

func (r *replayingConn) Close() error {
	r.Lock()
	defer r.Unlock()

	if len(r.flows) > 0 {
		r.t.Errorf("closed with unfinished flows: %d", len(r.flows))
		return fmt.Errorf("unexpected close")
	}
	return nil
}

func (r *replayingConn) LocalAddr() net.Addr                { return nil }
func (r *replayingConn) RemoteAddr() net.Addr               { return nil }
func (r *replayingConn) SetDeadline(t time.Time) error      { return nil }
func (r *replayingConn) SetReadDeadline(t time.Time) error  { return nil }
func (r *replayingConn) SetWriteDeadline(t time.Time) error { return nil }

// localListener is set up by TestMain and used by localPipe to create Conn
// pairs like net.Pipe, but connected by an actual buffered TCP connection.
var localListener struct {
	mu   sync.Mutex
	addr net.Addr
	ch   chan net.Conn
}

const localFlakes = 0 // change to 1 or 2 to exercise localServer/localPipe handling of mismatches

func localServer(l net.Listener) {
	for n := 0; ; n++ {
		c, err := l.Accept()
		if err != nil {
			return
		}
		if localFlakes == 1 && n%2 == 0 {
			c.Close()
			continue
		}
		localListener.ch <- c
	}
}

func TestMain(m *testing.M) {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s:\n", os.Args)
		flag.PrintDefaults()
	}

	flag.Parse()
	os.Exit(runMain(m))
}

func runMain(m *testing.M) int {
	// Set up localPipe.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		l, err = net.Listen("tcp6", "[::1]:0")
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open local listener: %v", err)
		os.Exit(1)
	}
	localListener.ch = make(chan net.Conn)
	localListener.addr = l.Addr()
	defer l.Close()
	go localServer(l)

	return m.Run()
}
