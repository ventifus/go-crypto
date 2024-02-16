// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"io"
	"os"
	"sync"
	"time"
)

// buffer provides a linked list buffer for data exchange
// between producer and consumer. Theoretically the buffer is
// of unlimited capacity as it does no allocation of its own.
type buffer struct {
	// protects concurrent access to head, tail and closed
	*sync.Cond

	head *element // the buffer that will be read first
	tail *element // the buffer that will be read last

	closed          bool
	deadlineReached bool
	timer           *time.Timer
}

// An element represents a single link in a linked list.
type element struct {
	buf  []byte
	next *element
}

// newBuffer returns an empty buffer that is not closed.
func newBuffer() *buffer {
	e := new(element)
	b := &buffer{
		Cond: newCond(),
		head: e,
		tail: e,
	}
	return b
}

// write makes buf available for Read to receive.
// buf must not be modified after the call to write.
func (b *buffer) write(buf []byte) {
	b.Cond.L.Lock()
	e := &element{buf: buf}
	b.tail.next = e
	b.tail = e
	b.Cond.Signal()
	b.Cond.L.Unlock()
}

// eof closes the buffer. Reads from the buffer once all
// the data has been consumed will receive io.EOF.
func (b *buffer) eof() {
	b.Cond.L.Lock()
	b.closed = true
	if b.timer != nil {
		b.timer.Stop()
		b.timer = nil
	}
	b.Cond.Signal()
	b.Cond.L.Unlock()
}

func (b *buffer) setDeadline(deadline time.Time) {
	if !deadline.IsZero() && deadline.Before(time.Now()) {
		// Unblock read, if any.
		b.deadline()
		return
	}
	b.Cond.L.Lock()
	defer b.Cond.L.Unlock()

	b.deadlineReached = false
	if b.timer != nil {
		b.timer.Stop()
		b.timer = nil
	}
	if deadline.IsZero() {
		return
	}
	b.timer = time.AfterFunc(time.Until(deadline), func() {
		b.deadline()
	})
}

func (b *buffer) deadline() {
	b.Cond.L.Lock()
	b.deadlineReached = true
	b.Cond.Signal()
	b.Cond.L.Unlock()
}

// Read reads data from the internal buffer in buf.  Reads will block
// if no data is available, or until the buffer is closed.
func (b *buffer) Read(buf []byte) (n int, err error) {
	b.Cond.L.Lock()
	defer b.Cond.L.Unlock()

	if b.deadlineReached {
		return 0, os.ErrDeadlineExceeded
	}

	for len(buf) > 0 {
		// if there is data in b.head, copy it
		if len(b.head.buf) > 0 {
			r := copy(buf, b.head.buf)
			buf, b.head.buf = buf[r:], b.head.buf[r:]
			n += r
			continue
		}
		// if there is a next buffer, make it the head
		if len(b.head.buf) == 0 && b.head != b.tail {
			b.head = b.head.next
			continue
		}

		// if at least one byte has been copied, return
		if n > 0 {
			break
		}

		// if nothing was read, and there is nothing outstanding
		// check to see if the buffer is closed.
		if b.closed {
			err = io.EOF
			break
		}
		// check if the deadline was reached.
		if b.deadlineReached {
			err = os.ErrDeadlineExceeded
			break
		}
		// out of buffers, wait for producer
		b.Cond.Wait()
	}
	return
}
