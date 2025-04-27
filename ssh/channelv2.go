// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

// NewChannelV2 represents an incoming request to a channel. It must either be
// accepted for use by calling Accept, or rejected by calling Reject.
type NewChannelV2 struct {
	ch *channel
}

// Accept accepts the channel creation request. The returned channel must be
// serviced using [Channel.Handle].
func (c *NewChannelV2) Accept() (*ChannelV2, error) {
	return c.ch.AcceptV2()
}

// Reject rejects the channel creation request. After calling
// this, no other methods on the Channel may be called.
func (c *NewChannelV2) Reject(reason RejectionReason, message string) error {
	return c.ch.Reject(reason, message)
}

// ChannelType returns the type of the channel, as supplied by the
// client.
func (c *NewChannelV2) ChannelType() string {
	return c.ch.ChannelType()
}

// ExtraData returns the arbitrary payload for this channel, as supplied
// by the client. This data is specific to the channel type.
func (c *NewChannelV2) ExtraData() []byte {
	return c.ch.ExtraData()
}

// A ChannelV2 is an ordered, reliable, flow-controlled, duplex stream
// that is multiplexed over an SSH connection.
type ChannelV2 struct {
	*channel
}

func (ch *channel) AcceptV2() (*ChannelV2, error) {
	if ch.decided {
		return nil, errDecidedAlready
	}
	ch.maxIncomingPayload = channelMaxPacket
	confirm := channelOpenConfirmMsg{
		PeersID:       ch.remoteId,
		MyID:          ch.localId,
		MyWindow:      ch.myWindow,
		MaxPacketSize: ch.maxIncomingPayload,
	}
	ch.decided = true
	if err := ch.sendMessage(confirm); err != nil {
		return nil, err
	}

	return &ChannelV2{channel: ch}, nil
}

func (ch *channel) Handle(handler RequestHandlerV2) error {
	for req := range ch.incomingRequests {
		if handler != nil {
			handler.NewRequest(req)
		} else {
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}
	return nil
}
