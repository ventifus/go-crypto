package ssh

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"math/big"
)

func init() {
	gexServerFunc = gexServer
}

func gexServer(gex *dhGEXSHA, c packetConn, randSource io.Reader, magics *handshakeMagics, priv Signer) (result *kexResult, err error) {
	// Receive GexRequest
	packet, err := c.readPacket()
	if err != nil {
		return
	}
	var kexDHGexRequest kexDHGexRequestMsg
	if err = Unmarshal(packet, &kexDHGexRequest); err != nil {
		return
	}

	// smoosh the user's preferred size into our own limits
	if kexDHGexRequest.PreferedBits > dhGroupExchangeMaximumBits {
		kexDHGexRequest.PreferedBits = dhGroupExchangeMaximumBits
	}
	if kexDHGexRequest.PreferedBits < dhGroupExchangeMinimumBits {
		kexDHGexRequest.PreferedBits = dhGroupExchangeMinimumBits
	}
	// fix min/max if they're inconsistent.  technically, we could just pout
	// and hang up, but there's no harm in giving them the benefit of the
	// doubt and just picking a bitsize for them.
	if kexDHGexRequest.MinBits > kexDHGexRequest.PreferedBits {
		kexDHGexRequest.MinBits = kexDHGexRequest.PreferedBits
	}
	if kexDHGexRequest.MaxBits < kexDHGexRequest.PreferedBits {
		kexDHGexRequest.MaxBits = kexDHGexRequest.PreferedBits
	}

	// Send GexGroup
	// This is the group called diffie-hellman-group14-sha1 in RFC
	// 4253 and Oakley Group 14 in RFC 3526.
	p, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)
	gex.p = p
	gex.g = big.NewInt(2)

	kexDHGexGroup := kexDHGexGroupMsg{
		P: gex.p,
		G: gex.g,
	}
	if err := c.writePacket(Marshal(&kexDHGexGroup)); err != nil {
		return nil, err
	}

	// Receive GexInit
	packet, err = c.readPacket()
	if err != nil {
		return
	}
	var kexDHGexInit kexDHGexInitMsg
	if err = Unmarshal(packet, &kexDHGexInit); err != nil {
		return
	}

	var pHalf = &big.Int{}
	pHalf.Rsh(gex.p, 1)

	y, err := rand.Int(randSource, pHalf)
	if err != nil {
		return
	}

	Y := new(big.Int).Exp(gex.g, y, gex.p)
	kInt, err := gex.diffieHellman(kexDHGexInit.X, y)
	if err != nil {
		return nil, err
	}

	hostKeyBytes := priv.PublicKey().Marshal()

	h := gex.hashFunc.New()
	magics.write(h)
	writeString(h, hostKeyBytes)
	binary.Write(h, binary.BigEndian, uint32(dhGroupExchangeMinimumBits))
	binary.Write(h, binary.BigEndian, uint32(dhGroupExchangePreferredBits))
	binary.Write(h, binary.BigEndian, uint32(dhGroupExchangeMaximumBits))
	writeInt(h, gex.p)
	writeInt(h, gex.g)
	writeInt(h, kexDHGexInit.X)
	writeInt(h, Y)

	K := make([]byte, intLength(kInt))
	marshalInt(K, kInt)
	h.Write(K)

	H := h.Sum(nil)

	// H is already a hash, but the hostkey signing will apply its
	// own key-specific hash algorithm.
	sig, err := signAndMarshal(priv, randSource, H)
	if err != nil {
		return nil, err
	}

	kexDHGexReply := kexDHGexReplyMsg{
		HostKey:   hostKeyBytes,
		Y:         Y,
		Signature: sig,
	}
	packet = Marshal(&kexDHGexReply)

	err = c.writePacket(packet)

	return &kexResult{
		H:         H,
		K:         K,
		HostKey:   hostKeyBytes,
		Signature: sig,
		Hash:      gex.hashFunc,
	}, err
}
