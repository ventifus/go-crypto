package ssh

import (
	"bytes"
	"compress/flate"
	"compress/zlib"
	"log"
	"testing"
)

func TestZlibPartialFlush(t *testing.T) {
	// Packet from SSH client
	compr := "x\x9c\x8ab```/N-.\xce\xcc\xcfc\x00\x01\x05\x10\xd1\xc0\x00\x10"

	// Corresponding uncompressed data
	plain := "Z\x00\x00\x00\asession\x00\x00\x00\x00\x00 \x00\x00\x00\x00\x80\x00"

	marker := []byte{0, 0, 0xff, 0xff}

	buf := &bytes.Buffer{}
	w, err := zlib.NewWriterLevel(buf, 6)

	n, err := w.Write([]byte(plain))
	log.Printf("n %d err %v", n, err)

	// Empty; data is buffered up.
	log.Printf("out %q", buf.Bytes())
	// want this
	log.Printf("wnt %q", compr)

	w.Flush()

	// Now we get the data, but also the sync marker
	log.Printf("out  %q", buf.Bytes())
	log.Printf("want %q", compr)

	rbuf := &bytes.Buffer{}
	rbuf.Write([]byte(compr))
	rbuf.Write(marker)
	r, err := zlib.NewReader(rbuf)
	log.Println("nr", err)

	dec := make([]byte, 1024)
	if n, err := r.Read(dec); err != nil {
		log.Println("r", n, err)
	} else {
		log.Printf("dec %q", dec[:n])
	}

	fbuf := &bytes.Buffer{}
	fw, err := flate.NewWriter(fbuf, 6)
	log.Printf("err %v", err)
	n, err = fw.Write([]byte(plain))
	fw.Flush()
	log.Printf("n %d err %v", n, err)
	log.Printf("out  %q", fbuf.Bytes())
	log.Printf("want %q", compr[2:])
}
