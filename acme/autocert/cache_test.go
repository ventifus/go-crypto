package autocert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io/ioutil"
	"math/big"
	"reflect"
	"testing"
)

// make sure DirCache satisfies Cache interface
var _ Cache = DirCache("/")

func TestDirCacheGet(t *testing.T) {
	dir, err := ioutil.TempDir("", "acmecache")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("cache dir: %s", dir)
	cache := DirCache(dir)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.org"},
		DNSNames:     []string{"a.example.org", "b.example.org"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	tlscert := tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
	}

	// test put
	if err := cache.Put(tlscert); err != nil {
		t.Fatalf("cache.Put: %v", err)
	}

	// test get
	for _, name := range append(tmpl.DNSNames, tmpl.Subject.CommonName) {
		tlscert1, err := cache.Get(name)
		if err != nil {
			t.Errorf("%q: cache.Get: %v", name, err)
			continue
		}
		cert, err := x509.ParseCertificate(tlscert1.Certificate[0])
		if err != nil {
			t.Errorf("%q: ParseCertificate: %v", name, err)
			continue
		}
		if cert.Subject.CommonName != tmpl.Subject.CommonName {
			t.Errorf("%q: CN = %q; want %q", name, cert.Subject.CommonName, tmpl.Subject.CommonName)
		}
		if !reflect.DeepEqual(cert.DNSNames, tmpl.DNSNames) {
			t.Errorf("%q: DNSNames = %v; want %v", name, cert.DNSNames, tmpl.DNSNames)
		}
		priv, ok := tlscert1.PrivateKey.(*rsa.PrivateKey)
		if !ok {
			t.Error("%q: PrivateKey is %T; want *rsa.PrivateKey", name, tlscert1.PrivateKey)
			continue
		}
		if priv.N.Cmp(key.N) != 0 {
			t.Errorf("%q: priv.N = %v; want %v", name, priv.N, key.N)
		}
	}
}
