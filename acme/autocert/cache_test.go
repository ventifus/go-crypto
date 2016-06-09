package autocert

import (
	"io/ioutil"
	"path/filepath"
	"reflect"
	"testing"
)

// make sure DirCache satisfies Cache interface
var _ Cache = DirCache("/")

func TestDirCache(t *testing.T) {
	dir, err := ioutil.TempDir("", "acmecache")
	if err != nil {
		t.Fatal(err)
	}
	dir = filepath.Join(dir, "certs") // a nonexistent dir
	cache := DirCache(dir)

	// test cache miss
	if _, _, err := cache.Get("nonexistent"); err != ErrCacheMiss {
		t.Errorf("get: %v; want ErrCacheMiss", err)
	}

	// test put/get
	b1, b2 := []byte{1}, []byte{2}
	if err := cache.Put("dummy", b1, b2); err != nil {
		t.Fatalf("put: %v", err)
	}
	b11, b22, err := cache.Get("dummy")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !reflect.DeepEqual(b1, b11) {
		t.Errorf("b1 = %v; want %v", b1, b11)
	}
	if !reflect.DeepEqual(b2, b22) {
		t.Errorf("b2 = %v; want %v", b2, b22)
	}

	// test delete
	if err := cache.Delete("dummy"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, _, err := cache.Get("dummy"); err != ErrCacheMiss {
		t.Errorf("get: %v; want ErrCacheMiss", err)
	}
}
