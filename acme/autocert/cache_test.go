// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package autocert

import (
	"io/ioutil"
	"path/filepath"
	"reflect"
	"testing"

	"golang.org/x/net/context"
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
	ctx := context.Background()

	// test cache miss
	if _, _, err := cache.Get(ctx, "nonexistent"); err != ErrCacheMiss {
		t.Errorf("get: %v; want ErrCacheMiss", err)
	}

	// test put/get
	b1, b2 := []byte{1}, []byte{2}
	if err := cache.Put(ctx, "dummy", b1, b2); err != nil {
		t.Fatalf("put: %v", err)
	}
	b11, b22, err := cache.Get(ctx, "dummy")
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
	if err := cache.Delete(ctx, "dummy"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, _, err := cache.Get(ctx, "dummy"); err != ErrCacheMiss {
		t.Errorf("get: %v; want ErrCacheMiss", err)
	}
}
