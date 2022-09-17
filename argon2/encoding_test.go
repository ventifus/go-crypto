// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package argon2

import (
	"reflect"
	"testing"
)

// generated with reference implementation:
// echo -n "password" | argon2 randomsaltishard -id -t 3 -m 12 -p 1 -l 32 -e
const testEncoded = `$argon2id$v=19$m=4096,t=3,p=1$cmFuZG9tc2FsdGlzaGFyZA$DYojYpnUWSMmTtrkVXyaNWVGxLmGe1n8VJBPDdFkbjU`

var testEncoding = &encoding{
	mode:        argon2id,
	version:     Version,
	memory:      4096,
	time:        3,
	parallelism: 1,
	salt:        []byte("randomsaltishard"),
	key:         IDKey([]byte("password"), []byte("randomsaltishard"), 3, 4096, 1, 32),
}

func Test_encoding_String(t *testing.T) {
	if got := testEncoding.String(); got != testEncoded {
		t.Errorf("encoding.String() =\n%v\nwant\n%v", got, testEncoded)
	}
}

func Test_decode(t *testing.T) {
	tests := []struct {
		name    string
		encoded string
		want    *encoding
		wantErr bool
	}{
		{
			name:    "scan error",
			encoded: "!",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "mode error",
			encoded: `$foobar$v=19$m=4096,t=3,p=1$c29tZXNhbHQ$qLml5cbqFAO6YxVHhrSBHP0UWdxrIxkNcM8aMX3blzU`,
			want:    nil,
			wantErr: true,
		},
		{
			name:    "salt error",
			encoded: `$argon2id$v=19$m=4096,t=3,p=1$!!!!!$qLml5cbqFAO6YxVHhrSBHP0UWdxrIxkNcM8aMX3blzU`,
			want:    nil,
			wantErr: true,
		},
		{
			name:    "key error",
			encoded: `$argon2id$v=19$m=4096,t=3,p=1$c29tZXNhbHQ$!!!!!!!!`,
			want:    nil,
			wantErr: true,
		},
		{
			name:    "success",
			encoded: testEncoded,
			want:    testEncoding,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decode(tt.encoded)
			if (err != nil) != tt.wantErr {
				t.Errorf("decode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("decode() = %v, want %v", got, tt.want)
			}
		})
	}
}
