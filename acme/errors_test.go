// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package acme

import (
	"io/ioutil"
	"net/http"
	"strings"
	"testing"
)

func TestResponseError(t *testing.T) {
	err500 := &Error{Status: 500, Detail: "500 Internal"}
	errTLS := &Error{Status: 500, Type: ErrTLS, Detail: "TLS err"}
	errMal := &Error{Status: 409, Type: ErrMalformed, Detail: "Already in use"}
	tests := []struct {
		body   string
		status string
		code   int
		err    *Error
	}{
		// won't unmarshal: should take resp.Status and .StatusCode
		{"", "500 Internal", 500, err500},
		// no "status" in JSON error: should take it from resp.Status
		{`{"type":"urn:acme:error:tls","detail":"TLS err"}`, "500 Server Error", 500, errTLS},
		// resp.StatusCode and "status" JSON field different: make sure we prefer what's in the JSON error
		{`{"type":"urn:acme:error:malformed","detail":"Already in use","status":409}`, "400 Bad Request", 400, errMal},
	}
	for i, test := range tests {
		res := &http.Response{
			Body:       ioutil.NopCloser(strings.NewReader(test.body)),
			Status:     test.status,
			StatusCode: test.code,
		}
		err := responseError(res).(*Error)
		if err.Status != test.err.Status {
			t.Errorf("%d: err.Status = %d; want %d", i, err.Status, test.err.Status)
		}
		if err.Type != test.err.Type {
			t.Errorf("%d: err.Type = %q; want %q", i, err.Type, test.err.Type)
		}
		if err.Detail != test.err.Detail {
			t.Errorf("%d: err.Detail = %q; want %q", i, err.Detail, test.err.Detail)
		}
		if err.Response != res {
			t.Errorf("%d: err.Response = %p; want %p", i, err.Response, res)
		}
	}
}
