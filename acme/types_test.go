// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package acme

import (
	"net/http"
	"testing"
	"time"
)

func TestRateLimitedError(t *testing.T) {
	h := http.Header{}
	h.Set("Retry-After", "120")

	e := &Error{
		StatusCode:  400,
		ProblemType: "urn:ietf:params:acme:error:rateLimited",
		Header:      h,
	}

	f, ok := IsRateLimited(e)
	if !ok {
		t.Fatal("expected a rate limited error, got false")
	}

	if !f.After(time.Now()) {
		t.Fatal("expected a future time, got %v", f)
	}
}
