package acme

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestDefaultBackoff(t *testing.T) {
	tt := []struct {
		nretry     int
		retryAfter string // Retry-After header
		out        time.Duration
	}{
		{0, "", time.Second},
		{1, "", 2 * time.Second},
		{2, "", 4 * time.Second},
		{3, "", 8 * time.Second},
		{-1, "", time.Second},
		{100, "", 10 * time.Second},
		{0, "3600", time.Hour},
	}
	for i, test := range tt {
		r := httptest.NewRequest("GET", "/", nil)
		resp := &http.Response{Header: http.Header{}}
		if test.retryAfter != "" {
			resp.Header.Set("Retry-After", test.retryAfter)
		}
		d := defaultBackoff(test.nretry, r, resp)
		max := test.out + time.Second // + max jitter
		if d < test.out || max < d {
			t.Errorf("%d: defaultBackoff(%v) = %v; want between %v and %v", i, test.nretry, d, test.out, max)
		}
	}
}

func TestErrorResponse(t *testing.T) {
	s := `{
		"status": 400,
		"type": "urn:acme:error:xxx",
		"detail": "text"
	}`
	res := &http.Response{
		StatusCode: 400,
		Status:     "400 Bad Request",
		Body:       ioutil.NopCloser(strings.NewReader(s)),
		Header:     http.Header{"X-Foo": {"bar"}},
	}
	err := responseError(res)
	v, ok := err.(*Error)
	if !ok {
		t.Fatalf("err = %+v (%T); want *Error type", err, err)
	}
	if v.StatusCode != 400 {
		t.Errorf("v.StatusCode = %v; want 400", v.StatusCode)
	}
	if v.ProblemType != "urn:acme:error:xxx" {
		t.Errorf("v.ProblemType = %q; want urn:acme:error:xxx", v.ProblemType)
	}
	if v.Detail != "text" {
		t.Errorf("v.Detail = %q; want text", v.Detail)
	}
	if !reflect.DeepEqual(v.Header, res.Header) {
		t.Errorf("v.Header = %+v; want %+v", v.Header, res.Header)
	}
}

func TestPostWithRetries(t *testing.T) {
	var count int
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count++
		w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce%d", count))
		if r.Method == "HEAD" {
			// We expect the client to do 2 head requests to fetch
			// nonces, one to start and another after getting badNonce
			return
		}

		head, err := decodeJWSHead(r)
		if err != nil {
			t.Errorf("decodeJWSHead: %v", err)
		} else if head.Nonce == "" {
			t.Error("head.Nonce is empty")
		} else if head.Nonce == "nonce1" {
			// return a badNonce error to force the call to retry
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"type":"urn:ietf:params:acme:error:badNonce"}`))
			return
		}
		// Make client.Authorize happy; we're not testing its result.
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"status":"valid"}`))
	}))
	defer ts.Close()

	client := Client{Key: testKey, dir: &Directory{AuthzURL: ts.URL}}
	// This call will fail with badNonce, causing a retry
	if _, err := client.Authorize(context.Background(), "example.com"); err != nil {
		t.Errorf("client.Authorize 1: %v", err)
	}
	if count != 4 {
		t.Errorf("total requests count: %d; want 4", count)
	}
}
