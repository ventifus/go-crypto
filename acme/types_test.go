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

	d, ok := IsRateLimited(e)
	if !ok {
		t.Fatal("expected a rate limited error")
	}

	ex := time.Duration(120) * time.Second
	if d != ex {
		t.Fatalf("expected %v, got %v", ex, d)
	}
}
