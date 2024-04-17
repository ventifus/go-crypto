// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package autocert

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"fmt"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert/internal/acmetest"
)

func TestRenewalNext(t *testing.T) {
	now := time.Now()
	man := &Manager{
		nowFunc: func() time.Time { return now },
	}
	defer man.stopRenew()
	const day = 24 * time.Hour
	tt := []struct {
		renewBefore time.Duration
		validPeriod time.Duration
		notAfter    time.Time
		min, max    time.Duration
	}{
		{7 * day, 90 * day, now.Add(90 * day), 83*day - renewJitter, 83 * day},
		{7 * day, 90 * day, now.Add(time.Hour), 0, 1},
		{7 * day, 90 * day, now, 0, 1},
		{7 * day, 90 * day, now.Add(-time.Hour), 0, 1},

		// If RenewBefore is 0, we refresh around when certificate is at 2/3 of its
		// lifetime, but never sooner than 30 days before expiration (ignoring random
		// jitter).
		{0, 90 * day, now.Add(90 * day), 60*day - renewJitter, 60 * day},
		{0, 90 * day, now.Add(60 * day), 30*day - renewJitter, 30 * day},
		{0, 90 * day, now, 0, 1},
		{0, 365 * day, now.Add(365 * day), 365*day - 30*day - renewJitter, 365*day - 30*day},
		{0, 365 * day, now.Add(265 * day), 265*day - 30*day - renewJitter, 265*day - 30*day},
		{0, 365 * day, now, 0, 1},
		{0, 3 * day, now.Add(3 * day), 2*day - renewJitter, 2 * day},
		{0, 3 * day, now.Add(2 * day), 1*day - renewJitter, 1 * day},
		{0, 3 * day, now, 0, 1},

		// Nonzero renewBefore less than 1h is treated as 30d.
		{time.Hour - 1, 90 * day, now.Add(90 * day), 60*day - renewJitter, 60 * day},
		{-1, 90 * day, now.Add(60 * day), 30*day - renewJitter, 30 * day},
		{1, 90 * day, now, 0, 1},
	}

	dr := &domainRenewal{m: man}
	for i, test := range tt {
		man.RenewBefore = test.renewBefore
		notBefore := test.notAfter.Add(-test.validPeriod)
		next := dr.next(notBefore, test.notAfter)
		if next < test.min || test.max < next {
			t.Errorf("%d: next = %v; want between %v and %v", i, next, test.min, test.max)
		}
	}
}

func TestRenewFromCache(t *testing.T) {
	const day = 24 * time.Hour
	slop := renewJitter + 5*time.Minute // Extra time for refresh/tests to complete.
	testRenewFromCache(t, day, 90*day, 90*day-day-slop)
	testRenewFromCache(t, 30*day, 90*day, 90*day-30*day-slop)
	testRenewFromCache(t, 0, 90*day, 90*day-30*day-slop)
	testRenewFromCache(t, 0, 7*day, 7*day*2/3-slop)
	testRenewFromCache(t, 0, 365*day, 365*day-30*day-slop)
}

func testRenewFromCache(t *testing.T, renewBefore time.Duration, validityPeriod time.Duration, expectAfter time.Duration) {
	descr := fmt.Sprintf("renewBefore %v, validityPeriod %v", renewBefore, validityPeriod)

	man := testManager(t)
	man.RenewBefore = renewBefore

	ca := acmetest.NewCAServer(t, validityPeriod).Start()
	ca.ResolveGetCertificate(exampleDomain, man.GetCertificate)

	man.Client = &acme.Client{
		DirectoryURL: ca.URL(),
	}

	// cache an almost expired cert
	now := time.Now()
	c := ca.LeafCert(exampleDomain, "ECDSA", now.Add(-validityPeriod), now.Add(time.Minute))
	if err := man.cachePut(context.Background(), exampleCertKey, c); err != nil {
		t.Fatalf("%s: %v", descr, err)
	}

	// verify the renewal happened
	defer func() {
		// Stop the timers that read and execute testDidRenewLoop before restoring it.
		// Otherwise the timer callback may race with the deferred write.
		man.stopRenew()
		testDidRenewLoop = func(next time.Duration, err error) {}
	}()
	renewed := make(chan bool, 1)
	testDidRenewLoop = func(next time.Duration, err error) {
		defer func() {
			select {
			case renewed <- true:
			default:
				// The renewal timer uses a random backoff. If the first renewal fails for
				// some reason, we could end up with multiple calls here before the test
				// stops the timer.
			}
		}()

		if err != nil {
			t.Errorf("%s: testDidRenewLoop: %v", descr, err)
		}
		// Next should be about at validityPeriod - renewBefore if renewBefore is set.
		// Otherwise at 2/3 of validityPeriod with a max of 30 days.
		if next < expectAfter {
			t.Errorf("%s: testDidRenewLoop: next = %v; want >= %v", descr, next, expectAfter)
		}

		// ensure the new cert is cached
		after := time.Now().Add(expectAfter)
		tlscert, err := man.cacheGet(context.Background(), exampleCertKey)
		if err != nil {
			t.Errorf("%s: man.cacheGet: %v", descr, err)
			return
		}
		if !tlscert.Leaf.NotAfter.After(after) {
			t.Errorf("%s: cache leaf.NotAfter = %v; want > %v", descr, tlscert.Leaf.NotAfter, after)
		}

		// verify the old cert is also replaced in memory
		man.stateMu.Lock()
		defer man.stateMu.Unlock()
		s := man.state[exampleCertKey]
		if s == nil {
			t.Errorf("%s: m.state[%q] is nil", descr, exampleCertKey)
			return
		}
		tlscert, err = s.tlscert()
		if err != nil {
			t.Errorf("%s: s.tlscert: %v", descr, err)
			return
		}
		if !tlscert.Leaf.NotAfter.After(after) {
			t.Errorf("%s: state leaf.NotAfter = %v; want > %v", descr, tlscert.Leaf.NotAfter, after)
		}
	}

	// trigger renew
	hello := clientHelloInfo(exampleDomain, algECDSA)
	if _, err := man.GetCertificate(hello); err != nil {
		t.Fatal(err)
	}
	<-renewed
}

func TestRenewFromCacheAlreadyRenewed(t *testing.T) {
	ca := acmetest.NewCAServer(t, 90*24*time.Hour).Start()
	man := testManager(t)
	man.RenewBefore = 24 * time.Hour
	man.Client = &acme.Client{
		DirectoryURL: "invalid",
	}

	// cache a recently renewed cert with a different private key
	now := time.Now()
	newCert := ca.LeafCert(exampleDomain, "ECDSA", now.Add(-2*time.Hour), now.Add(time.Hour*24*90))
	if err := man.cachePut(context.Background(), exampleCertKey, newCert); err != nil {
		t.Fatal(err)
	}
	newLeaf, err := validCert(exampleCertKey, newCert.Certificate, newCert.PrivateKey.(crypto.Signer), now)
	if err != nil {
		t.Fatal(err)
	}

	// set internal state to an almost expired cert
	oldCert := ca.LeafCert(exampleDomain, "ECDSA", now.Add(-2*time.Hour), now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	oldLeaf, err := validCert(exampleCertKey, oldCert.Certificate, oldCert.PrivateKey.(crypto.Signer), now)
	if err != nil {
		t.Fatal(err)
	}
	man.stateMu.Lock()
	if man.state == nil {
		man.state = make(map[certKey]*certState)
	}
	s := &certState{
		key:  oldCert.PrivateKey.(crypto.Signer),
		cert: oldCert.Certificate,
		leaf: oldLeaf,
	}
	man.state[exampleCertKey] = s
	man.stateMu.Unlock()

	// verify the renewal accepted the newer cached cert
	defer func() {
		// Stop the timers that read and execute testDidRenewLoop before restoring it.
		// Otherwise the timer callback may race with the deferred write.
		man.stopRenew()
		testDidRenewLoop = func(next time.Duration, err error) {}
	}()
	renewed := make(chan bool, 1)
	testDidRenewLoop = func(next time.Duration, err error) {
		defer func() {
			select {
			case renewed <- true:
			default:
				// The renewal timer uses a random backoff. If the first renewal fails for
				// some reason, we could end up with multiple calls here before the test
				// stops the timer.
			}
		}()

		if err != nil {
			t.Errorf("testDidRenewLoop: %v", err)
		}
		// Next should be about 90 days
		// Previous expiration was within 1 min.
		future := 88 * 24 * time.Hour
		if next < future {
			t.Errorf("testDidRenewLoop: next = %v; want >= %v", next, future)
		}

		// ensure the cached cert was not modified
		tlscert, err := man.cacheGet(context.Background(), exampleCertKey)
		if err != nil {
			t.Errorf("man.cacheGet: %v", err)
			return
		}
		if !tlscert.Leaf.NotAfter.Equal(newLeaf.NotAfter) {
			t.Errorf("cache leaf.NotAfter = %v; want == %v", tlscert.Leaf.NotAfter, newLeaf.NotAfter)
		}

		// verify the old cert is also replaced in memory
		man.stateMu.Lock()
		defer man.stateMu.Unlock()
		s := man.state[exampleCertKey]
		if s == nil {
			t.Errorf("m.state[%q] is nil", exampleCertKey)
			return
		}
		stateKey := s.key.Public().(*ecdsa.PublicKey)
		if !stateKey.Equal(newLeaf.PublicKey) {
			t.Error("state key was not updated from cache")
			return
		}
		tlscert, err = s.tlscert()
		if err != nil {
			t.Errorf("s.tlscert: %v", err)
			return
		}
		if !tlscert.Leaf.NotAfter.Equal(newLeaf.NotAfter) {
			t.Errorf("state leaf.NotAfter = %v; want == %v", tlscert.Leaf.NotAfter, newLeaf.NotAfter)
		}
	}

	// assert the expiring cert is returned from state
	hello := clientHelloInfo(exampleDomain, algECDSA)
	tlscert, err := man.GetCertificate(hello)
	if err != nil {
		t.Fatal(err)
	}
	if !oldLeaf.NotAfter.Equal(tlscert.Leaf.NotAfter) {
		t.Errorf("state leaf.NotAfter = %v; want == %v", tlscert.Leaf.NotAfter, oldLeaf.NotAfter)
	}

	// trigger renew
	man.startRenew(exampleCertKey, s.key, s.leaf.NotBefore, s.leaf.NotAfter)
	<-renewed
	func() {
		man.renewalMu.Lock()
		defer man.renewalMu.Unlock()

		// verify the private key is replaced in the renewal state
		r := man.renewal[exampleCertKey]
		if r == nil {
			t.Errorf("m.renewal[%q] is nil", exampleCertKey)
			return
		}
		renewalKey := r.key.Public().(*ecdsa.PublicKey)
		if !renewalKey.Equal(newLeaf.PublicKey) {
			t.Error("renewal private key was not updated from cache")
		}
	}()

	// assert the new cert is returned from state after renew
	hello = clientHelloInfo(exampleDomain, algECDSA)
	tlscert, err = man.GetCertificate(hello)
	if err != nil {
		t.Fatal(err)
	}
	if !newLeaf.NotAfter.Equal(tlscert.Leaf.NotAfter) {
		t.Errorf("state leaf.NotAfter = %v; want == %v", tlscert.Leaf.NotAfter, newLeaf.NotAfter)
	}
}
