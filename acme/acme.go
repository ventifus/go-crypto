// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package acme provides an ACME client implementation.
// See https://ietf-wg-acme.github.io/acme/ for details.
package acme

import (
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/context"
)

// ACME server response statuses used to describe Authorization and Challenge states.
const (
	StatusUnknown    = "unknown"
	StatusPending    = "pending"
	StatusProcessing = "processing"
	StatusValid      = "valid"
	StatusInvalid    = "invalid"
	StatusRevoked    = "revoked"
)

// Account is a user account. It is associated with a private key.
type Account struct {
	// URI is the account unique ID, which is also a URL used to retrieve
	// account data from the CA.
	URI string `json:"uri"`

	// Contact is a slice of contact info used during registration.
	Contact []string `json:"contact"`

	// The terms user has agreed to.
	// Zero value indicates that the user hasn't agreed yet.
	AgreedTerms string `json:"agreement"`

	// Actual terms of a CA.
	CurrentTerms string `json:"terms"`

	// Authz is the authorization URL used to initiate a new authz flow.
	Authz string `json:"authz"`

	// Authorizations is a URI from which a list of authorizations
	// granted to this account can be fetched via a GET request.
	Authorizations string `json:"authorizations"`

	// Certificates is a URI from which a list of certificates
	// issued for this account can be fetched via a GET request.
	Certificates string `json:"certificates"`
}

// Endpoint is ACME server directory.
type Endpoint struct {
	RegURL    string `json:"new-reg"`
	AuthzURL  string `json:"new-authz"`
	CertURL   string `json:"new-cert"`
	RevokeURL string `json:"revoke-cert"`
}

// Challenge encodes a returned CA challenge.
type Challenge struct {
	Type   string
	URI    string `json:"uri"`
	Token  string
	Status string
}

// ChallengeSet encodes a set of challenges, together with permitted combinations.
type ChallengeSet struct {
	Challenges   []Challenge
	Combinations [][]int
}

// Authorization encodes an authorization response.
type Authorization struct {
	ChallengeSet
	Identifier AuthzID
	URI        string
	Status     string
}

// AuthzID encodes an ID for something to authorize, typically a domain.
type AuthzID struct {
	Type  string `json:"type,omitempty"`
	Value string `json:"value,omitempty"`
}

// Client is an ACME client.
type Client struct {
	// HTTPClient optionally specifies an HTTP client to use
	// instead of http.DefaultClient.
	HTTPClient *http.Client
	// Key is the account key used to register with a CA
	// and sign requests.
	Key *rsa.PrivateKey
}

// CreateCert requests a new certificate.
// It always returns a non-empty long-lived certURL.
// The cert der bytes, however, may be nil even if no error occurred.
// The returned value will also contain CA (the issuer) certificate if bundle is true.
//
// url is typically an Endpoint.CertURL.
// csr is a DER encoded certificate signing request.
func (c *Client) CreateCert(url string, csr []byte, exp time.Duration, bundle bool) (der [][]byte, certURL string, err error) {
	req := struct {
		Resource  string `json:"resource"`
		CSR       string `json:"csr"`
		NotBefore string `json:"notBefore,omitempty"`
		NotAfter  string `json:"notAfter,omitempty"`
	}{
		Resource: "new-cert",
		CSR:      base64.RawURLEncoding.EncodeToString(csr),
	}
	now := timeNow()
	req.NotBefore = now.Format(time.RFC3339)
	if exp > 0 {
		req.NotAfter = now.Add(exp).Format(time.RFC3339)
	}

	res, err := c.postJWS(url, req)
	if err != nil {
		return nil, "", err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusCreated {
		return nil, "", responseError(res)
	}

	curl := res.Header.Get("location") // cert permanent URL
	if res.ContentLength == 0 {
		// no cert in the body
		return nil, curl, nil
	}
	// slurp issued cert and ca, if requested
	cert, err := responseCert(c.httpClient(), res, bundle)
	return cert, curl, err
}

// Register create a new registration by following the "new-reg" flow.
// It populates the a argument with the response received from the server.
// Existing field values may be overwritten.
//
// The url argument is typically an Endpoint.RegURL.
func (c *Client) Register(url string, a *Account) error {
	return c.doReg(url, a, "new-reg")
}

// GetReg retrieves an existing registration.
// The url argument is an Account.URI, usually obtained with c.Register.
func (c *Client) GetReg(url string) (*Account, error) {
	a := &Account{URI: url}
	return a, c.doReg(url, a, "reg")
}

// UpdateReg updates existing registration.
// It populates the a argument with the response received from the server.
// Existing field values may be overwritten.
//
// The url argument is an Account.URI, usually obtained with c.Register.
func (c *Client) UpdateReg(url string, a *Account) error {
	return c.doReg(url, a, "reg")
}

// Authorize performs the initial step in an authorization flow.
// The caller will then need to choose from and perform a set of returned
// challenges using c.Accept in order to successfully complete authorization.
//
// The url argument is an authz URL, usually obtained with c.Register.
func (c *Client) Authorize(url, domain string) (*Authorization, error) {
	req := struct {
		Resource   string  `json:"resource"`
		Identifier AuthzID `json:"identifier"`
	}{
		Resource:   "new-authz",
		Identifier: AuthzID{Type: "dns", Value: domain},
	}
	res, err := c.postJWS(url, req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusCreated {
		return nil, responseError(res)
	}

	var az Authorization
	if err := json.NewDecoder(res.Body).Decode(&az); err != nil {
		return nil, fmt.Errorf("Decode: %v", err)
	}
	az.URI = res.Header.Get("Location")
	if az.Status != "pending" {
		return nil, fmt.Errorf("Unexpected status: %s", az.Status)
	}
	return &az, nil
}

// GetAuthz retrieves the current status of an authorization flow.
//
// A client typically polls an authz status using this method.
func (c *Client) GetAuthz(url string) (*Authorization, error) {
	res, err := c.httpClient().Get(url)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusAccepted {
		return nil, responseError(res)
	}
	az := &Authorization{URI: url}
	if err := json.NewDecoder(res.Body).Decode(az); err != nil {
		return nil, fmt.Errorf("Decode: %v", err)
	}
	return az, nil
}

// GetChallenge retrieves the current status of an challenge.
//
// A client typically polls a challenge status using this method.
func (c *Client) GetChallenge(url string) (*Challenge, error) {
	res, err := c.httpClient().Get(url)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusAccepted {
		return nil, responseError(res)
	}
	az := &Challenge{URI: url}
	if err := json.NewDecoder(res.Body).Decode(az); err != nil {
		return nil, fmt.Errorf("Decode: %v", err)
	}
	return az, nil
}

// Accept informs the server that the client accepts one of its challenges
// previously obtained with c.Authorize.
//
// The server will then perform the validation asynchronously.
func (c *Client) Accept(chal *Challenge) (*Challenge, error) {
	req := struct {
		Resource string `json:"resource"`
		Type     string `json:"type"`
		Auth     string `json:"keyAuthorization"`
	}{
		Resource: "challenge",
		Type:     chal.Type,
		Auth:     keyAuth(&c.Key.PublicKey, chal.Token),
	}
	res, err := c.postJWS(chal.URI, req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	// Note: the protocol specifies 200 as the expected response code, but
	// letsencrypt seems to be returning 202.
	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusAccepted {
		return nil, responseError(res)
	}

	var rc Challenge
	if err := json.NewDecoder(res.Body).Decode(&rc); err != nil {
		return nil, fmt.Errorf("Decode: %v", err)
	}
	return &rc, nil
}

// HTTP01Handler creates a new handler which responds to a http-01 challenge.
// The token argument is a Challenge.Token value.
func (c *Client) HTTP01Handler(token string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, token) {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("content-type", "text/plain")
		w.Write([]byte(keyAuth(&c.Key.PublicKey, token)))
	})
}

func (c *Client) httpClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return http.DefaultClient
}

// postJWS signs body and posts it to the provided url.
// The body argument must be JSON-serializable.
func (c *Client) postJWS(url string, body interface{}) (*http.Response, error) {
	nonce, err := fetchNonce(c.httpClient(), url)
	if err != nil {
		return nil, err
	}
	b, err := jwsEncodeJSON(body, c.Key, nonce)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("POST", url, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	return c.httpClient().Do(req)
}

// doReg sends all types of registration requests.
// The type of request is identified by typ argument, which is a "resource"
// in the ACME spec terms.
//
// A non-nil acct argument indicates whether the intention is to mutate data
// of the Account. Only Contact and Agreement of its fields are used
// in such cases.
//
// The fields of acct will be populate with the server response
// and may be overwritten.
func (c *Client) doReg(url string, acct *Account, typ string) error {
	req := struct {
		Resource  string   `json:"resource"`
		Contact   []string `json:"contact,omitempty"`
		Agreement string   `json:"agreement,omitempty"`
	}{
		Resource: typ,
	}
	if acct != nil {
		req.Contact = acct.Contact
		req.Agreement = acct.AgreedTerms
	}
	res, err := c.postJWS(url, req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return responseError(res)
	}

	if err := json.NewDecoder(res.Body).Decode(acct); err != nil {
		return fmt.Errorf("Decode: %v", err)
	}
	if v := res.Header.Get("Location"); v != "" {
		acct.URI = v
	}
	if v := linkHeader(res.Header, "terms-of-service"); v != "" {
		acct.CurrentTerms = v
	}
	if v := linkHeader(res.Header, "next"); v != "" {
		acct.Authz = v
	}
	return nil
}

// Discover performs ACME server discovery using provided url and client.
// If client argument is nil, DefaultClient will be used.
func Discover(client *http.Client, url string) (Endpoint, error) {
	if client == nil {
		client = http.DefaultClient
	}
	res, err := client.Get(url)
	if err != nil {
		return Endpoint{}, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return Endpoint{}, responseError(res)
	}
	var ep Endpoint
	if json.NewDecoder(res.Body).Decode(&ep); err != nil {
		return Endpoint{}, err
	}
	return ep, nil
}

// FetchCert retrieves already issued certificate from the given url, in DER format.
// It retries the request until the certificate is successfully retrieved,
// context is cancelled by the caller or an error response is received.
//
// The returned value will also contain CA (the issuer) certificate if bundle == true.
//
// http.DefaultClient is used if client argument is nil.
func FetchCert(ctx context.Context, client *http.Client, url string, bundle bool) ([][]byte, error) {
	if client == nil {
		client = http.DefaultClient
	}
	for {
		res, err := client.Get(url)
		if err != nil {
			return nil, err
		}
		defer res.Body.Close()
		if res.StatusCode == http.StatusOK {
			return responseCert(client, res, bundle)
		}
		if res.StatusCode > 299 {
			return nil, responseError(res)
		}
		d, err := retryAfter(res.Header.Get("retry-after"))
		if err != nil {
			d = 3 * time.Second
		}
		select {
		case <-time.After(d):
			// retry
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func responseCert(client *http.Client, res *http.Response, bundle bool) ([][]byte, error) {
	b, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("ReadAll: %v", err)
	}
	cert := [][]byte{b}
	if !bundle {
		return cert, nil
	}
	// append ca cert
	up := linkHeader(res.Header, "up")
	if up == "" {
		return nil, errors.New("rel=up link not found")
	}
	b, err = slurp(client, up)
	if err != nil {
		return nil, err
	}
	return append(cert, b), nil
}

func fetchNonce(client *http.Client, url string) (string, error) {
	resp, err := client.Head(url)
	if err != nil {
		return "", nil
	}
	defer resp.Body.Close()
	enc := resp.Header.Get("replay-nonce")
	if enc == "" {
		return "", errors.New("nonce not found")
	}
	return enc, nil
}

func slurp(client *http.Client, url string) ([]byte, error) {
	res, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, responseError(res)
	}
	return ioutil.ReadAll(res.Body)
}

func linkHeader(h http.Header, rel string) string {
	for _, v := range h["Link"] {
		parts := strings.Split(v, ";")
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if !strings.HasPrefix(p, "rel=") {
				continue
			}
			if v := strings.Trim(p[4:], `"`); v == rel {
				return strings.Trim(parts[0], "<>")
			}
		}
	}
	return ""
}

func retryAfter(v string) (time.Duration, error) {
	if i, err := strconv.Atoi(v); err == nil {
		return time.Duration(i) * time.Second, nil
	}
	t, err := http.ParseTime(v)
	if err != nil {
		return 0, err
	}
	return t.Sub(timeNow()), nil
}

// keyAuth generates a key authorization string for a given token.
func keyAuth(pub *rsa.PublicKey, token string) string {
	return fmt.Sprintf("%s.%s", token, JWKThumbprint(pub))
}

// timeNow is useful for testing for fixed current time.
var timeNow = time.Now
