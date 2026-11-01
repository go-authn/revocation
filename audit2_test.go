// SPDX-License-Identifier: BSD-3-Clause

// Tests of the 2026-11 audit: each failed before its fix (see the CHANGELOG).

package revocation

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A URL may carry a password or a token (basic authentication to an issuer).
// Errors end up in logs and in the unauthenticated /healthz of a mirror.
func TestErrorsDoNotCarryTheURLsPasswordNorItsQuery(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	ca := newSSHCA(t)
	u := strings.Replace(srv.URL, "http://", "http://svc:s3cretpass@", 1) + "/krl?token=tok3n"
	f, err := NewFetcher(Source{URL: u, Kind: KRL, SSHCA: ca.pub}, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = f.Fetch(context.Background())
	if err == nil {
		t.Fatal("a 500 was not an error")
	}
	for _, secret := range []string{"s3cretpass", "tok3n"} {
		if strings.Contains(err.Error(), secret) {
			t.Errorf("the error carries %q: %v", secret, err)
		}
	}
	// And the expiry and rollback messages, which name the URL too.
	_, err = NewFetcher(Source{URL: "ftp://svc:s3cretpass@h/x", Kind: KRL, SSHCA: ca.pub}, nil)
	if err == nil || strings.Contains(err.Error(), "s3cretpass") {
		t.Errorf("the scheme error carries the password: %v", err)
	}
}

// A source that cannot send an ETag makes every poll download the list; the
// same bytes must not be verified and parsed again (a 64 MB CRL cost 3 GB
// allocated per refresh).
func TestAListIdenticalToTheOneHeldIsNotParsedAgain(t *testing.T) {
	dir := t.TempDir()
	ca := newX509CA(t, "ca")
	now := time.Now()
	var serials []int64
	for i := int64(1); i <= 3000; i++ {
		serials = append(serials, i)
	}
	der := ca.crl(t, 1, now.Add(-time.Hour), now.Add(time.Hour), nil, serials...)
	p := write(t, dir, "x.crl", der)
	f, err := NewFetcher(Source{URL: FileURL(p), Kind: CRL, X509CA: ca.cert}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, changed, err := f.Fetch(context.Background()); err != nil || !changed {
		t.Fatalf("first fetch: changed=%v err=%v", changed, err)
	}
	allocs := testing.AllocsPerRun(5, func() {
		if _, changed, err := f.Fetch(context.Background()); err != nil || changed {
			t.Fatalf("again: changed=%v err=%v", changed, err)
		}
	})
	if allocs > 60 {
		t.Errorf("an unchanged CRL of 3000 entries cost %.0f allocations per fetch: it is parsed again", allocs)
	}
	// The same holds for a PEM copy of it, and a changed list is still taken.
	pp := write(t, dir, "y.crl", pemOf("X509 CRL", der))
	g, _ := NewFetcher(Source{URL: FileURL(pp), Kind: CRL, X509CA: ca.cert}, nil)
	g.Fetch(context.Background())
	if a := testing.AllocsPerRun(5, func() { g.Fetch(context.Background()) }); a > 80 {
		t.Errorf("an unchanged PEM CRL cost %.0f allocations per fetch", a)
	}
	next := ca.crl(t, 2, now.Add(-time.Minute), now.Add(time.Hour), nil, 1)
	write(t, dir, "x.crl", next)
	l, changed, err := f.Fetch(context.Background())
	if err != nil || !changed || l.Version.Int64() != 2 {
		t.Fatalf("a newer CRL was not taken: changed=%v err=%v", changed, err)
	}
}

// A shortcut for "the same bytes" must not become a way round the checks: a
// held list that has lapsed is still refused when it is served again.
func TestTheSameExpiredListIsStillRefused(t *testing.T) {
	dir := t.TempDir()
	ca := newX509CA(t, "ca")
	now := time.Now()
	der := ca.crl(t, 1, now.Add(-2*time.Hour), now.Add(time.Hour), nil, 7)
	p := write(t, dir, "x.crl", der)
	clock := now
	f, _ := NewFetcher(Source{URL: FileURL(p), Kind: CRL, X509CA: ca.cert, Clock: func() time.Time { return clock }}, nil)
	if _, _, err := f.Fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	clock = now.Add(2 * time.Hour)
	if _, _, err := f.Fetch(context.Background()); err == nil {
		t.Error("the same CRL, past its nextUpdate, was accepted")
	}
}

// RFC 5280 5.2.3: CRLNumber ::= INTEGER (0..MAX), at most 20 octets. Found by
// FuzzVerifyCRLSigned: -1 was accepted and ordered before every other number.
func TestACRLNumberOutsideTheRFCRangeIsRefused(t *testing.T) {
	ca := newX509CA(t, "ca")
	now := time.Now()
	huge := new(big.Int).Lsh(big.NewInt(1), 160)
	for _, n := range []*big.Int{big.NewInt(-1), huge} {
		der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: n,
			ThisUpdate: now.Add(-time.Hour), NextUpdate: now.Add(time.Hour)}, ca.cert, ca.key)
		if err != nil {
			t.Logf("the standard library will not write number %v: %v", n, err)
			continue
		}
		if _, err := VerifyCRL(der, ca.cert); err == nil {
			t.Errorf("CRL number %v was accepted", n)
		}
	}
	der := ca.crl(t, 0, now.Add(-time.Hour), now.Add(time.Hour), nil)
	if _, err := VerifyCRL(der, ca.cert); err != nil {
		t.Errorf("CRL number 0 is valid: %v", err)
	}
}
