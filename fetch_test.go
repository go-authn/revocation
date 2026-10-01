// SPDX-License-Identifier: BSD-3-Clause

package revocation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// issuer serves one list and its signature, as section 4 says: an ETag on
// the list, If-None-Match answered 304, If-Match on the signature answered
// 412 when the list has changed. ignoreIfMatch plays a server that does not
// implement it; between, when set, runs between the two requests.
type issuer struct {
	mu            sync.Mutex
	raw, sig      []byte
	ignoreIfMatch bool
	between       func()
	lists, sigs   atomic.Int32
	notModified   atomic.Int32
}

func etagOf(b []byte) string {
	h := sha256.Sum256(b)
	return `"` + hex.EncodeToString(h[:8]) + `"`
}

func (is *issuer) set(raw, sig []byte) {
	is.mu.Lock()
	is.raw, is.sig = raw, sig
	is.mu.Unlock()
}

func (is *issuer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	is.mu.Lock()
	raw, sig, between := is.raw, is.sig, is.between
	is.mu.Unlock()
	tag := etagOf(raw)
	switch {
	case strings.HasSuffix(r.URL.Path, ".sig"):
		is.sigs.Add(1)
		if m := r.Header.Get("If-Match"); m != "" && m != tag && !is.ignoreIfMatch {
			w.WriteHeader(http.StatusPreconditionFailed)
			return
		}
		w.Write(sig)
	default:
		is.lists.Add(1)
		if r.Header.Get("If-None-Match") == tag {
			is.notModified.Add(1)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", tag)
		w.Write(raw)
		if between != nil {
			between()
		}
	}
}

func krlFetcher(t *testing.T, srv *httptest.Server, ca sshCA, held *List) *Fetcher {
	t.Helper()
	f, err := NewFetcher(Source{URL: srv.URL + "/ssh/krl", Kind: KRL, SSHCA: ca.pub, Client: srv.Client()}, held)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestFetchKRL(t *testing.T) {
	ca := newSSHCA(t)
	now := time.Now()
	is := &issuer{}
	is.set(signedKRL(t, ca, 1, now, now.Add(time.Hour), 3))
	srv := httptest.NewTLSServer(is)
	defer srv.Close()
	f := krlFetcher(t, srv, ca, nil)
	ctx := context.Background()

	l, changed, err := f.Fetch(ctx)
	if err != nil || !changed || l.Version.Uint64() != 1 {
		t.Fatalf("first fetch: %v %v %+v", err, changed, l)
	}
	// Nothing new: a 304, nothing re-downloaded.
	if _, changed, err := f.Fetch(ctx); err != nil || changed || is.notModified.Load() != 1 {
		t.Fatalf("second fetch: %v changed=%v 304s=%d", err, changed, is.notModified.Load())
	}
	// A new version arrives.
	is.set(signedKRL(t, ca, 2, now, now.Add(time.Hour), 3, 4))
	if l, changed, err := f.Fetch(ctx); err != nil || !changed || l.Version.Uint64() != 2 {
		t.Fatalf("new version: %v %v", err, changed)
	}
	// Re-issued: same version, later, new expiry.
	is.set(signedKRL(t, ca, 2, now.Add(time.Minute), now.Add(2*time.Hour), 3, 4))
	if l, changed, err := f.Fetch(ctx); err != nil || !changed || !l.Expires.After(now.Add(time.Hour)) {
		t.Fatalf("re-issue: %v %v", err, changed)
	}
}

// Everything a mirror, a cache or an attacker in the path may serve is
// refused, and the list held is kept: never replaced by nothing.
func TestFetchKeepsTheHeldListOnEveryRefusal(t *testing.T) {
	ca, other := newSSHCA(t), newSSHCA(t)
	now := time.Now()
	good, goodSig := signedKRL(t, ca, 5, now, now.Add(time.Hour), 3)
	empty, _ := signedKRL(t, ca, 6, now, now.Add(time.Hour))
	_, forgedSig := signedKRL(t, other, 6, now, now.Add(time.Hour))
	older, olderSig := signedKRL(t, ca, 4, now, now.Add(time.Hour))
	stale, staleSig := signedKRL(t, ca, 6, now.Add(-2*time.Hour), now.Add(-time.Hour))
	replayed, replayedSig := signedKRL(t, ca, 5, now.Add(-time.Minute), now.Add(time.Hour), 3)
	for name, c := range map[string][2][]byte{
		"an empty list signed by another CA": {empty, forgedSig},
		"an older version":                   {older, olderSig},
		"an expired list":                    {stale, staleSig},
		"an older issue of the same version": {replayed, replayedSig},
		"a list and no signature":            {empty, nil},
	} {
		t.Run(name, func(t *testing.T) {
			is := &issuer{}
			is.set(good, goodSig)
			srv := httptest.NewTLSServer(is)
			defer srv.Close()
			f := krlFetcher(t, srv, ca, nil)
			if _, _, err := f.Fetch(context.Background()); err != nil {
				t.Fatal(err)
			}
			is.set(c[0], c[1])
			l, changed, err := f.Fetch(context.Background())
			if err == nil || changed {
				t.Errorf("served %s: accepted (changed=%v)", name, changed)
			}
			if !l.Same(f.Held()) || l.Version.Uint64() != 5 || !l.KRL.IsRevoked(certOf(t, ca, 3)) {
				t.Errorf("the list held after the refusal is not the good one")
			}
		})
	}
}

// A list re-issued between the list and its signature: answered 412 by an
// issuer that implements If-Match, a mismatched pair by one that does not.
// Either way the fetcher tries once more and gets a matching pair.
func TestFetchRetriesARaceWithTheIssuer(t *testing.T) {
	for _, ignore := range []bool{false, true} {
		ca := newSSHCA(t)
		now := time.Now()
		is := &issuer{ignoreIfMatch: ignore}
		is.set(signedKRL(t, ca, 1, now, now.Add(time.Hour)))
		next, nextSig := signedKRL(t, ca, 2, now, now.Add(time.Hour), 9)
		var once sync.Once
		is.between = func() { once.Do(func() { is.set(next, nextSig) }) }
		srv := httptest.NewTLSServer(is)
		f := krlFetcher(t, srv, ca, nil)
		l, changed, err := f.Fetch(context.Background())
		if err != nil || !changed || l.Version.Uint64() != 2 {
			t.Errorf("ignoreIfMatch=%v: %v %v %+v", ignore, err, changed, l)
		}
		if is.lists.Load() != 2 {
			t.Errorf("ignoreIfMatch=%v: %d list requests, want 2", ignore, is.lists.Load())
		}
		srv.Close()
	}
}

// The held copy survives a restart: a fetcher given it refuses an older
// list it would otherwise have taken as its first.
func TestFetchFollowsTheCopyFromBefore(t *testing.T) {
	ca := newSSHCA(t)
	now := time.Now()
	raw, sig := signedKRL(t, ca, 7, now, now.Add(time.Hour), 1)
	held, err := VerifyKRL(raw, sig, ca.pub)
	if err != nil {
		t.Fatal(err)
	}
	is := &issuer{}
	is.set(signedKRL(t, ca, 6, now, now.Add(time.Hour)))
	srv := httptest.NewTLSServer(is)
	defer srv.Close()
	f := krlFetcher(t, srv, ca, held)
	if _, _, err := f.Fetch(context.Background()); !errors.Is(err, ErrRollback) {
		t.Errorf("an older list after a restart: %v", err)
	}
}

func TestFetchCRLAndFiles(t *testing.T) {
	ca := newX509CA(t, "ca")
	now := time.Now()
	dir := t.TempDir()
	p := write(t, dir, "ca.crl", ca.crl(t, 3, now.Add(-time.Minute), now.Add(time.Hour), nil, 42))
	f, err := NewFetcher(Source{URL: "file://" + p, Kind: CRL, X509CA: ca.cert, MaxAge: time.Hour}, nil)
	if err != nil {
		t.Fatal(err)
	}
	l, changed, err := f.Fetch(context.Background())
	if err != nil || !changed || l.Version.Int64() != 3 {
		t.Fatalf("%v %v", err, changed)
	}
	// Unchanged file: not changed.
	if _, changed, err := f.Fetch(context.Background()); err != nil || changed {
		t.Errorf("same file again: %v %v", err, changed)
	}
	// The caller's max_age is enforced on top of nextUpdate.
	f.now = func() time.Time { return now.Add(70 * time.Minute) }
	os.WriteFile(p, ca.crl(t, 4, now.Add(-2*time.Hour), now.Add(3*time.Hour), nil), 0o600)
	if _, _, err := f.Fetch(context.Background()); !errors.Is(err, ErrExpired) {
		t.Errorf("a CRL older than max_age: %v", err)
	}
	os.Remove(p)
	if _, _, err := f.Fetch(context.Background()); err == nil {
		t.Error("a missing file: no error")
	}
}

func TestFetchBoundsAndAnswers(t *testing.T) {
	ca := newSSHCA(t)
	now := time.Now()
	raw, sig := signedKRL(t, ca, 1, now, now.Add(time.Hour))
	for name, h := range map[string]http.HandlerFunc{
		"404": func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) },
		"a 304 with nothing held": func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotModified)
		},
		"an endless signature": func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, ".sig") {
				w.Write(make([]byte, maxSig+1))
				return
			}
			w.Write(raw)
		},
		"a signature that 404s": func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, ".sig") {
				http.NotFound(w, r)
				return
			}
			w.Write(raw)
		},
	} {
		srv := httptest.NewTLSServer(h)
		f := krlFetcher(t, srv, ca, nil)
		if _, _, err := f.Fetch(context.Background()); err == nil {
			t.Errorf("%s: no error", name)
		}
		srv.Close()
	}
	_ = sig
	// A dead server.
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	f := krlFetcher(t, srv, ca, nil)
	srv.Close()
	if _, _, err := f.Fetch(context.Background()); err == nil {
		t.Error("a closed server: no error")
	}
}

func TestNewFetcherRefusals(t *testing.T) {
	ca := newSSHCA(t)
	x := newX509CA(t, "ca")
	for _, s := range []Source{
		{URL: "ftp://x/l", Kind: KRL, SSHCA: ca.pub},
		{URL: "://", Kind: KRL, SSHCA: ca.pub},
		{URL: "https://x/l", Kind: KRL},
		{URL: "https://x/l", Kind: CRL},
		{URL: "https://x/l", Kind: Kind(9), SSHCA: ca.pub, X509CA: x.cert},
	} {
		if _, err := NewFetcher(s, nil); err == nil {
			t.Errorf("%+v: accepted", s)
		}
	}
	f, err := NewFetcher(Source{URL: "file://" + filepath.Join(t.TempDir(), "x"), Kind: KRL, SSHCA: ca.pub}, nil)
	if err != nil || f.src.Client == nil || f.Held() != nil {
		t.Errorf("defaults: %v", err)
	}
}
