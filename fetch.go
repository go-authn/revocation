// SPDX-License-Identifier: BSD-3-Clause

package revocation

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// Source is where a list comes from and what it must verify against.
type Source struct {
	// URL is http://, https:// or file://. The list verifies by itself, so
	// the transport decides how fast a change arrives, never whether a
	// forged or stale list is taken. A KRL's signature is at URL+".sig".
	URL  string
	Kind Kind
	// SSHCA is the CA key a KRL must be signed by; X509CA the certificate a
	// CRL must be signed by.
	SSHCA  ssh.PublicKey
	X509CA *x509.Certificate
	// MaxAge, when not zero, bounds a list's age from its issue, besides
	// its own expiry.
	MaxAge time.Duration
	// Client fetches http and https URLs; nil is a client with a one
	// minute timeout.
	Client *http.Client
	// Clock is the time a list's currency is judged at; nil is time.Now.
	// One clock for the fetcher and its caller, or they disagree on what
	// is current.
	Clock func() time.Time
}

// FilePath is the local path a file:// URL names: file:///etc/x is
// /etc/x, and on Windows file:///C:/x is C:\x (RFC 8089, appendix E.2).
func FilePath(u string) (string, error) {
	p, err := url.Parse(u)
	if err != nil || p.Scheme != "file" || (p.Host != "" && p.Host != "localhost") || p.Path == "" {
		return "", fmt.Errorf("revocation: %q is not a file URL of a local path", u)
	}
	path := p.Path
	if runtime.GOOS == "windows" && len(path) >= 3 && path[0] == '/' && path[2] == ':' {
		path = path[1:]
	}
	return filepath.FromSlash(path), nil
}

// FileURL is the file:// URL of a local path, the inverse of FilePath.
func FileURL(path string) string {
	p := filepath.ToSlash(path)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p // C:/x -> /C:/x
	}
	return (&url.URL{Scheme: "file", Path: p}).String()
}

// maxSig bounds a signature: an armored SSHSIG by the largest RSA key is a
// few kilobytes.
const maxSig = 64 << 10

// maxKRL is the largest KRL sshd loads (go-authn/krl refuses past it too).
const maxKRL = 32 << 20

// Fetcher fetches one source, keeping the last list that verified.
type Fetcher struct {
	src Source
	now func() time.Time

	mu   sync.Mutex
	held *List
	etag string
}

// NewFetcher returns a Fetcher for src that holds held, the copy kept from
// before (the file last written, read back): a fetched list must follow it.
func NewFetcher(src Source, held *List) (*Fetcher, error) {
	u, err := url.Parse(src.URL)
	if err != nil {
		return nil, fmt.Errorf("revocation: %q: %w", src.URL, err)
	}
	switch u.Scheme {
	case "http", "https":
	case "file":
		if _, err := FilePath(src.URL); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("revocation: %q: an http, https or file URL", src.URL)
	}
	switch {
	case src.Kind == KRL && src.SSHCA == nil:
		return nil, errors.New("revocation: a KRL source needs the SSH CA key it is signed by")
	case src.Kind == CRL && src.X509CA == nil:
		return nil, errors.New("revocation: a CRL source needs the CA certificate it is signed by")
	case src.Kind != KRL && src.Kind != CRL:
		return nil, fmt.Errorf("revocation: unknown kind %v", src.Kind)
	}
	if src.Client == nil {
		src.Client = &http.Client{Timeout: time.Minute}
	}
	now := src.Clock
	if now == nil {
		now = time.Now
	}
	return &Fetcher{src: src, now: now, held: held}, nil
}

// Held is the last list that verified, or nil.
func (f *Fetcher) Held() *List {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.held
}

// Fetch fetches the source once. It returns the list held afterwards, and
// whether it changed. A list that does not verify, is not current, or does
// not follow the one held is refused with an error, and the one held is
// kept: never the empty answer, which would revoke nothing.
func (f *Fetcher) Fetch(ctx context.Context) (*List, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	changed, err := f.fetch(ctx)
	if errors.Is(err, errMismatch) {
		changed, err = f.fetch(ctx) // re-issued between the list and its signature
	}
	return f.held, changed, err
}

var (
	errMismatch    = errors.New("revocation: the list changed between it and its signature")
	errNotModified = errors.New("not modified")
)

// fetch makes one attempt, and reports whether the held list was replaced.
func (f *Fetcher) fetch(ctx context.Context) (bool, error) {
	raw, tag, err := f.get(ctx, f.src.URL, maxSizeOf(f.src.Kind), "If-None-Match", f.etagIfHeld())
	if errors.Is(err, errNotModified) {
		if f.held == nil {
			return false, fmt.Errorf("revocation: %s answered 304 and no copy is held", f.src.URL)
		}
		// Still the same list -- which may have expired since: a 304 is
		// no news, and the caller asks Current of what it holds.
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var l *List
	switch f.src.Kind {
	case KRL:
		sig, _, err := f.get(ctx, f.src.URL+".sig", maxSig, "If-Match", tag)
		if err != nil {
			return false, err
		}
		if l, err = VerifyKRL(raw, sig, f.src.SSHCA); err != nil {
			// Possibly a list re-issued between the two requests by a
			// server that ignores If-Match: tried once more, then it is
			// an error.
			return false, fmt.Errorf("%w: %w", errMismatch, err)
		}
	case CRL:
		if l, err = VerifyCRL(raw, f.src.X509CA); err != nil {
			return false, err
		}
	}
	if err := l.Current(f.now(), f.src.MaxAge); err != nil {
		return false, fmt.Errorf("%s: %w", f.src.URL, err)
	}
	if l.Same(f.held) {
		f.etag = tag
		return false, nil
	}
	if err := l.Follows(f.held); err != nil {
		return false, fmt.Errorf("%s: %w", f.src.URL, err)
	}
	f.held, f.etag = l, tag
	return true, nil
}

func (f *Fetcher) etagIfHeld() string {
	if f.held == nil {
		return ""
	}
	return f.etag
}

func maxSizeOf(k Kind) int64 {
	if k == KRL {
		return maxKRL
	}
	return maxCRL
}

// get fetches u, at most limit bytes, with the conditional header cond when
// tag is not empty; it returns the body and its ETag.
func (f *Fetcher) get(ctx context.Context, u string, limit int64, cond, tag string) ([]byte, string, error) {
	if strings.HasPrefix(u, "file://") {
		path, err := FilePath(u)
		if err != nil {
			return nil, "", err
		}
		fh, err := os.Open(path)
		if err != nil {
			return nil, "", fmt.Errorf("revocation: %w", err)
		}
		defer fh.Close()
		return readBounded(fh, limit, u)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, "", err
	}
	if tag != "" {
		req.Header.Set(cond, tag)
	}
	res, err := f.src.Client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("revocation: %w", err)
	}
	defer res.Body.Close()
	switch res.StatusCode {
	case http.StatusOK:
	case http.StatusNotModified:
		return nil, "", errNotModified
	case http.StatusPreconditionFailed:
		return nil, "", errMismatch
	default:
		return nil, "", fmt.Errorf("revocation: %s answered %s", u, res.Status)
	}
	b, _, err := readBounded(res.Body, limit, u)
	return b, res.Header.Get("ETag"), err
}

func readBounded(r io.Reader, limit int64, what string) ([]byte, string, error) {
	b, err := io.ReadAll(io.LimitReader(r, limit+1))
	switch {
	case err != nil:
		return nil, "", fmt.Errorf("revocation: %s: %w", what, err)
	case int64(len(b)) > limit:
		return nil, "", fmt.Errorf("revocation: %s is larger than %d bytes", what, limit)
	}
	return b, "", nil
}
