// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-authn/revocation"
)

// handler serves the verified copies -- a mirror -- in the form section 4
// of PROTOCOL.md describes:
//
//	GET /<source>        the list; ETag, If-None-Match
//	GET /<source>.sig    a KRL's signature; If-Match the list's ETag
//	GET /healthz         200 when every source holds a current list and
//	                     every output is written whole; 503 naming what is not
//
// It serves from memory, the pair a fetcher holds, never from the files a
// write may be half way through: a list and a signature come from the same
// issue, or a 412 says they would not.
func (a *agent) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", a.health)
	mux.HandleFunc("GET /{name}", a.serveList)
	return mux
}

// tagOf is l's ETag, from the cache; the cache holds the lists served
// now and nothing older.
func (a *agent) tagOf(l *revocation.List) string {
	a.tagMu.Lock()
	defer a.tagMu.Unlock()
	if t, ok := a.tags[l]; ok {
		return t
	}
	if len(a.tags) >= 2*len(a.cfg.Sources) {
		clear(a.tags)
	}
	t := etag(l.Raw)
	a.tags[l] = t
	return t
}

func etag(b []byte) string {
	h := sha256.Sum256(b)
	return `"` + hex.EncodeToString(h[:16]) + `"`
}

func (a *agent) serveList(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	base, sig := strings.CutSuffix(name, ".sig")
	i, ok := a.cfg.byName[base]
	if !ok {
		http.NotFound(w, r)
		return
	}
	l := a.fetchers[i].Held()
	if l == nil || (sig && l.Kind != revocation.KRL) {
		http.NotFound(w, r)
		return
	}
	tag := a.tagOf(l)
	h := w.Header()
	h.Set("Content-Type", "application/octet-stream")
	// Short: a mirror behind a cache must not hold a list past the next
	// poll. Freshness is the list's own expiry, not this header.
	h.Set("Cache-Control", "max-age=30")
	if sig {
		if m := r.Header.Get("If-Match"); m != "" && m != tag {
			w.WriteHeader(http.StatusPreconditionFailed)
			return
		}
		w.Write(l.Sig)
		return
	}
	h.Set("ETag", tag)
	if r.Header.Get("If-None-Match") == tag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Write(l.Raw)
}

func (a *agent) health(w http.ResponseWriter, _ *http.Request) {
	var lapsed, broken []string
	for i := range a.cfg.Sources {
		if a.current(i) == nil {
			lapsed = append(lapsed, a.cfg.Sources[i].Name)
		}
	}
	a.mu.RLock()
	for _, o := range a.cfg.Outputs {
		if err := a.outErrs[o.Name]; err != nil {
			// The error names what fails: a source whose list cannot be
			// merged, or the output itself.
			broken = append(broken, o.Name+": "+strings.ReplaceAll(err.Error(), "\n", "; "))
		}
	}
	a.mu.RUnlock()
	if len(lapsed)+len(broken) > 0 {
		w.WriteHeader(http.StatusServiceUnavailable)
		if len(lapsed) > 0 {
			fmt.Fprintf(w, "no current list: %s\n", strings.Join(lapsed, ", "))
		}
		if len(broken) > 0 {
			fmt.Fprintf(w, "output %s\n", strings.Join(broken, "\noutput "))
		}
		return
	}
	fmt.Fprintln(w, "ok")
}
