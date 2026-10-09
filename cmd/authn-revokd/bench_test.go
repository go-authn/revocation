// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-authn/krl"
	"github.com/go-authn/revocation"
)

// What a poll costs the mirror, for a list of n revocations among the
// serials a CA has issued: the unchanged poll (304) every agent makes
// every refresh, and the full download it makes when the list changes.
//
//	go test -run '^$' -bench Mirror -benchmem ./cmd/authn-revokd
func BenchmarkMirror(b *testing.B) {
	for _, n := range []int{100, 10_000, 100_000} {
		is := newSSHIssuer(&testing.T{})
		// n revoked among 20n issued, at random: the sparse case.
		kb := krl.NewBuilder(1, "bench")
		rng := rand.New(rand.NewPCG(1, uint64(n)))
		for range n {
			kb.RevokeSerial(is.signer.PublicKey(), 1+rng.Uint64N(uint64(20*n)))
		}
		now := time.Now()
		kb.SetExpires(now.Add(time.Hour))
		raw, _ := kb.Marshal(now)
		sig, _ := revocation.SignKRL(raw, is.signer)
		is.raw, is.sig = raw, sig
		origin := httptest.NewTLSServer(is)
		dir := b.TempDir()
		cfg := &config{StateDir: filepath.Join(dir, "state"), refresh: time.Minute,
			Sources: []sourceBlock{{Name: "a", URL: origin.URL + "/krl", kind: revocation.KRL, sshCA: is.signer.PublicKey()}},
			byName:  map[string]int{"a": 0}}
		a, err := newAgent(cfg, &safeBuffer{}, origin.Client())
		if err != nil {
			b.Fatal(err)
		}
		if err := a.syncOnce(context.Background()); err != nil {
			b.Fatal(err)
		}
		h := a.handler()
		tag := etag(raw)
		b.Run(fmt.Sprintf("n=%d/KRL=%dB/304", n, len(raw)), func(b *testing.B) {
			req := httptest.NewRequest("GET", "/a", nil)
			req.Header.Set("If-None-Match", tag)
			for b.Loop() {
				w := httptest.NewRecorder()
				h.ServeHTTP(w, req)
				if w.Code != http.StatusNotModified {
					b.Fatal(w.Code)
				}
			}
		})
		b.Run(fmt.Sprintf("n=%d/KRL=%dB/200", n, len(raw)), func(b *testing.B) {
			req := httptest.NewRequest("GET", "/a", nil)
			for b.Loop() {
				w := httptest.NewRecorder()
				h.ServeHTTP(w, req)
				if w.Code != http.StatusOK {
					b.Fatal(w.Code)
				}
			}
		})
		b.Run(fmt.Sprintf("n=%d/verify", n), func(b *testing.B) {
			for b.Loop() {
				if _, err := revocation.VerifyKRL(raw, sig, is.signer.PublicKey()); err != nil {
					b.Fatal(err)
				}
			}
		})
		origin.Close()
	}
}
