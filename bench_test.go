// SPDX-License-Identifier: BSD-3-Clause

package revocation

import (
	"context"
	"testing"
	"time"
)

// BenchmarkFetchUnchangedCRL is a poll of a source that sends no ETag, which
// downloads the 100 000-entry CRL again each time.
func BenchmarkFetchUnchangedCRL(b *testing.B) {
	dir := b.TempDir()
	ca := newX509CA(b, "ca")
	now := time.Now()
	serials := make([]int64, 100000)
	for i := range serials {
		serials[i] = int64(i + 1)
	}
	der := ca.crl(b, 1, now.Add(-time.Hour), now.Add(time.Hour), nil, serials...)
	p := write(b, dir, "x.crl", der)
	f, err := NewFetcher(Source{URL: FileURL(p), Kind: CRL, X509CA: ca.cert}, nil)
	if err != nil {
		b.Fatal(err)
	}
	if _, _, err := f.Fetch(context.Background()); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(der)))
	for b.Loop() {
		if _, changed, err := f.Fetch(context.Background()); err != nil || changed {
			b.Fatalf("changed=%v err=%v", changed, err)
		}
	}
}
