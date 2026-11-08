// SPDX-License-Identifier: BSD-3-Clause

package revocation

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

// A Floor orders without being trusted: read from a copy that does not
// verify, it refuses a list older than it, admits the same or a newer one,
// and is only consulted until a list is held.
func TestFloorRefusesAnOlderListFromTheFile(t *testing.T) {
	ca := newSSHCA(t)
	now := time.Now()
	dir := t.TempDir()
	floorRaw := krlOf(t, ca, 5, now.Add(-time.Minute), now.Add(time.Hour), 10)
	floor, err := UnverifiedOrder(KRL, floorRaw)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		v      uint64
		issued time.Time
		ok     bool
	}{
		{4, now.Add(-time.Second), false},     // an older version, issued later
		{5, now.Add(-2 * time.Minute), false}, // the same version, issued earlier
		{5, now.Add(-time.Minute), true},      // the same list
		{5, now.Add(-time.Second), true},      // re-issued
		{6, now.Add(-2 * time.Minute), true},  // newer
	} {
		raw, sig := signedKRL(t, ca, c.v, c.issued, now.Add(time.Hour))
		p := filepath.Join(dir, "krl")
		write(t, dir, "krl", raw)
		write(t, dir, "krl.sig", sig)
		f, err := NewFetcher(Source{URL: FileURL(p), Kind: KRL, SSHCA: ca.pub, Floor: floor, Clock: func() time.Time { return now }}, nil)
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = f.Fetch(t.Context())
		switch {
		case c.ok && err != nil:
			t.Errorf("v%d issued %s: refused: %v", c.v, c.issued.Sub(now), err)
		case !c.ok && !errors.Is(err, ErrRollback):
			t.Errorf("v%d issued %s: %v, want ErrRollback", c.v, c.issued.Sub(now), err)
		case !c.ok && f.Held() != nil:
			t.Errorf("v%d: a list below the floor is held", c.v)
		}
	}
}

func TestUnverifiedOrderKRLAndCRL(t *testing.T) {
	ca := newSSHCA(t)
	now := time.Now().Truncate(time.Second)
	f, err := UnverifiedOrder(KRL, krlOf(t, ca, 7, now, now.Add(time.Hour)))
	if err != nil || f.Version.Int64() != 7 || !f.Issued.Equal(now) || f.Kind != KRL {
		t.Errorf("KRL: %+v, %v", f, err)
	}
	if _, err := UnverifiedOrder(KRL, []byte("garbage")); err == nil {
		t.Error("a KRL that does not parse gave a floor")
	}

	x := newX509CA(t, "ca")
	der := x.crl(t, 9, now, now.Add(time.Hour), nil)
	for name, raw := range map[string][]byte{"DER": der, "PEM": pemOf("X509 CRL", der)} {
		f, err := UnverifiedOrder(CRL, raw)
		if err != nil || f.Version.Int64() != 9 || !f.Issued.Equal(now) || f.Kind != CRL {
			t.Errorf("CRL %s: %+v, %v", name, f, err)
		}
	}
	for name, raw := range map[string][]byte{"garbage": []byte("garbage"), "not a CRL": pemOf("CERTIFICATE", der), "too big": make([]byte, maxCRL+1)} {
		if _, err := UnverifiedOrder(CRL, raw); err == nil {
			t.Errorf("CRL %s gave a floor", name)
		}
	}
	if _, err := UnverifiedOrder(Kind(99), der); err == nil {
		t.Error("an unknown kind gave a floor")
	}

	// A floor of one kind does not admit the other.
	kf, _ := UnverifiedOrder(KRL, krlOf(t, ca, 1, now, now.Add(time.Hour)))
	if err := kf.Admits(&List{Kind: CRL, Version: f.Version, Issued: now}); err == nil {
		t.Error("a CRL followed a KRL floor")
	}
}
