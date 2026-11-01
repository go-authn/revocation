// SPDX-License-Identifier: BSD-3-Clause

package revocation

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-authn/krl"
	"github.com/hiddeco/sshsig"
	"golang.org/x/crypto/ssh"
)

// The fuzz targets use a CA with a fixed key, so that a corpus recorded by one
// run means the same thing in the next: with a fresh key per run, no mutated
// seed would ever verify, and the parsers behind the signature check would
// never be reached.
func fuzzSeed(b byte) ed25519.PrivateKey { return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{b}, 32)) }

var fuzzEpoch = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func fuzzX509CA(tb testing.TB) (*x509.Certificate, ed25519.PrivateKey) {
	tb.Helper()
	key := fuzzSeed(1)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fuzz-ca"},
		NotBefore: fuzzEpoch, NotAfter: fuzzEpoch.AddDate(50, 0, 0), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, key.Public(), key)
	if err != nil {
		tb.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		tb.Fatal(err)
	}
	return c, key
}

func fuzzCRL(tb testing.TB, ca *x509.Certificate, key ed25519.PrivateKey, num int64, next time.Time, ext []pkix.Extension, serials ...int64) []byte {
	tb.Helper()
	var entries []x509.RevocationListEntry
	for _, s := range serials {
		entries = append(entries, x509.RevocationListEntry{SerialNumber: big.NewInt(s), RevocationTime: fuzzEpoch})
	}
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(num), ThisUpdate: fuzzEpoch,
		NextUpdate: next, RevokedCertificateEntries: entries, ExtraExtensions: ext}, ca, key)
	if err != nil {
		tb.Fatal(err)
	}
	return der
}

// checkCRLInvariants is what a CRL VerifyCRL returned must satisfy.
func checkCRLInvariants(t *testing.T, ca *x509.Certificate, raw []byte, l *List) {
	t.Helper()
	if l.Kind != CRL || l.Version == nil || l.CRL == nil || l.Version.Sign() < 0 {
		t.Fatalf("a verified CRL without its number or form: %+v", l)
	}
	if !l.Expires.After(l.Issued) {
		t.Fatalf("a verified CRL whose nextUpdate %v is not after thisUpdate %v", l.Expires, l.Issued)
	}
	// Idempotent: what was kept verifies again, to the same list.
	again, err := VerifyCRL(l.Raw, ca)
	if err != nil || !again.Same(l) {
		t.Fatalf("a verified CRL does not verify again: %v", err)
	}
}

func FuzzVerifyCRL(f *testing.F) {
	ca, key := fuzzX509CA(f)
	good := fuzzCRL(f, ca, key, 5, fuzzEpoch.Add(time.Hour), nil, 1, 2, 3)
	f.Add(good)
	f.Add(pemOf("X509 CRL", good))
	f.Add(pemOf("CERTIFICATE", good))
	f.Add([]byte{})
	f.Add([]byte{0x30, 0x00})
	f.Add(good[:len(good)/2])
	f.Fuzz(func(t *testing.T, raw []byte) {
		l, err := VerifyCRL(raw, ca)
		if err != nil {
			return
		}
		checkCRLInvariants(t, ca, raw, l)
	})
}

// FuzzVerifyCRLSigned fuzzes what is behind the signature check: a CRL the CA
// signed, with the fields and the extension an attacker who holds the CA key,
// or a buggy issuer, could put in it.
func FuzzVerifyCRLSigned(f *testing.F) {
	ca, key := fuzzX509CA(f)
	f.Add(int64(5), int64(3600), []byte{2, 5, 29, 20}, false, []byte{0x02, 0x01, 0x05})
	f.Add(int64(0), int64(1), []byte{2, 5, 29, 27}, true, []byte{0x02, 0x01, 0x01})
	f.Add(int64(-1), int64(-5), []byte{1, 2, 3}, true, []byte{})
	f.Fuzz(func(t *testing.T, num, nextSecs int64, oid []byte, critical bool, val []byte) {
		var ext []pkix.Extension
		if len(oid) >= 2 {
			arcs := asn1.ObjectIdentifier{int(oid[0] % 3), int(oid[1] % 40)}
			for _, b := range oid[2:] {
				arcs = append(arcs, int(b))
			}
			ext = append(ext, pkix.Extension{Id: arcs, Critical: critical, Value: val})
		}
		if nextSecs > 1<<40 || nextSecs < -(1<<40) {
			return
		}
		der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(num),
			ThisUpdate: fuzzEpoch, NextUpdate: fuzzEpoch.Add(time.Duration(nextSecs) * time.Second),
			ExtraExtensions: ext}, ca, key)
		if err != nil {
			return // the standard library refuses to write it
		}
		l, err := VerifyCRL(der, ca)
		if err != nil {
			return
		}
		checkCRLInvariants(t, ca, der, l)
		for _, e := range l.CRL.Extensions {
			if e.Critical && !e.Id.Equal(oidCRLNumber) && !e.Id.Equal(oidAuthorityKeyID) {
				t.Fatalf("a critical extension %v was accepted", e.Id)
			}
			if e.Id.Equal(oidDeltaCRL) {
				t.Fatal("a delta CRL was accepted")
			}
		}
	})
}

func fuzzSSHCA(tb testing.TB) ssh.Signer {
	tb.Helper()
	s, err := ssh.NewSignerFromKey(fuzzSeed(2))
	if err != nil {
		tb.Fatal(err)
	}
	return s
}

func fuzzSign(tb testing.TB, raw []byte, s ssh.Signer) []byte {
	tb.Helper()
	sig, err := sshsig.SignWithRand(bytes.NewReader(raw), rand.Reader, s, sshsig.HashSHA512, Namespace)
	if err != nil {
		tb.Fatal(err)
	}
	return sshsig.Armor(sig)
}

func checkKRLInvariants(t *testing.T, ca ssh.PublicKey, l *List) {
	t.Helper()
	if l.Kind != KRL || l.Version == nil || l.KRL == nil || l.Expires.IsZero() || l.KRL.Signed {
		t.Fatalf("a verified KRL without its version, expiry or form: %+v", l)
	}
	again, err := VerifyKRL(l.Raw, l.Sig, ca)
	if err != nil || !again.Same(l) {
		t.Fatalf("a verified KRL does not verify again: %v", err)
	}
}

func FuzzVerifyKRL(f *testing.F) {
	s := fuzzSSHCA(f)
	b := krl.NewBuilder(3, "fuzz")
	b.RevokeSerial(s.PublicKey(), 7)
	b.SetExpires(fuzzEpoch.Add(time.Hour))
	raw, err := b.Marshal(fuzzEpoch)
	if err != nil {
		f.Fatal(err)
	}
	sig := fuzzSign(f, raw, s)
	f.Add(raw, sig)
	f.Add(raw, []byte("-----BEGIN SSH SIGNATURE-----\n-----END SSH SIGNATURE-----\n"))
	f.Add(raw[:len(raw)/2], sig)
	f.Add([]byte{}, []byte{})
	f.Fuzz(func(t *testing.T, raw, sig []byte) {
		l, err := VerifyKRL(raw, sig, s.PublicKey())
		if err != nil {
			return
		}
		checkKRLInvariants(t, s.PublicKey(), l)
	})
}

// FuzzVerifyKRLSigned reaches the KRL parser behind the signature: the CA
// signs whatever the fuzzer wrote.
func FuzzVerifyKRLSigned(f *testing.F) {
	s := fuzzSSHCA(f)
	b := krl.NewBuilder(3, "fuzz")
	b.RevokeSerial(s.PublicKey(), 7)
	b.RevokeKeyID(s.PublicKey(), "someone")
	b.SetExpires(fuzzEpoch.Add(time.Hour))
	raw, _ := b.Marshal(fuzzEpoch)
	f.Add(raw)
	f.Add(raw[:len(raw)-3])
	f.Add([]byte("SSHKRL\n\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 1<<16 {
			return
		}
		l, err := VerifyKRL(raw, fuzzSign(t, raw, s), s.PublicKey())
		if err != nil {
			return
		}
		checkKRLInvariants(t, s.PublicKey(), l)
	})
}

// FuzzCheckCRLSignature feeds the signature check, which runs on bytes nobody
// has parsed.
func FuzzCheckCRLSignature(f *testing.F) {
	ca, key := fuzzX509CA(f)
	good := fuzzCRL(f, ca, key, 1, fuzzEpoch.Add(time.Hour), nil)
	f.Add(good)
	f.Add(good[:len(good)-1])
	f.Fuzz(func(t *testing.T, der []byte) {
		if err := checkCRLSignature(der, ca); err == nil {
			// Accepted: then it parses as a CRL signed by ca, or the check
			// accepted bytes the parser refuses -- fine, but never a CRL
			// whose issuer is another's: VerifyCRL decides that next.
			if _, perr := x509.ParseRevocationList(der); perr == nil {
				if cerr := mustSignedBy(der, ca); cerr != nil {
					t.Fatalf("the signature check accepted a CRL the standard library says is not signed by the CA: %v", cerr)
				}
			}
		}
	})
}

func mustSignedBy(der []byte, ca *x509.Certificate) error {
	rl, err := x509.ParseRevocationList(der)
	if err != nil {
		return err
	}
	return rl.CheckSignatureFrom(ca)
}

func FuzzFilePathAndRedact(f *testing.F) {
	f.Add("file:///etc/krl")
	f.Add("https://u:p@h/x?token=1")
	f.Add("file://host/x")
	f.Add("%zz")
	f.Fuzz(func(t *testing.T, u string) {
		FilePath(u)
		r := redact(u)
		if p, err := url.Parse(u); err == nil && p.User != nil {
			if pw, ok := p.User.Password(); ok && pw != "" && pw != "xxxxx" {
				if q, err := url.Parse(r); err == nil && q.User != nil {
					if got, _ := q.User.Password(); got == pw {
						t.Fatalf("redact(%q) = %q keeps the password", u, r)
					}
				}
			}
			if p.RawQuery != "" && strings.Contains(r, "?"+p.RawQuery) && p.RawQuery != "xxxxx" {
				t.Fatalf("redact(%q) = %q keeps the query", u, r)
			}
		}
	})
}
