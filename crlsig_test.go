// SPDX-License-Identifier: BSD-3-Clause

package revocation

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"strings"
	"testing"
	"time"
)

// caWith is a CA certificate for key, self-signed.
func caWith(t *testing.T, key crypto.Signer) *x509.Certificate {
	t.Helper()
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c
}

// Every signature algorithm a CRL may come with verifies, signed by its
// CA; the control, the same kind of key but another one, is refused.
func TestCRLSignatureAlgorithms(t *testing.T) {
	rsaKey := func() crypto.Signer { k, _ := rsa.GenerateKey(rand.Reader, 2048); return k }
	ec := func(c elliptic.Curve) func() crypto.Signer {
		return func() crypto.Signer { k, _ := ecdsa.GenerateKey(c, rand.Reader); return k }
	}
	ed := func() crypto.Signer { _, k, _ := ed25519.GenerateKey(rand.Reader); return k }
	for _, c := range []struct {
		name string
		key  func() crypto.Signer
		alg  x509.SignatureAlgorithm
	}{
		{"RSA SHA-256", rsaKey, x509.SHA256WithRSA},
		{"RSA SHA-512", rsaKey, x509.SHA512WithRSA},
		{"RSA-PSS SHA-256", rsaKey, x509.SHA256WithRSAPSS},
		{"RSA-PSS SHA-384", rsaKey, x509.SHA384WithRSAPSS},
		{"ECDSA P-256", ec(elliptic.P256()), x509.ECDSAWithSHA256},
		{"ECDSA P-384", ec(elliptic.P384()), x509.ECDSAWithSHA384},
		{"Ed25519", ed, x509.PureEd25519},
	} {
		key, other := c.key(), c.key()
		ca, otherCA := caWith(t, key), caWith(t, other)
		now := time.Now()
		der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{SignatureAlgorithm: c.alg,
			Number: big.NewInt(1), ThisUpdate: now, NextUpdate: now.Add(time.Hour)}, ca, key)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if _, err := VerifyCRL(der, ca); err != nil {
			t.Errorf("%s: refused, signed by its CA: %v", c.name, err)
		}
		if _, err := VerifyCRL(der, otherCA); err == nil {
			t.Errorf("%s: accepted against another CA of the same kind", c.name)
		}
	}
}

// A CRL signed by somebody else is refused before it is parsed: v0.2.0
// parsed first, and a 63 MB one cost 3 GB allocated (found by a security
// audit). Here 100 000 entries, about 2 MB: a parse is hundreds of
// thousands of allocations; the refusal is a few dozen.
func TestACRLFromAnotherCAIsRefusedBeforeItIsParsed(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca, otherCA := caWith(t, key), caWith(t, other)
	entries := make([]x509.RevocationListEntry, 100_000)
	now := time.Now()
	for i := range entries {
		entries[i] = x509.RevocationListEntry{SerialNumber: big.NewInt(int64(i + 1)), RevocationTime: now}
	}
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1),
		ThisUpdate: now, NextUpdate: now.Add(time.Hour), RevokedCertificateEntries: entries}, otherCA, other)
	if err != nil {
		t.Fatal(err)
	}
	allocs := testing.AllocsPerRun(1, func() {
		if _, err := VerifyCRL(der, ca); err == nil {
			t.Fatal("accepted")
		}
	})
	t.Logf("%d bytes refused in %.0f allocations", len(der), allocs)
	if allocs > 1000 {
		t.Errorf("refusing a CRL from another CA took %.0f allocations: it was parsed first", allocs)
	}
}

// What is not a CRL, or is signed with an algorithm this reader does not
// verify, is refused, saying which.
func TestCRLSignatureRefusals(t *testing.T) {
	ca := newX509CA(t, "ca")
	now := time.Now().UTC().Truncate(time.Second)
	number, _ := asn1.Marshal(big.NewInt(1))
	good := signRawCRL(t, ca, rawTBS{ThisUpdate: now, NextUpdate: now.Add(time.Hour),
		Extensions: []pkix.Extension{{Id: oidCRLNumber, Value: number}}})
	if _, err := VerifyCRL(good, ca.cert); err != nil {
		t.Fatalf("control: %v", err)
	}
	// ecdsa-with-SHA1: a valid OID, not one this reader verifies.
	var outer rawCRL
	if _, err := asn1.Unmarshal(good, &outer); err != nil {
		t.Fatal(err)
	}
	outer.Algorithm.Algorithm = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 1}
	sha1, _ := asn1.Marshal(outer)
	for name, c := range map[string]struct {
		der  []byte
		want string
	}{
		"ecdsa-with-SHA1": {sha1, "not one this reader verifies"},
		"trailing data":   {append(append([]byte{}, good...), 0), "not a CRL"},
		"not DER":         {[]byte{0x30, 0x80, 1}, "not a CRL"},
	} {
		if _, err := VerifyCRL(c.der, ca.cert); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
}
