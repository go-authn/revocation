// SPDX-License-Identifier: BSD-3-Clause

package revocation

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"strings"
	"testing"
	"time"
)

// CRLs Go's x509.CreateRevocationList will not write, built from RFC 5280
// 5.1's ASN.1 and signed: so that the refusals of what is missing from one
// are tested on CRLs that verify.

type rawEntry struct {
	Serial     *big.Int
	Revoked    time.Time
	Extensions []pkix.Extension `asn1:"optional"`
}

type rawTBS struct {
	Version    int `asn1:"optional,default:0"`
	Signature  pkix.AlgorithmIdentifier
	Issuer     asn1.RawValue
	ThisUpdate time.Time
	NextUpdate time.Time        `asn1:"optional"`
	Revoked    []rawEntry       `asn1:"optional"`
	Extensions []pkix.Extension `asn1:"optional,explicit,tag:0"`
}

type rawCRL struct {
	TBS       asn1.RawValue
	Algorithm pkix.AlgorithmIdentifier
	Signature asn1.BitString
}

var oidECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}

func signRawCRL(t *testing.T, ca x509CA, tbs rawTBS) []byte {
	t.Helper()
	alg := pkix.AlgorithmIdentifier{Algorithm: oidECDSAWithSHA256}
	tbs.Version = 1 // v2
	tbs.Signature = alg
	tbs.Issuer = asn1.RawValue{FullBytes: ca.cert.RawSubject}
	der, err := asn1.Marshal(tbs)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(der)
	sig, err := ecdsa.SignASN1(rand.Reader, ca.key, h[:])
	if err != nil {
		t.Fatal(err)
	}
	out, err := asn1.Marshal(rawCRL{TBS: asn1.RawValue{FullBytes: der}, Algorithm: alg, Signature: asn1.BitString{Bytes: sig, BitLength: 8 * len(sig)}})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestVerifyCRLRefusesWhatGoWillNotWrite(t *testing.T) {
	ca := newX509CA(t, "ca")
	now := time.Now().UTC().Truncate(time.Second)
	number := func(n int64) pkix.Extension {
		v, _ := asn1.Marshal(big.NewInt(n))
		return pkix.Extension{Id: oidCRLNumber, Value: v}
	}
	good := rawTBS{ThisUpdate: now, NextUpdate: now.Add(time.Hour), Extensions: []pkix.Extension{number(3)}}
	if _, err := VerifyCRL(signRawCRL(t, ca, good), ca.cert); err != nil {
		t.Fatalf("control: the hand-built CRL is refused: %v", err)
	}
	for name, c := range map[string]struct {
		tbs  rawTBS
		want string
	}{
		"no CRL number":     {rawTBS{ThisUpdate: now, NextUpdate: now.Add(time.Hour)}, "no CRL number"},
		"no nextUpdate":     {rawTBS{ThisUpdate: now, Extensions: []pkix.Extension{number(3)}}, "no nextUpdate"},
		"next before this":  {rawTBS{ThisUpdate: now, NextUpdate: now.Add(-time.Hour), Extensions: []pkix.Extension{number(3)}}, "not after"},
		"critical in entry": {rawTBS{ThisUpdate: now, NextUpdate: now.Add(time.Hour), Extensions: []pkix.Extension{number(3)},
			Revoked: []rawEntry{{Serial: big.NewInt(9), Revoked: now, Extensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 3}, Critical: true, Value: []byte{5, 0}}}}}}, "entry"},
	} {
		_, err := VerifyCRL(signRawCRL(t, ca, c.tbs), ca.cert)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want an error saying %q", name, err, c.want)
		}
	}
}
