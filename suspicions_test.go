// SPDX-License-Identifier: BSD-3-Clause

// Tests of the 2026-11-21 audit's suspicions (see the CHANGELOG).

package revocation

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"
	"time"
)

// RFC 5280 5.2.5: the issuing distribution point "identifies the CRL
// distribution point and scope"; an implementation that does not support it
// "MUST either treat the status of any certificate not listed on this CRL as
// unknown or locate another CRL". This reader supports none of it, so a CRL
// that carries one is a partition, not the whole list -- whether or not its
// issuer marked the extension critical, which RFC 5280 says it MUST.
func TestACRLWithAnIssuingDistributionPointIsRefusedCriticalOrNot(t *testing.T) {
	ca := newX509CA(t, "ca")
	now := time.Now()
	// IssuingDistributionPoint ::= SEQUENCE { [1] onlyContainsUserCerts TRUE }
	idp := []byte{0x30, 0x03, 0x81, 0x01, 0xff}
	for _, critical := range []bool{true, false} {
		ext := []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 28}, Critical: critical, Value: idp}}
		der := ca.crl(t, 1, now.Add(-time.Hour), now.Add(time.Hour), ext, 7)
		if _, err := VerifyCRL(der, ca.cert); err == nil {
			t.Errorf("a CRL with an issuingDistributionPoint (critical=%v) was read as a complete list", critical)
		}
	}
	// The control: the same CRL without the extension is read.
	der := ca.crl(t, 1, now.Add(-time.Hour), now.Add(time.Hour), nil, 7)
	if _, err := VerifyCRL(der, ca.cert); err != nil {
		t.Errorf("a complete CRL was refused: %v", err)
	}
}
