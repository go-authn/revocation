// SPDX-License-Identifier: BSD-3-Clause

// Package revocation verifies, orders and fetches revocation lists -- SSH
// KRLs with a detached SSHSIG signature, and X.509 CRLs -- for a
// distribution that trusts nothing in between: every list is checked
// against the CA it revokes for, refused once it is no longer current, and
// never let replace a newer one.
//
// VerifyKRL and VerifyCRL check a list; List.Current and List.Follows say
// whether it may be used now and whether it may replace the one held;
// Fetcher fetches one source with all three; SignKRL signs a KRL for an
// issuer; FailClosedKRL is what a distributor writes for sshd when it has
// no current list.
//
// PROTOCOL.md says what is verified and why; the authn-revokd command distributes
// lists with this package.
package revocation
