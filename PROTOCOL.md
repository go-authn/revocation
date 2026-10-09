# Distributing revocation lists

This document says how a revocation list travels from the authority that
writes it to every server that must refuse what it lists, without any of the
servers in between being trusted, and without a server ever mistaking a stale
list for a current one. It covers OpenSSH key revocation lists (KRLs) and X.509
certificate revocation lists (CRLs).

It adds as little as it can. A CRL already carries all it needs; a KRL gets a
detached signature and one extension, both of which deployed OpenSSH already
tolerates. The lists themselves stay what `sshd`, OpenSSL and every TLS
server already read.

## 1. What is wrong with copying files

OpenSSH has no mechanism to distribute a KRL; the practice is configuration
management, `rsync` or a `cron` job fetching over HTTPS. Two things are then
missing, whatever the transport:

- **Authenticity.** A KRL is not signed. OpenSSH never verifies the KRL
  signature section. PROTOCOL.krl section 6 says "OpenSSH >= 9.4 will refuse
  to load KRLs that contain signatures"; measured, `ssh-keygen` 9.6p1 and
  10.3p1 load such a KRL and skip the signature (go-authn/krl's
  `TestOracleSigned`). Either way, a KRL is exactly as authentic as the last
  hop that carried it, and a mirror, a cache or a compromised web server can
  serve an empty one.
- **Freshness.** Neither `sshd` nor a KRL has a notion of a list's end: a copy
  that stopped updating months ago is read as the current one. TUF calls
  serving it an *indefinite freeze attack* ("An attacker cannot respond to
  client requests with the same, outdated metadata without the client being
  aware of the problem", TUF specification 1.5.2), and nothing in a copied
  file prevents it.
  `sshd` does fail closed when the file is unreadable (sshd_config(5),
  `RevokedKeys`), but not when it is old.

A CRL has neither problem: it is signed by its CA, and carries `nextUpdate`
("the date by which the next CRL will be issued", RFC 5280 5.1.2.5). RFC
5280's validation algorithm does not use a CRL past it: "If the current time
is after the value of the CRL next update field, then do one of the
following" -- a delta CRL, or a new complete CRL (6.3.3, step (a)(1)).
OpenSSL does the same: measured with OpenSSL 3.6.4, `openssl verify -crl_check` on a
CRL past its `nextUpdate` answers `error 12 ... CRL has expired` and refuses
the certificate. This protocol brings KRLs to the same place, and treats both
alike from there.

## 2. The objects

### 2.1 An X.509 CRL

Unchanged, DER-encoded (RFC 5280). A distributor accepts one only when:

- its signature verifies against the CA certificate the distributor was
  configured with, and its issuer is that certificate's subject;
- it has a `nextUpdate` later than now, and a `thisUpdate` not in the future;
- it has a CRL Number, which "conveys a monotonically increasing sequence
  number for a given CRL scope and CRL issuer" (RFC 5280 5.2.3);
- it is not a delta CRL (no `deltaCRLIndicator`: a delta lists only what
  changed since the complete base CRL it references, RFC 5280 5.2.4, and a
  distributor that hands out lists one at a time cannot pair them), and
  carries no critical extension other than those it understands.

### 2.2 An OpenSSH KRL and its signature

Two files:

- **`<name>`**: the KRL, in the format of OpenSSH's PROTOCOL.krl, with one
  extension section:
  - name `expires@go-authn.github.io`, **not critical**, body one `uint64`:
    seconds since 1970-01-01 UTC after which the list is no longer current.

  PROTOCOL.krl section 5 defines extension sections and recommends the
  `name@domain` form; a non-critical one is skipped by `sshd`
  (krl.c `extension_section`), so the file stays what `RevokedKeys` loads.
  go-authn/krl writes and reads it (`Builder.SetExpires`, `KRL.Expires`).
- **`<name>.sig`**: an armored SSHSIG signature (PROTOCOL.sshsig) over the
  whole KRL file, by the **SSH CA key** whose certificates the list revokes,
  with the namespace `krl@go-authn.github.io`. Signers use the hash
  `sha512`, `ssh-keygen -Y sign`'s default; verifiers accept `sha256` too,
  the other hash PROTOCOL.sshsig allows. This is
  what PROTOCOL.krl recommends instead of its own signature section, and
  what `ssh-keygen -Y verify` checks:

  ```sh
  echo "ca@univ-a.fr namespaces=\"krl@go-authn.github.io\" $(cat ca.pub)" > allowed
  ssh-keygen -Y verify -f allowed -I ca@univ-a.fr -n krl@go-authn.github.io \
      -s univ-a.krl.sig < univ-a.krl
  ```

  The namespace keeps the signature from being accepted as anything else
  ("This prevents cross-protocol attacks", PROTOCOL.sshsig). Signing with the
  CA key itself needs no new trust: a server that accepts the CA's
  certificates (`TrustedUserCAKeys`) already trusts that key above anything
  a revocation could do.

A distributor accepts a KRL only when the signature verifies by the CA key it
was configured with, under that namespace; the KRL parses as `sshd` parses
it; and it has an expiry later than now.

## 3. Rules every distributor follows

A *distributor* is anything that fetches lists and passes them on: a server
using them itself (go-fileshare), an agent writing them to disk for `sshd` or
nginx (`authn-revokd`), a mirror (`authn-revokd` with `listen`).

1. **Verify before use, and before passing on.** A list that does not verify
   is never written, served or used. The last good copy stays.
2. **Never backwards.** A list's position is its version (the KRL's
   `krl_version`, the CRL Number) and then its issue time (`generated_date`,
   `thisUpdate`). A list lower than the one held is refused (TUF's *rollback
   attack*). An equal version with a later issue time is the same list
   re-issued with a new expiry, and replaces it. The copy held survives a
   restart: it is the file written, read back at start.
3. **Never past its end.** A list whose expiry has passed is not current,
   whatever the distributor holds; and a distributor may bound it more tightly
   with its own `max_age` from the issue time.
4. **Fail closed.** When the held list is no longer current and no current one
   can be had, what the list protects is refused:
   - for X.509, the expired CRL is left in place; OpenSSL refuses it by itself
     (section 1);
   - for `sshd`, which has no notion of expiry, the distributor writes a KRL
     that **revokes the CA key itself**: `sshd` checks the CA key of every
     certificate against the list (krl.c `ssh_krl_check_key`), so every
     certificate of that CA is refused, and nothing else. go-authn/krl's
     `TestOracleRevokingTheCARevokesEveryCertificate` measures it with
     `ssh-keygen -Q`.
5. **Merge each list for its own CA.** A distributor that merges several
   CAs' lists into one file (`sshd` before OpenSSH 10.3 reads one
   `RevokedKeys`) keeps each list's effect on its own CA's certificates and
   none on another CA. A revoked plain key cannot be scoped: `sshd` checks a
   certificate's own key against the file whoever signed it, so a list's key
   revocations are kept in a shared file only from a source trusted with
   every CA's users (authn-revokd's `revoke_keys`). A list that cannot be merged
   fails closed for its own CA (rule 4), not for the others.
6. **Write atomically.** A file is written beside its target and renamed over
   it. `sshd` reads `RevokedKeys` at each authentication (auth.c
   `auth_key_is_revoked`, krl.c `ssh_krl_file_contains_key`), so the rename is
   all it needs; a server that reads its CRL once at start is told to reload.

## 4. Transport

Any. Because every object authenticates itself, a list may come over HTTPS,
plain HTTP inside a cluster, a CDN, a mirror, or a file dropped by
configuration management; what changes with the transport is only how fast a
change arrives, never whether a forged or stale list is accepted.

Over HTTP:

- `GET <url>` returns the list; `GET <url>.sig` returns a KRL's signature.
- The list carries an `ETag`; a distributor polls with `If-None-Match`, and a
  `304 Not Modified` costs a few hundred bytes.
- The signature is fetched with `If-Match: <the list's ETag>`, so that a list
  re-issued between the two requests answers `412 Precondition Failed` instead
  of a signature that does not match; the distributor then fetches both again.
  A server that ignores `If-Match` still cannot make it accept a mismatched
  pair: the signature would not verify, and the next poll fetches both again.
- Bodies are bounded (a KRL at OpenSSH's own load limit, a CRL at 64 MiB).

Polling is cheap enough to be the whole mechanism: see the measurement in the
README. A push (go-authn/bridge's Shared Signals stream, RFC 8936) can make a
consumer fetch sooner; it never replaces the fetch, since the list is what is
verified.

## 5. Issuers

An issuer (go-authn/bridge) publishes, for each CA:

- the list, re-issued well before it expires: with an expiry `E` after issue,
  every `E/2` at least, so that a distributor polling every `E/4` always has a
  current list while the issuer is up;
- for a KRL, its signature; the pair is produced once per issue and served
  unchanged until the next, so both requests see the same list.

## 6. What this does not do

- It does not make a revocation reach a server faster than the server polls.
  The bound on how long a revoked credential keeps working is the poll
  interval plus the issuer's re-issue delay; on a lapse, it is the expiry.
- It does not protect against the CA key. Whoever holds it can sign any list,
  as they can sign any certificate.
- It does not hide which lists a server fetches. Each server fetches whole
  lists, so nobody learns which certificate it is checking: the privacy
  argument Let's Encrypt gave for replacing OCSP with CRLs.
