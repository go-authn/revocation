# go-authn/revocation

Distributing revocation lists, SSH KRLs and X.509 CRLs, from the authority that
writes them to every server that must refuse what they list, **without trusting
anything in between and without ever mistaking a stale list for a current one**.

- **[PROTOCOL.md](PROTOCOL.md)**: what is verified, and why.
- **`revokd`**: an agent that fetches the lists, keeps only those that verify,
  and writes them where `sshd` and TLS servers read them. When a list lapses, it
  fails closed for `sshd`. With `listen`, it serves the verified lists to other
  agents as a **mirror**.
- **the Go package**: verifies, orders and fetches lists, and signs KRLs for an
  issuer (go-authn/bridge).

## Why

OpenSSH has no way to distribute a KRL. Practice is configuration management,
`rsync` or `cron` with `curl`, and two things are missing whatever the transport:

- **A KRL is not signed.** OpenSSH stopped verifying the KRL signature section,
  and from 9.4 refuses a KRL that has one. So a KRL is only as authentic as the
  last hop that carried it.
- **Nothing says a KRL is stale.** `sshd` reads a file that stopped updating
  months ago as the current list. TUF calls serving such a file an *indefinite
  freeze attack*.

A CRL has neither problem: it is signed, and has a `nextUpdate` past which
OpenSSL refuses it (measured below). This brings KRLs to the same place:

| | KRL | CRL |
| --- | --- | --- |
| authentic | detached **SSHSIG** by the SSH CA key, namespace `krl@go-authn.github.io`, checked with `ssh-keygen -Y verify` too | signed by its CA |
| current | **`expires@go-authn.github.io`**, a non-critical extension, which sshd ignores ([go-authn/krl](https://github.com/go-authn/krl) v0.2.0) | `nextUpdate` |
| never backwards | `krl_version`, then generation date | CRL Number, then `thisUpdate` |
| fail closed | revokd writes a KRL that **revokes the CA key**: every certificate of that CA is refused | OpenSSL refuses an expired CRL by itself |

Since every list verifies by itself, the transport can be HTTPS, HTTP inside a
cluster, a CDN, a mirror, or a file. The transport decides how fast a change
arrives, never whether a forged or stale list is accepted.

## revokd

```hcl
state_dir = "/var/lib/revokd"     # the verified copies: rollback protection, and what a mirror serves
refresh   = "1m"

source "univ-a-ssh" {
  url    = "https://idp.univ-a.fr/ssh/krl"   # and .../ssh/krl.sig
  ssh_ca = "/etc/ssh/ca/univ-a.pub"          # what the list must be signed by
}
source "univ-b-ssh" {
  url    = "http://mirror.cluster.local:8080/univ-b-ssh"   # a mirror: plain http is fine
  ssh_ca = "/etc/ssh/ca/univ-b.pub"
}
source "univ-a-x509" {
  url     = "https://idp.univ-a.fr/x509/crl"
  x509_ca = "/etc/ssl/univ-a-ca.pem"
  max_age = "2h"                             # optional, on top of nextUpdate
}

output "sshd" {                              # sshd_config: RevokedKeys /etc/ssh/revoked.krl
  path    = "/etc/ssh/revoked.krl"
  sources = ["univ-a-ssh", "univ-b-ssh"]     # merged into one file
}
output "nginx" {
  path      = "/etc/nginx/univ-a.crl"
  sources   = ["univ-a-x509"]
  format    = "pem"
  on_change = ["systemctl", "reload", "nginx"]   # retried at each sync until it succeeds
}

listen = ":8080"                             # optional: serve the verified lists (a mirror)
```

```sh
revokd -config /etc/revokd.hcl          # run
revokd -config /etc/revokd.hcl -once    # one sync, for cron: exit 1 when a list is not current
```

- **One file for sshd.** `RevokedKeys` takes a single file before OpenSSH 10.3
  (multiple files arrived with openssh-portable 135a622, 2026-02-11; Debian 13
  ships 10.0, Ubuntu 24.04 9.6), so the KRL sources of an output are merged
  (`krl.Builder.Merge`). A source whose list is not current contributes its CA
  key, revoked, and the file's comment says `FAIL CLOSED` and names it
  (`ssh-keygen -Q -l -f` shows it).
- **No reload for sshd.** sshd reads `RevokedKeys` at each authentication, so
  the atomic rename is enough. An unreadable file refuses every login
  (sshd_config(5)).
- **The mirror** serves `GET /<source>` (with ETag, `If-None-Match`),
  `GET /<source>.sig` (with `If-Match`, 412 when the list changed in between),
  and `GET /healthz` (503 while a source has no current list). It serves from
  memory the pair its fetcher holds, so a list and a signature always match.
  Mirrors chain: a mirror's source can be another mirror.

## Measured

- **A real sshd judges what revokd writes** (`TestSSHDJudgesWhatRevokdWrites`,
  OpenSSH 10.3p1 here and the Ubuntu runner's on CI). A certificate logs in with
  nothing revoked; once its serial is revoked it is refused; with a list
  revoking nothing that then lapses, it is refused (the fail-closed list); with
  a fresh list it logs in again. sshd is never restarted. Removing the
  fail-closed list from revokd turns this red.
- **OpenSSL fails closed on its own:** `openssl verify -crl_check` with a CRL
  past its `nextUpdate` answers `error 12 ... CRL has expired` (OpenSSL 3.6.4).
- **ssh-keygen judges the signatures both ways:** `ssh-keygen -Y verify`
  accepts what `SignKRL` writes, and `VerifyKRL` accepts what
  `ssh-keygen -Y sign` writes. Each refuses the other namespace.
- **RSA with SHA-1** (`ssh-rsa`), which PROTOCOL.sshsig forbids, is accepted by
  x/crypto's and hiddeco/sshsig's `Verify`. It is refused because
  hiddeco/sshsig's `Unarmor` refuses that format. A test holds the dependency to
  it, with `rsa-sha2-512` as the control.
- **A poll costs the mirror about 0.6 µs** of handler time when nothing changed
  (304), **whatever the size of the list**. The first version hashed the list
  per request: 122 µs at 100 000 revocations. A full download of 100 000 sparse
  revocations is 256 KiB and costs 22 µs to serve and 2.6 ms to verify. So
  10 000 servers polling every minute make 167 requests a second, which a
  mirror handles with a fraction of a core, TLS aside
  (`go test -run '^$' -bench Mirror ./cmd/revokd`).

## What it does not do

A revocation reaches a server no faster than the server polls (`refresh`),
plus the issuer's delay in re-issuing. When the issuer is down, it is refused
from the list's expiry onward. Whoever holds a CA's key can sign any list, as
they can sign any certificate.

## License

BSD 3-Clause.
