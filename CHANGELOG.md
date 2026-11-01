# Changelog

Versions follow [semantic versioning](https://semver.org); below v1.0.0 a
breaking change bumps the minor version.

## v0.6.7

Audit, fuzzing, chaos and performance pass. Every item below was proved by a
test that failed first.

### Fixed

- **A list that lapsed was refused only at the next refresh.** With
  `refresh = "1h"`, `authn-revokd` kept the last KRL on disk, current as far as
  `sshd` could tell, for up to an hour after the issuer stopped. The agent now
  wakes at the first expiry (or `max_age`) of a current list and fails closed
  then.
- **One upstream that never answers delayed every other source**, and the
  outputs with them: sources were fetched one after the other, a request waits
  up to a minute, a fetch makes up to four. Sources are now fetched together
  (at most 16 at once), each within two minutes.
- **A hung `on_change` command froze the agent.** It ran with the agent's lock
  held, so `/healthz` and the next sync hung with it, and it had no deadline.
  It now runs without the lock, is killed after one minute (and the children
  holding its output with it), and is retried at the next sync like any other
  failure.
- **An output deleted, truncated or replaced behind the agent's back stayed
  that way** until the list next changed. `sshd` refuses every login when its
  `RevokedKeys` is unreadable. The file is now compared with the disk at every
  sync, and rewritten (and `on_change` run) when it differs.
- **A `file://` source naming a FIFO blocked the agent forever** in `open(2)`.
  A source must now be a regular file.
- **A URL's password and query (a token) appeared in errors**, so in the logs
  and in the unauthenticated `/healthz` of a mirror. Errors now show the URL
  without its password, query and fragment.
- **A CRL number outside `0..2^159`** was accepted (found by fuzzing: `-1`).
  RFC 5280 5.2.3: `CRLNumber ::= INTEGER (0..MAX)`, at most 20 octets.
- The mirror had no read or write timeout: a client that asked for a list and
  never read it held its connection for good. It now has them.
- Temporary files of a write killed between creating and renaming them were
  never removed. They are swept at start-up.

### Performance

- A source that sends no `ETag` is downloaded at every poll, and the same bytes
  were verified and parsed again: a 100 000-entry CRL (2.1 MB) cost 300 138
  allocations and 97 MB per poll, now 37 allocations and 4.8 MB (the file read).
  Bytes identical to the list held are not verified again; currency is still
  judged.

### Tests

- Fuzz targets, the first in this repository: `FuzzVerifyCRL`,
  `FuzzVerifyCRLSigned` (what is behind the signature check), `FuzzVerifyKRL`,
  `FuzzVerifyKRLSigned`, `FuzzCheckCRLSignature`, `FuzzFilePathAndRedact`,
  `FuzzDecodeState`, `FuzzLoadConfig`. The CA keys are fixed so a recorded
  corpus keeps its meaning.

### Dependencies

- `govulncheck` reports one advisory in a module we require and do not call:
  GO-2026-5932, `golang.org/x/crypto/openpgp` ("unmaintained, unsafe by
  design"), with **no fixed version** (`Fixed in: N/A`). `golang.org/x/crypto`
  v0.58.0 is the latest. Nothing in this module imports `openpgp`.
