# Installing authn-revokd

This page installs `authn-revokd` as a systemd service on Linux. The agent
fetches signed SSH KRLs and X.509 CRLs, keeps the lists that verify, and writes
them for `sshd` and TLS servers to read. Upgrading from `revokd`? See
[Upgrading to v0.6.0](#upgrading-to-v060).

Every step on this page was run on Ubuntu 24.04 (arm64, systemd 255,
OpenSSH 9.6p1): the units, the account, the configuration, an `sshd` reading
the KRL, the fail-closed path, the timer, the path unit, the drop-ins and the
uninstall.

> **Versioned services through go-pkgx are coming, not available.** go-pkgx
> will offer `pkgm service`, which installs and switches versions of a
> service like this one. It does not exist yet. Until it does, the steps on
> this page are the way to install authn-revokd.

## Layout

| Path | What | Owner, mode |
| --- | --- | --- |
| `/usr/local/bin/authn-revokd` | the binary | root, 0755 |
| `/usr/lib/sysusers.d/authn-revokd.conf` | the `authn-revokd` system account | root, 0644 |
| `/etc/systemd/system/authn-revokd.service` | the daemon | root, 0644 |
| `/etc/authn-revokd/revokd.hcl` | the configuration (the default `-config`) | root, 0644 |
| `/etc/authn-revokd/ca/*.pub`, `*.pem` | the CA keys the lists must be signed by | root, 0644 |
| `/var/lib/authn-revokd/` | `StateDirectory=`, the only writable place | authn-revokd, 0755 |
| `/var/lib/authn-revokd/state/` | `state_dir`: the verified copies (rollback protection) | authn-revokd, 0700 |
| `/var/lib/authn-revokd/sshd.krl` | an output: what `sshd` reads | authn-revokd, 0644 |

**Write the outputs to `/var/lib/authn-revokd`, and point the servers there.**
Do not write them to `/etc/ssh` or `/etc/nginx`. An output is written beside its
final name and renamed over it, so its **directory** must be writable. Making
`/etc/ssh` writable would let the `authn-revokd` account replace
`sshd_config`. The unit allows writes to its state directory and nowhere else
(`ProtectSystem=strict`). If an output must live elsewhere, see
[An output outside /var/lib/authn-revokd](#an-output-outside-varlibauthn-revokd).

The outputs are 0644 in a 0755 directory. `sshd` (root) can read them, and so
can a TLS server that runs as its own user. The state stays 0700.

## 1. Download and verify

Each release carries `authn-revokd-<os>-<arch>` for linux, darwin and windows
on amd64 and arm64, a `SHA256SUMS` manifest, and a build provenance attestation
per binary.

```sh
v=v0.6.0
arch=$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')
gh release download "$v" --repo go-authn/revocation \
  --pattern "authn-revokd-linux-$arch" --pattern SHA256SUMS

sha256sum -c SHA256SUMS --ignore-missing
gh attestation verify "authn-revokd-linux-$arch" --repo go-authn/revocation
```

`sha256sum` proves the file matches the manifest. `gh attestation verify` proves
that this repository's release workflow built the file at a tag. Do not install a
binary that fails either check.

Or build it from source with Go:

```sh
go install github.com/go-authn/revocation/cmd/authn-revokd@v0.6.0
```

## 2. Install the binary, the account and the unit

Download the unit and the sysusers snippet from the same tag, from
[`packaging/`](../packaging):

```sh
base=https://raw.githubusercontent.com/go-authn/revocation/$v/packaging
curl -fsSLO "$base/sysusers.d/authn-revokd.conf"
curl -fsSLO "$base/systemd/authn-revokd.service"
```

Then install them:

```sh
sudo install -m 0755 "authn-revokd-linux-$arch" /usr/local/bin/authn-revokd
authn-revokd -version                     # authn-revokd v0.6.0

sudo install -m 0644 authn-revokd.conf /usr/lib/sysusers.d/authn-revokd.conf
sudo systemd-sysusers /usr/lib/sysusers.d/authn-revokd.conf
sudo install -m 0644 authn-revokd.service /etc/systemd/system/
sudo systemctl daemon-reload
```

The account is static, not `DynamicUser=`. authn-revokd refuses a state
directory owned by anyone other than its own uid or root. The state must
survive restarts and upgrades. With `DynamicUser=`, the files would also sit
under `/var/lib/private`, which is 0700 root, so a TLS server running as its
own user could not read them.

## 3. Configure

`/etc/authn-revokd/revokd.hcl`. The required keys are `state_dir`, at least
one `source` (each with a `url` and either `ssh_ca` or `x509_ca`), and an
`output` for each file a server reads (each with a `path` and its `sources`).
Every other key is optional.

```hcl
state_dir = "/var/lib/authn-revokd/state"   # required: absolute, 0700, created if missing
refresh   = "1m"                            # optional, default 1m

# A go-authn/bridge serves its KRL at /ssh/krl and the signature at /ssh/krl.sig.
source "univ-a-ssh" {
  url    = "https://idp.univ-a.fr/ssh/krl"           # required
  ssh_ca = "/etc/authn-revokd/ca/univ-a-ssh.pub"     # required: ssh_ca or x509_ca
}

source "univ-a-x509" {
  url     = "https://idp.univ-a.fr/x509/crl"
  x509_ca = "/etc/authn-revokd/ca/univ-a-x509.pem"
}

output "sshd" {
  path    = "/var/lib/authn-revokd/sshd.krl"         # required: absolute
  sources = ["univ-a-ssh"]                           # required: KRL sources merge into one file
}

output "tls" {
  path    = "/var/lib/authn-revokd/univ-a.crl"
  sources = ["univ-a-x509"]                          # a CRL output takes one source
  format  = "pem"                                    # der (default) or pem
}
```

The [README](../README.md#authn-revokd) documents every key: `max_age`,
`revoke_keys`, `on_change` and `listen` (the mirror).

```sh
sudo install -d -m 0755 /etc/authn-revokd /etc/authn-revokd/ca
sudo install -m 0644 univ-a-ssh.pub /etc/authn-revokd/ca/
sudo install -m 0644 revokd.hcl /etc/authn-revokd/revokd.hcl
```

## 4. Enable, and check, BEFORE wiring sshd

⛔ **sshd refuses every certificate when `RevokedKeys` names a file that does not
exist.** That was measured on the test host before the first sync: `Permission
denied (publickey)`. So start authn-revokd first, and wait until the file is
there:

```sh
sudo systemctl enable --now authn-revokd
systemctl status authn-revokd
journalctl -u authn-revokd -n 20     # "<source>: version N, issued ..., expires ..."
                                     # "output sshd: wrote /var/lib/authn-revokd/sshd.krl"
ssh-keygen -Q -l -f /var/lib/authn-revokd/sshd.krl
```

`ssh-keygen -Q -l` prints the file's comment and what it revokes. Its comment
is `authn-revokd sshd` while every source is current. It ends in `FAIL CLOSED,
every certificate refused from <source>` while a source is not.

With `listen` set, `GET /healthz` returns 200, or 503 and the reason while a
source has no current list or an output fails.

`sudo systemctl reload authn-revokd` sends SIGHUP, and the agent syncs every
source at once instead of waiting for the next `refresh`. For example, use it
after a revocation that must reach sshd now. It does **not** re-read the
configuration: after changing `revokd.hcl`, run `systemctl restart authn-revokd`.

## 5. Wire sshd

In `/etc/ssh/sshd_config`:

```
TrustedUserCAKeys /etc/ssh/ca/univ-a-ssh.pub
RevokedKeys /var/lib/authn-revokd/sshd.krl
```

```sh
sudo sshd -t && sudo systemctl reload ssh     # "sshd" on Fedora/RHEL
```

sshd reads `RevokedKeys` at every authentication, so it needs no reload when
authn-revokd rewrites the file. Only this change to `sshd_config` needs one.

## 6. Wire a TLS server's CRL

Point the server at the output, for example nginx:

```nginx
ssl_client_certificate /etc/authn-revokd/ca/univ-a-x509.pem;
ssl_verify_client      on;
ssl_crl                /var/lib/authn-revokd/univ-a.crl;   # format = "pem"
```

A TLS server reads its CRL when it loads its configuration, so it must be
reloaded when the CRL changes. ⛔ **`on_change = ["systemctl", "reload", "nginx"]`
does not work under this unit.** On the test host, the command ran as the
`authn-revokd` account and systemd refused it with "Interactive authentication
required". Let systemd watch the file instead, as root:

```ini
# /etc/systemd/system/authn-revokd-nginx.path
[Unit]
Description=Reload nginx when authn-revokd rewrites its CRL

[Path]
PathChanged=/var/lib/authn-revokd/univ-a.crl

[Install]
WantedBy=paths.target
```

```ini
# /etc/systemd/system/authn-revokd-nginx.service
[Unit]
Description=Reload nginx for a new CRL

[Service]
Type=oneshot
ExecStart=/usr/bin/systemctl reload nginx
```

```sh
sudo systemctl daemon-reload && sudo systemctl enable --now authn-revokd-nginx.path
```

The path unit fires on the rename that authn-revokd uses to replace the file.
This was measured with `PathChanged=` on an output.

An expired CRL fails closed by itself: OpenSSL refuses it with "CRL has
expired". The server needs nothing more for that.

## Run as a timer instead (optional)

`authn-revokd -once` syncs once and exits 1 when a list is not current. The
outputs are written either way, and failed closed for sshd.
[`authn-revokd-once.service` and `.timer`](../packaging/systemd) run it every
minute. They are for a host that wants no long-running process.

The daemon remains the better choice. It fails a lapsed list closed as soon as
the next `refresh` notices, where the timer waits for its next tick. Only the
daemon serves as a mirror, because `listen` is ignored with `-once`. **Never
enable both.** The units conflict, so starting one stops the other.

```sh
sudo install -m 0644 authn-revokd-once.service authn-revokd-once.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl disable --now authn-revokd
sudo systemctl enable --now authn-revokd-once.timer
systemctl list-timers authn-revokd-once.timer
```

When a source stopped answering on the test host, the next run after the list
expired wrote the fail-closed KRL and exited 1. The unit showed `failed`. The
timer kept firing, and sshd refused the CA's certificates.

## What the unit allows

`systemd-analyze security authn-revokd` rates both units **1.1 OK** on
systemd 255. They run as the unprivileged `authn-revokd` account and have no
capability at all (`CapabilityBoundingSet=` is empty). The whole file system
is read-only except `/var/lib/authn-revokd`. The units also set
`PrivateUsers=`, `PrivateDevices=`, `PrivateTmp=` and `PrivateIPC=`, protect
the kernel, clock, hostname and control groups, and allow only
`AF_INET AF_INET6 AF_UNIX` sockets and `@system-service` system calls (minus
`@privileged @resources`). They also set `MemoryDenyWriteExecute=`,
`LockPersonality=`, `RestrictNamespaces=`, `RestrictRealtime=`,
`RestrictSUIDSGID=` and `UMask=0077`. The outputs are still 0644: they are
chmod-ed explicitly.

Two drop-ins widen this for a reason. Each is one file, created with
`sudo systemctl edit authn-revokd`:

### An output outside /var/lib/authn-revokd

Give it a directory of its own, owned by `authn-revokd`, and add exactly
that directory:

```sh
sudo install -d -m 0755 -o authn-revokd -g authn-revokd /etc/nginx/authn-revokd
```

```ini
[Service]
ReadWritePaths=/etc/nginx/authn-revokd
```

Without the drop-in the write fails, and the journal says so: `output tls: open
/etc/nginx/authn-revokd/.univ-a.crl.NNN: read-only file system`. Never add the
directory that holds other configuration (`/etc/ssh`, `/etc/nginx`).

### A mirror on a port below 1024

```ini
[Service]
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
PrivateUsers=no
```

`PrivateUsers=no` is required. Inside a private user namespace the capability
does not reach the host's network, and the bind fails with `listen tcp
127.0.0.1:880: bind: permission denied`. This was measured. The score becomes
1.4. A port above 1024 needs no drop-in.

## The daemon must keep running

⛔ sshd ignores the expiry that authn-revokd puts in the KRL. The file is
failed closed **by authn-revokd** when a list lapses. While authn-revokd is
stopped, sshd keeps reading the last file it wrote, and a revocation issued in
the meantime never arrives. The unit therefore sets `Restart=always`. Monitor
`systemctl is-active authn-revokd`, or `/healthz` when `listen` is set.

## Upgrade

```sh
# download and verify the new version as in step 1, then:
sudo install -m 0755 authn-revokd-linux-$arch /usr/local/bin/authn-revokd.new
sudo mv /usr/local/bin/authn-revokd /usr/local/bin/authn-revokd.prev
sudo mv /usr/local/bin/authn-revokd.new /usr/local/bin/authn-revokd
sudo systemctl restart authn-revokd
authn-revokd -version && journalctl -u authn-revokd -n 5
```

Read the release notes for changes to the unit or the configuration. Compare
the unit with the one in `packaging/` at the new tag. The state carries over:
the verified copies keep ordering the next list, so a restart cannot let an
older list in.

## Roll back

```sh
sudo mv /usr/local/bin/authn-revokd.prev /usr/local/bin/authn-revokd
sudo systemctl restart authn-revokd
```

A rollback does not reset the state. The older binary still refuses any list
older than the one held, which is the point of the state.

## Uninstall

Remove `RevokedKeys` (and `ssl_crl`) from the servers' configuration **first**,
and reload them. sshd refuses every certificate once the file is gone.

```sh
sudo systemctl disable --now authn-revokd authn-revokd-once.timer 2>/dev/null
sudo rm -f /etc/systemd/system/authn-revokd.service \
           /etc/systemd/system/authn-revokd-once.service \
           /etc/systemd/system/authn-revokd-once.timer
sudo rm -rf /etc/systemd/system/authn-revokd.service.d
sudo systemctl daemon-reload
sudo rm -f /usr/local/bin/authn-revokd /usr/local/bin/authn-revokd.prev
sudo rm -rf /var/lib/authn-revokd /etc/authn-revokd     # the state, the outputs, the configuration
sudo rm -f /usr/lib/sysusers.d/authn-revokd.conf
sudo userdel authn-revokd
```

## Upgrading to v0.6.0

The command was renamed: **`revokd` is now `authn-revokd`**. `revokd` is a
generic name that a host may already give to something else. The module path
does not change.

| | before v0.6.0 | from v0.6.0 |
| --- | --- | --- |
| command | `revokd` | `authn-revokd` |
| `go install` | `github.com/go-authn/revocation/cmd/revokd@v0.5.1` | `github.com/go-authn/revocation/cmd/authn-revokd@v0.6.0` |
| release assets | `revokd-<os>-<arch>` | `authn-revokd-<os>-<arch>` |
| default `-config` | `/etc/revokd.hcl` | `/etc/authn-revokd/revokd.hcl` |
| log prefix, `-version` | `revokd: …`, `revokd vX` | `authn-revokd: …`, `authn-revokd vX` |
| KRL comment (`ssh-keygen -Q -l`) | `revokd <output>` | `authn-revokd <output>` |
| SIGHUP | killed the process (Go's default), and systemd saw a clean exit | syncs now; `systemctl reload` sends it |

- **The default configuration moved** into a directory of its own, where the
  CA keys it names can sit beside it. Nothing reads `/etc/revokd.hcl` any
  more. When `-config` is not given, `/etc/authn-revokd/revokd.hcl` is
  missing and `/etc/revokd.hcl` exists, authn-revokd exits 2 with an error
  that names both paths. Move the file, or pass `-config /etc/revokd.hcl`.
- **The state format is unchanged.** Point the new `state_dir` at the old
  directory, or move the directory, and the held lists keep ordering the next
  ones. Moving it to `/var/lib/authn-revokd/state` goes like this:

  ```sh
  sudo systemctl stop revokd                 # whatever ran it before
  sudo systemd-sysusers /usr/lib/sysusers.d/authn-revokd.conf
  sudo install -d -m 0755 -o authn-revokd -g authn-revokd /var/lib/authn-revokd
  sudo mv /var/lib/revokd /var/lib/authn-revokd/state
  sudo chown -R authn-revokd:authn-revokd /var/lib/authn-revokd/state
  sudo chmod 0700 /var/lib/authn-revokd/state
  ```

- **The outputs.** If they were written to `/etc/ssh/revoked.krl` or a similar
  path, move them to `/var/lib/authn-revokd/` and change `RevokedKeys` (and
  `ssl_crl`) to match. Start authn-revokd first, so the file exists before sshd
  is reloaded. Otherwise, add the directory with a
  [drop-in](#an-output-outside-varlibauthn-revokd).
- **Scripts and monitoring** that match `revokd:` in the logs, call `revokd`,
  or download `revokd-linux-amd64` need the new name.
