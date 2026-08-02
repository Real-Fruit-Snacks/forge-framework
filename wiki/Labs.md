# Labs

Local, throwaway docker targets so modules get tested against **real
services**, not mocks. Everything binds to `127.0.0.1` only. Requires
docker (daemon running, your user in the `docker` group).

```
forge > lab                 # list labs, state, target ports
forge > lab up web          # build + start (waits for real readiness)
forge > lab down web        # stop + remove
forge > lab clean           # janitor: tear down EVERY framework lab
```

Lifecycle guarantees: labs you start are torn down on `exit`; containers
have no restart policy (nothing survives reboot); `lab clean` removes even
orphans whose lab directory was deleted (compose-label surgery); and
`lab purge <name>` destroys a lab entirely (containers, volumes, images —
asks first) when you want the disk back.

**Disk policy:** containers and networks are freed aggressively; images
and volumes are kept deliberately — they're the expensive parts to remake
(minutes for images, ~20 min for the Windows install, whose disk is
~34GB). Reclaim with `lab purge <name>`; house-clean dangling layers from
rebuilds occasionally with `docker image prune`.

## Shipped labs

| Lab | Target | For | Access |
|---|---|---|---|
| `web` | `127.0.0.1:18080` | dir busting, HTTP brute, scanners | basic/form: `admin:hunter2` |
| `ssh` | `127.0.0.1:12222` | ssh_login, SSH work | `admin:admin`, `user:password`, `root:toor` |
| `smb` | `127.0.0.1:10139` + `10445` | SMB/impacket modules | guest share `public`; `labuser:labpass` |
| `ad` | `127.0.0.1:389` + `88` + `445` | AD enumeration (real DC, FORGE.LOCAL) | `Administrator:P@ssw0rd123`, `analyst:Summer2024!`, kerberoastable `backup_svc` |
| `windows` | `127.0.0.1:1445` (SMB), `13389` (RDP) | psexec/wmiexec-class Windows targets (KVM in docker) | `labadmin:Labpass2024!`; first boot installs (~20 min) |

Each lab has its own **build README** in its directory (`labs/<name>/README.md`)
— what it's for, exactly how it's built, fixtures, and the gotchas it
took to get there. That's the replication record for future-you and
anyone else.

The web lab is deterministic by design (route table at the top of
`labs/web/app.py`): hidden 200s, a 403, a 401 realm, a login form, nested
paths for recursion (`/admin/panel`, `/backup/db`). Wordlists in
`labs/web/wordlists/` contain known hits AND known decoys — a buster
tested only against hits proves nothing about its filtering.

## Adding a lab

1. `labs/<name>/Dockerfile` + `compose.yml`. `lab` picks it up.
2. Ports in the house format (the framework parses them):
   `- "127.0.0.1:<hostport>:<containerport>"`.
3. Add a `READY` file if TCP-connect isn't proof of readiness (it rarely
   is — docker-proxy accepts before the app serves):
   `http <port> <path>` · `banner <port>` · `tcp <port>` — `lab up` polls
   these before returning.
4. Deterministic everything: fixed creds, fixed content, no randomness.

Good candidates: `ftp` (vsftpd, anonymous), `mysql`/`postgres`, `mssql`,
`dvwa`/`juice-shop` (image-only, heavier).

## The Windows question

**Solved**: the `windows` lab runs a real Windows Server in a KVM VM
inside docker ([dockur/windows](https://github.com/dockur/windows)) —
psexec/wmiexec/ADMIN$/RDP all work. First boot installs the OS (~20 min,
watch at `http://127.0.0.1:8006`); the disk persists in a volume so later
boots are fast. See `labs/windows/README.md`.

Samba (the `smb` lab) still covers protocol-level impacket work
(smbclient/rpcdump/samrdump class) with far less weight, and the `ad` lab
covers domain-level LDAP/Kerberos. Use the windows lab when you need
service control or a genuine Windows auth stack; a local eval VM
(`virt-install`) or a cloud trial remain the answer for heavier,
GUI-driven work.

## Gotcha collection (learned the hard way)

- **`isSigningRequired()` lies on SMB 3.1.1** — impacket forces signing
  client-side for the pre-auth hash, so the method always returns True
  there. `smb_enum` negotiates SMB 2.1 explicitly to read the *server's*
  policy. Remember this when writing other impacket modules.
- **Debian smbd logging flag** is `--debug-stdout`, not `--log-stdout` —
  the wrong flag kills the container silently at start.
- **docker-proxy eats your readiness check** — see `READY` files above.
- **Samba AD DC needs CAP_SYS_ADMIN** — NT ACLs are `security.NTACL`
  xattrs; docker's default capabilities drop SYS_ADMIN and provision dies
  with `NT_STATUS_ACCESS_DENIED` (not an xattr/filesystem problem, though
  it looks like one). The `ad` lab grants it in compose.yml.
- **Samba provision belongs at runtime, not build time** — overlayfs
  rootfs blocks the ACL work regardless; the `ad` lab provisions in its
  entrypoint on a host-backed volume. `--use-ntvfs` no longer exists in
  modern samba, don't reach for it.
- **impacket's LDAPConnection doesn't parse URL ports** — `ldap://host`
  is 389, always. AD labs bind 1:1 on loopback for this reason.
- **Samba's Heimdal KDC requires the authenticator cksum field** — RFC
  calls it optional and impacket omits it, so `getKerberosTGS` fails with
  `KRB_AP_ERR_INAPP_CKSUM` on Samba ("No authenticator in request"). The
  kerberoast module vendors its own TGS-REQ with the checksum (HMAC over
  the req-body, usage 6). Also: don't set the `renew` kdc-option like
  impacket does — Heimdal takes it literally and dies with
  `KDC_ERR_NEVER_VALID` while Windows just clamps.
- **Samba's KDC doesn't honor UF_DONT_REQUIRE_PREAUTH** (this build) —
  every account gets PREAUTH_REQUIRED, so AS-REP roasting can't be tested
  against the bundled lab. The asreproast module works against Windows
  KDCs; against Samba it must (and does) skip cleanly.
- **Provisioning needs `samba-ad-provision`** — the schema files for
  `samba-tool domain provision` live in a separate package from
  `samba-ad-dc`; without it the build dies with "File not found".