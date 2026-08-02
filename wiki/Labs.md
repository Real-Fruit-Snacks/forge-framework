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
orphans whose lab directory was deleted (compose-label surgery).

## Shipped labs

| Lab | Target | For | Access |
|---|---|---|---|
| `web` | `127.0.0.1:18080` | dir busting, HTTP brute, scanners | basic/form: `admin:hunter2` |
| `ssh` | `127.0.0.1:12222` | ssh_login, SSH work | `admin:admin`, `user:password`, `root:toor` |
| `smb` | `127.0.0.1:10139` + `10445` | SMB/impacket modules | guest share `public`; `labuser:labpass` |

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

Samba covers protocol-level impacket work (smbclient/rpcdump/samrdump
class). It does NOT emulate Windows service control, so psexec/wmiexec
modules need a real Windows box. Options: a local eval VM
(`virt-install` — this machine has KVM), or a cloud trial. Either way,
just `set RHOSTS <ip>` — modules don't care where the target lives.
Automating Windows installs into the framework is deliberately out of
scope: containers are seconds, Windows ISOs are yak-shaving.

## Gotcha collection (learned the hard way)

- **`isSigningRequired()` lies on SMB 3.1.1** — impacket forces signing
  client-side for the pre-auth hash, so the method always returns True
  there. `smb_enum` negotiates SMB 2.1 explicitly to read the *server's*
  policy. Remember this when writing other impacket modules.
- **Debian smbd logging flag** is `--debug-stdout`, not `--log-stdout` —
  the wrong flag kills the container silently at start.
- **docker-proxy eats your readiness check** — see `READY` files above.
