# smb lab

**Purpose:** SMB/impacket-class protocol target (shares, signing checks,
auth).

**Build:** `debian:bookworm-slim` + `samba`.

**How it's built:**

1. Install samba; create `/shares/public` (guest-readable, contains
   `flag.txt`) and `/shares/labuser` (authenticated).
2. `labuser` created with both a Linux password AND an smbpasswd
   (`labuser:labpass`) — SMB auth needs both.
3. `smb.conf` (in this dir): `security = user`, `map to guest = Bad User`,
   **`server signing = disabled`** (so modules see a relay-able target),
   two shares.
4. Runs `smbd --foreground --debug-stdout --no-process-group`.
   Gotcha: the flag is `--debug-stdout`; `--log-stdout` is rejected and
   kills the container silently.

**Ports:** 139 → `127.0.0.1:10139`, 445 → `127.0.0.1:10445`.

**Notes:** covers protocol-level impacket (smbclient/rpcdump/samrdump
class). For service-control protocols (psexec/wmiexec) use the `windows`
lab — Samba doesn't emulate Windows SCM/WMI.
