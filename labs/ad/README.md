# ad lab

**Purpose:** a real Active Directory domain controller (FORGE.LOCAL) for
AD enumeration and attack modules.

**Build:** `debian:bookworm-slim` + `samba-ad-dc` + `samba-ad-provision`
+ `krb5-kdc`. Domain is provisioned by `entrypoint.sh` **on first boot**
(provision needs `security.NTACL` xattrs, blocked at build time on
overlayfs). State lives on the `ad-state` volume: second boots skip the
~60s provision and keep the same domain SID. **Fixture or entrypoint
edits only take effect after `lab purge ad`** — the volume keeps the
old state otherwise.

**Fixtures (deterministic):** accounts are created by `entrypoint.sh`;
everything else is a reviewable LDIF under `fixtures/` (see the header
comment there for what each fixture feeds). Highlights:

- `Administrator / P@ssw0rd123`, `analyst / Summer2024!` (in Helpdesk)
- `backup_svc / Backup2024!` — kerberoastable, unconstrained delegation,
  RBCD target for web_svc, password-in-description
- `web_svc / Web2024!` — kerberoastable, constrained delegation with
  protocol transition
- `sql_svc$` — a gMSA (retrievable by Builtin Administrators). This
  Samba build has no KDS root key, so `msDS-ManagedPassword` is never
  constructed: gmsa_dump can enumerate it but not dump it (Windows DCs
  can — the module says so plainly)
- `noauth` (DONT_REQUIRE_PREAUTH set for AS-REP roasting — but this KDC
  build ignores the flag, so it answers PREAUTH_REQUIRED like everyone
  else — plus PASSWD_NOTREQD)
- `WS01` — LAPS cleartext password + a BitLocker recovery key
- `WeakServicePSO` on Helpdesk, site subnet 10.10.10.0/24, ESC1-shaped
  template `VulnWeb`, a GPP cpassword in SYSVOL
- `[shared]` guest-readable share with a flag file

**The hard lessons baked into this build** (all in
[../../wiki/Labs.md](../../wiki/Labs.md)'s gotcha collection):

1. **`samba-ad-provision` is a separate package** — schema files for
   `samba-tool domain provision`; the build dies without it.
2. **Provision must happen at runtime, not build time** — NT ACLs need
   `security.NTACL` xattrs, blocked on docker's overlayfs during build.
3. **The container needs `cap_add: SYS_ADMIN`** — without it provision
   dies with `NT_STATUS_ACCESS_DENIED` (looks like a filesystem problem,
   is actually a capability problem).
4. **State lives on a volume, smb.conf included** — an earlier design
   split them (smb.conf in the image, sam.ldb on a volume) and second
   boots broke. Now the finished smb.conf is copied onto the volume and
   `/etc/samba/smb.conf` symlinks to it, so fast-path boots are
   consistent.

**Ports (1:1 on loopback — impacket ignores URL ports and speaks AD
ports only):** 135 → `127.0.0.1:135` (RPC endpoint mapper), 389 →
`127.0.0.1:389` (LDAP), 88 → `127.0.0.1:88` (Kerberos), 445 →
`127.0.0.1:445` (SMB), plus 49152-49160 (dynamic RPC, pinned via
`rpc server dynamic port range` in `entrypoint.sh` — DRSUAPI/DCSync
resolves its endpoint through 135 and then lands in this range).

**Known noise:** `samba_dnsupdate` logs a DNS timeout on boot — cosmetic
(the DC's internal DNS registering its own A record races itself in a
container). LDAP works fine.
