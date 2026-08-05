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
  protocol transition (may impersonate anyone to `HTTP/api.forge.local` —
  that's the S4U module's target)
- `sql_svc$` — a gMSA (retrievable by Builtin Administrators). This
  Samba build has no KDS root key, so `msDS-ManagedPassword` is never
  constructed: gmsa_dump can enumerate it but not dump it (Windows DCs
  can — the module says so plainly)
- `noauth` (DONT_REQUIRE_PREAUTH — AS-REP roastable; the lab flips all
  three Samba switches to make the KDC honor it: `[kdc] require-preauth
  = no` + the flag on noauth AND on krbtgt — plus PASSWD_NOTREQD)
- `WS01` — LAPS cleartext password + a BitLocker recovery key. Also holds
  the `HTTP/api.forge.local` SPN (web_svc's constrained-delegation
  target); fixture-created computers have no password, so `entrypoint.sh`
  sets one — without Kerberos keys the KDC can't issue tickets to it
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
5. **`ldap server require strong auth = no`** (entrypoint.sh smb.conf
   tuning) — Samba defaults it to yes and REJECTS unsigned NTLM SASL
   binds outright; stock Windows Server doesn't enforce LDAP signing,
   so a relayed (unsignable) NTLM bind is accepted there. The relay_smb
   e2e lives on this — it's tuned to match the Windows default, with
   the consequence documented: unsigned binds are weaker, fine for a
   lab. NOTE: the tuning only lands on cold provision — a persisted
   smb.conf on an old volume keeps the old value (`lab purge` first).

**Ports (1:1 on loopback — impacket ignores URL ports and speaks AD
ports only):** 135 → `127.0.0.1:135` (RPC endpoint mapper), 389 →
`127.0.0.1:389` (LDAP), 88 → `127.0.0.1:88` (Kerberos), 445 →
`127.0.0.1:445` (SMB), 53 → `127.0.0.1:15353` (Samba's internal DNS, for
`dns_recon`), plus 49152-49160 (dynamic RPC, pinned via
`rpc server dynamic port range` in `entrypoint.sh` — DRSUAPI/DCSync
resolves its endpoint through 135 and then lands in this range).

**Known noise:** `samba_dnsupdate` logs a DNS timeout on boot — cosmetic
(the DC's internal DNS registering its own A record races itself in a
container). LDAP works fine.
