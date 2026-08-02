# ad lab

**Purpose:** a real Active Directory domain controller (FORGE.LOCAL) for
AD enumeration and attack modules.

**Build:** `debian:bookworm-slim` + `samba-ad-dc` + `samba-ad-provision`
+ `krb5-kdc`. Domain is provisioned by `entrypoint.sh` **at runtime,
fresh on every boot** (stateless — no volume).

**Fixtures (deterministic):**

- `Administrator / P@ssw0rd123`
- `analyst / Summer2024!` (normal user)
- `backup_svc / Backup2024!` with SPN `HTTP/web.forge.local`
  (kerberoastable — works with the kerberoast module), UAC
  TRUSTED_FOR_DELEGATION (unconstrained delegation), and an RBCD rule
  (`msDS-AllowedToActOnBehalfOfOtherIdentity`) letting `web_svc`
  impersonate against it
- `web_svc / Web2024!` with SPN `HTTP/intranet.forge.local` (also
  kerberoastable), constrained delegation to `HTTP/api.forge.local` with
  protocol transition (TRUSTED_TO_AUTH_FOR_DELEGATION)
- `noauth` (DONT_REQUIRE_PREAUTH set for AS-REP roasting — but see the
  caveat below: this KDC build ignores the flag, so it answers
  PREAUTH_REQUIRED like everyone else)
- `[shared]` guest-readable share with a flag file

**The four hard lessons baked into this build** (all in
[../../wiki/Labs.md](../../wiki/Labs.md)'s gotcha collection):

1. **`samba-ad-provision` is a separate package** — schema files for
   `samba-tool domain provision`; the build dies without it.
2. **Provision must happen at runtime, not build time** — NT ACLs need
   `security.NTACL` xattrs, blocked on docker's overlayfs during build.
3. **The container needs `cap_add: SYS_ADMIN`** — without it provision
   dies with `NT_STATUS_ACCESS_DENIED` (looks like a filesystem problem,
   is actually a capability problem).
4. **No persistence volume** — smb.conf lives in the container layer,
   sam.ldb would live on a volume; split state breaks the second boot.
   Stateless = a clean domain every time (provisioning takes ~60s).

**Ports (1:1 on loopback — impacket ignores URL ports and speaks AD
ports only):** 135 → `127.0.0.1:135` (RPC endpoint mapper), 389 →
`127.0.0.1:389` (LDAP), 88 → `127.0.0.1:88` (Kerberos), 445 →
`127.0.0.1:445` (SMB), plus 49152-49160 (dynamic RPC, pinned via
`rpc server dynamic port range` in `entrypoint.sh` — DRSUAPI/DCSync
resolves its endpoint through 135 and then lands in this range).

**Known noise:** `samba_dnsupdate` logs a DNS timeout on boot — cosmetic
(the DC's internal DNS registering its own A record races itself in a
container). LDAP works fine.
