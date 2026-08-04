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
| `ad` | `127.0.0.1:389` + `88` + `445` + `135` + `15353` (DNS) | AD enumeration + DCSync (real DC, FORGE.LOCAL) | `Administrator:P@ssw0rd123`, `analyst:Summer2024!`, kerberoastable `backup_svc` + `web_svc`, delegation fixtures (unconstrained/constrained/RBCD) |
| `windows` | `127.0.0.1:1445` (SMB), `13389` (RDP), `15985` (WinRM) | psexec/wmiexec-class Windows targets (KVM in docker) | `labadmin:Labpass2024!`; first boot installs (~20 min) |
| `workstation` | `127.0.0.1:2445` (SMB), `23389` (RDP) | Windows 11 client — the foothold box | `labadmin:Labpass2024!`; first boot installs (~20 min) |
| `domain` | DC: `127.0.0.1:389/88/445`; member: `3445` (SMB), `33389` (RDP); CA: `4445` (SMB/cert pipe) | small AD domain: Samba DC + Win11 member that auto-joins FORGE.LOCAL + a Windows Server **Enterprise CA** (esc1) | DC creds as `ad`; member `labadmin:Labpass2024!` |
| `mssql` | `127.0.0.1:11433` | TDS auth (mssql_login) | `sa:For9e_SQL!2024`; image is ~1.5 GB — purge when done |
| `snmp` | `127.0.0.1:10161` (udp) | community spray (snmp_login) | `private-lab`; everything else gets silence, like a real agent |

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

Good candidates: `ftp` (vsftpd, anonymous), `mysql`/`postgres`,
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

**Domain topologies**: the `domain` lab composes the `ad` lab's DC with a
Windows 11 member on a private network and joins it automatically during
setup (`labs/domain/oem/`). That's the "spin up a small domain" answer —
one `lab up domain`. The `workstation` lab is the same dockur/windows
recipe as a standalone Win11 client, for when you don't need a DC.
Note the DC in `domain` claims the same loopback ports as the `ad` lab —
never run both.

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
- **AS-REP roasting on Samba needs THREE switches, not one** — Heimdal's
  `require_preauth_p()` is `config || client || server`, so all three
  must be off: `[kdc] require-preauth = no` in `/etc/samba/krb5.conf`
  (the file the KDC actually reads — NOT the generated
  `private/krb5.conf`), `DONT_REQ_PREAUTH` on the roast target, and the
  same flag on **krbtgt** (Samba builds krbtgt's hdb entry with
  require_preauth=1 from its stock UAC, which alone forces preauth for
  every AS-REQ). The lab's fixture + entrypoint set all three; a Windows
  DC needs only the account flag. Side effect: krbtgt now shows up in
  DONT_REQ_PREAUTH scans — its AS-REP fails benignly (AES-only keys vs
  the rc4-only probe).
- **Provisioning needs `samba-ad-provision`** — the schema files for
  `samba-tool domain provision` live in a separate package from
  `samba-ad-dc`; without it the build dies with "File not found".
- **Samba verifies the DRS client's prefix map with schema-info
  semantics** — impacket's `MakeAttid` emits table-relative attids plus a
  1-entry `PrefixTableDest`; Samba requires a non-empty map to carry a
  schema-info trailer, so it rejects the request with
  `WERR_INVALID_PARAMETER` (the `0x57` trailing the reply) and returns
  zero objects *with `ErrorCode: 0` in the body*. The fix: standard-index
  attids (0x0009 = `1.2.840.113556.1.4`) and an EMPTY prefix table, which
  takes Samba's documented "Windows RODC" fallback — and is what real
  Windows RODCs send, so it works on Windows too. impacket's
  trailing-4-bytes error heuristic in `DCERPC_v5.request()` misfires on
  these replies (`DRSR SessionError: code: 0x0` with a perfectly valid
  parsed packet); the dcsync module uses `checkError=False` and reads
  `extended_ret` itself.
- **DRSUAPI needs 135 + dynamic RPC ports** — it's ncacn_ip_tcp only:
  endpoint mapper on 135, then a dynamic port. The `ad` lab pins Samba's
  range (`rpc server dynamic port range = 49152-49160` in smb.conf's
  [global]) and publishes it 1:1; without it DCSync hangs at endpoint
  resolution.
- **Never request `msDS-AllowedToActOnBehalfOfOtherIdentity` values over
  LDAP** — it's a raw security descriptor and impacket's LDAP codec dies
  decoding it (`PyAsn1UnicodeDecodeError`), killing the whole search.
  Query by filter-presence (`(attr=*)`) and don't ask for the attribute —
  the delegation module does exactly that.
- **LDIF modify blocks need blank-line separation** — two `changetype:
  modify` blocks back to back parse as one entry and `ldbmodify` dies
  with "attribute 'dn' was not found in the schema". Under `set -e` that
  silently kills a whole lab provision.
- **Samba schema extensions** need `dsdb:schema update allowed` as an
  ldb `--option` (the exact parameter name — "dsdb:schema:allow updates"
  from old wikis is wrong), `changetype: add` in a separate file from
  modifies (`ldbadd` rejects modify blocks), and correct
  attributeSyntax/oMSyntax pairs (2.5.5.16 = oMSyntax 65). PSOs need
  `msDS-PasswordReversibleEncryptionEnabled` and
  `msDS-PasswordHistoryLength` as mandatory attributes.
- **PSOs are admin-only on Samba** — Windows lets any authenticated
  user read Password Settings Objects; Samba's CN=System ACLs don't.
  Fine-grained policy checks need a privileged account against the lab.
- **Windows guests mint a Public NLA profile on network change** — and
  the firewall silently stops answering SMB/RDP inbound. Fix at TWO
  points: specialize-time in the oem script AND a boot scheduled task
  that waits for a profile to exist (a task that fires before the
  network does nothing; registering it needs a proper SYSTEM principal —
  bare `-User SYSTEM` fails silently). Pinning the DC's container MAC
  reduces how often it triggers.
- **Golden-ticket forging has four Samba-specific traps** (all verified
  against the lab): modern Samba holds NO rc4 krbtgt key (forge AES256
  from dcsync's kerberos-key loot, not the NT hash); the ticket's kvno
  must match krbtgt's (Samba provisions it at 1, Windows usually 2+);
  PAC ClientId and ticket authtime must agree to the second
  ("PAC timestamp mismatch"); PAC_REQUESTOR takes the raw Structure SID,
  not the NDR RPC_SID (NDR-encoded input decodes as S-5-0 garbage →
  "SID mismatch between PAC and looked up client"); and Samba's NDR
  puller wants LOGON_INFO's declared ObjectBufferLength 8-padded while
  Windows doesn't care.
- **S4U2self's PA-FOR-USER checksum is not a plain HMAC** — Heimdal's
  `mssfu.c` verifies RFC 4757 KERB_CHECKSUM_HMAC_MD5 with usage 17
  (Ksign = HMAC(K, "signaturekey\0"), then MD5(LE32(17) || blob), then
  HMAC(Ksign, that)) and answers KRB_AP_ERR_BAD_INTEGRITY for the plain
  form. Three more S4U traps: the delegation target SPN must exist in
  the KDB (KDC_ERR_S_PRINCIPAL_UNKNOWN) and the target account must hold
  keys — a fixture-created computer has no password, so no enctypes
  (KDC_ERR_ETYPE_NOSUPP); the additional-tickets field must be in the
  req-body BEFORE the authenticator cksum is computed; and the S4U2self
  ticket must be re-encoded through impacket's types.Ticket — a component
  lifted from a decoded TGS-REP keeps its outer tag and produces garbage
  DER (the KDC drops the connection mid-request).
- **SCMR command exec only works as the smbexec echo-chain** (verified
  against the windows lab): `cmd /c bat > localfile` constructions get
  the service tree reaped before the output flushes (instant 1053, empty
  file). The chain that works: service cmd echoes the payload into a
  .bat with ^-escaped redirects, runs the bat, deletes it; output goes
  to a UNC path on the target's own ADMIN$ (the SMB redirector commits
  the bytes even when the SCM kills the tree). ERROR_SERVICE_REQUEST_
  TIMEOUT (1053) on StartServiceW is the NORMAL path — cmd.exe never
  talks to the dispatcher. Also: cmd's `>` writes UTF-16-LE for builtins
  but console apps write ANSI (sniff BOM/NUL-pattern, don't guess), and
  impacket's putFile callback must return empty bytes at EOF or the
  upload loop never ends.
- **Ticket loot is CCACHE, never raw KDC-REP bytes** — a consumed TGT
  needs its session key, which bare AS-REP/TGS-REP bytes don't carry.
  ccache stores both (and every external tool reads it via KRB5CCNAME).
  impacket's `Credential.toTGT()` rebuilds a synthetic AS-REP from a
  ccache entry, so one vendored TGS-REQ shape serves real and
  ccache-sourced TGTs alike; ccache Principal components are
  CountedOctetStrings — read their `['data']`, don't decode them.- **The endpoint mapper is not one thing** (ad_probe's three tiers):
  classic Windows answers `ept_lookup` with the full dump; Samba's
  epmapper implements `ept_map` only (lookup returns
  `ept_s_not_registered`, and binds get flaky when hammered); hardened
  Server 2022 rejects impacket's EPM bind outright
  (`reason_not_specified`, auth and transport irrelevant) — the honest
  fallback is binding each interface's UUID on its canonical pipe
  (`\spoolss`, `\svcctl`, ...), where pipe-missing means absent and
  ACCESS_DENIED means present-but-gated. Two impacket shape traps:
  `SMBTransport(filename=)` wants `\svcctl`, NOT `\pipe\svcctl` (it
  prepends), and a faulted EPM lookup poisons the association — retry
  maps on a fresh dce.
- **Remote TSCH is the tightest admin channel on modern Windows** — on
  the lab guests, atsvc binds but `hSchRpcRegisterTask` answers
  `rpc_s_access_denied` to EVERYONE (workgroup 2022 filters local
  accounts via UAC; the domain member denies domain admins too, with
  Domain Admins verified nested in local Administrators). Local
  `schtasks` as SYSTEM works fine — it's the remote interface ACL, not
  the service. at_exec reports the denial cleanly; happy path needs a
  field/domain target. Also: `schtasks /s 127.0.0.1 /u user` is refused
  by design ("credentials are not allowed on the local machine").
- **Win11 Defender kills the psexec pattern, and self-heals** — service
  -> cmd.exe chains are quarantined as `VirTool:Win32/MSFPsExecCommand`
  (Server 2022's Defender ignores the same chain). First symptom is
  exec "succeeding" with empty output; the evidence is in
  `Microsoft-Windows-Windows Defender/Operational.evtx` (readable over
  ADMIN$ with FILE_SHARE_READ|WRITE — it's locked otherwise).
  `Set-MpPreference -DisableRealtimeMonitoring` gets reverted within
  hours; the durable off-switch is the GPO key
  `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware=1`
  (now in the domain member's oem).
- **A stale domain join reports ACCOUNT_LOCKED_OUT** — the member's disk
  predated the current dc-state (its machine account didn't exist), so
  every domain login returned LOCKED_OUT while the DC swore the account
  was fine. Trust problems wear misleading error codes; check the
  computer account in AD before believing them.
- **RBCD is doubly unsupported on Samba 4.17** —
  `msDS-AllowedToActOnBehalfOfOtherIdentity` is system-only (LDAP
  writes refused with constraintViolation; fixtures must plant it via
  ldbmodify), and the KDC's hdb doesn't implement the RBCD check at all
  (S4U2proxy with the PA-PAC-OPTIONS RBCD bit falls through to classic
  constrained delegation and denies). The s4u module sends the bit
  because Windows honors it — no classic-path regression. rbcd set/clear
  reports the denial plainly; rbcd get still parses fixture SDs fine.
- **Samba's SAMR makes machine accounts in CN=Users with the USER
  class** — not CN=Computers/computer-class like Windows. Consequences:
  dNSHostName violates the objectClass (skip it), DNs must be found by
  sAMAccountName search not assumed. Also: creating machine accounts
  needs admin on Samba (no ms-DS-MachineAccountQuota=10 default like
  Windows) — analyst gets "doesn't have the right", Administrator works.
- **Server 2022's netlogon is the opposite of Win11's vs Samba** — the
  Win11 RC4 relax (RequireStrongKey/SignOrSeal/Seal/Sign = 0) breaks
  2022's secure channel AT BIRTH; every domain logon then fails with
  "trust relationship failed". 2022 wants all four = 1 plus a
  post-join `Reset-ComputerMachinePassword`. The domain lab's member
  keeps the relax, the CA gets the strong set — same DC, opposite
  recipes.
- **A template the CA can't read is "Invalid Template"** — without an
  Authenticated-Users read ACE on the template's SD,
  `certutil -SetCATemplates +X` fails with "Element not found
  0x80070490 / Invalid Template". It's a visibility error, not a
  schema one; bisecting attribute-by-attribute is a waste of time until
  the SD is proven (compare against a template that publishes).
- **"Not supported by the AD CS policy" at enrollment can mean missing
  msPKI-Template-Schema-Version** — the template publishes fine but the
  policy module denies every request (CERTSRV_E_UNSUPPORTED_TEMPLATE,
  0x80094800). Set schema-version 1 (v1 template, same class as the
  stock Web Server template); schema-version 2 without the full v2
  apparatus fails publish-time validation instead.
- **A blank "Denied by Policy Module" means missing validity fields** —
  templates without pKIExpirationPeriod/pKIOverlapPeriod/pKIKeyUsage
  publish and even look enrollable, but every request dies with an
  empty disposition message (0x8007076D). Copy the values from a
  healthy template (esc4 does this from the stock User template).
- **certsvc caches templates — restart after EVERY change** (publish,
  attribute edit, SD edit), or enrollment sees the stale object. And
  `msPKI-Enrollment-Flag` bit 0x2 is CT_FLAG_PEND_ALL_REQUESTS:
  requests come back disposition 5 (pending) instead of issuing — ESC1
  needs auto-issuance, so the lab template uses 0.
- **Server 2022's cert pipe requires packet privacy** — the ICPR bind
  must `set_auth_level(PKT_PRIVACY)` + `set_credentials` or the request
  fails with Win32 1746 ("binding does not contain any authentication
  information"), even over an authenticated SMB session.
- **The CA can silently drop a requested SAN** — a `SAN:upn=` request
  attribute alone got ignored (issued cert had no SAN at all) until the
  UPN also rode inside the CSR as an OtherName extension
  (1.3.6.1.4.1.311.20.2.3). esc1 sends both and verifies the SAN is in
  the issued cert before claiming the win.
- **0x80070576 is ERROR_TIME_SKEW, not a missing-DC error** — the
  message "could not find required Active Directory information" is a
  red herring; the event log says it plainly ("time and/or date
  difference between the client and server"). The QEMU RTC is seeded
  from host-local time while the Windows image uses a US Pacific
  timezone, so the guest's UTC is hours off the DC's and certsvc's
  policy module denies every request. Never patch it with
  `Set-Date (Get-Date).ToUniversalTime()` — on a non-UTC guest that
  writes the TZ offset INTO the RTC and poisons every later boot.
  The lab's ForgeLabTimeSync boot task pins the guest to UTC and takes
  the clock from the DC's net time on every boot.
- **ad-state (and dc-state) persist Samba's database across runs** — a
  test that creates a machine account and dies before the delete leaves
  residue that fails the NEXT run with STATUS_USER_EXISTS. Lab tests
  that create objects clean up in setUpClass, not just at the end.
- **Debian's Samba KDC has no PKINIT** — the 4.17 samba-ad-dc build
  ships with zero pkinit/pk-as-req symbols in its KDC binaries (checked
  with a strings scan), and `kdc enable pkinit` isn't a parameter it
  knows. Cert-auth attacks (pkinit, shadow credentials) are provable
  here only through error handling — issuance needs a real Windows AD
  KDC. The pkinit module's e2e therefore asserts the clean refusal,
  not a TGT.
- **Samba resolves attributes by lDAPDisplayName ONLY** — an LDAP write
  addressed to the hyphenated CN form (`msDS-KeyCredentialLink`) fails
  with "noSuchAttribute ... was not found in the schema" even though
  the attributeSchema object is right there (Windows resolves both
  names). Write `msDSKeyCredentialLink`. The ad lab carries the
  attribute as a schema fixture (15-kcl-schema.add.ldif + User
  mayContain), so shadow_creds plant/restore runs live.
