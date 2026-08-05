# Roadmap

The working backlog. Each entry carries everything needed to pick it up
cold: scope, payoff, what's already proven, design notes with the
hard-won technical facts, the testing plan (our e2e discipline is not
optional), and the files to touch. Priority order top to bottom. When an
item ships, delete it here and update [[Development]]'s roadmap pointer.

The bar for every item: real modules against real labs, proven on the
artifact itself — no mocked crypto, no "it should work".

## 1. DPAPI stage 5: system-scope keys (WiFi, machine creds)

**Scope.** `modules/auxiliary/attack/dpapi_system.py`: pull the
DPAPI_SYSTEM keys out of LSA secrets (bootkey from SYSTEM hive +
SECURITY hive, both fetchable over SMB), decrypt the SYSTEM masterkeys
(`Windows\System32\Microsoft\Protect\<sid>\` and `...\S-1-5-18\User\`),
then the blobs they protect: WiFi profile `keyMaterial` XML, scheduled
task credentials, service account passwords.

**Payoff.** The machine half of DPAPI — the user chain (stages 1-4)
doesn't touch it. WiFi passwords alone justify it on real assessments.

**Proven building blocks.** `sam_dump` (remote registry hive dump —
the transport for SYSTEM/SECURITY), the whole core/dpapi.py chain.
dploot's `triage_system_masterkeys` (fetched during stage 2) is the
reference: `LSASecrets(SECURITYFile, bootkey, remoteOps,
perSecretCallback)` yields `dpapi_machinekey`/`dpapi_userkey` secrets —
impacket ships the entire mechanism in `examples/secretsdump.py`.

**Design notes.**
- `DPAPI_SYSTEM` struct: Version(4), MachineKey(20), UserKey(20).
  `MasterKey.decrypt()` takes either key directly (no RSA step — this
  is the password-path decryption, impacket's dpapi.py example shows it
  under the `-system -security` flags).
- WiFi XML lives at `ProgramData\Microsoft\Wlansvc\Profiles\Interfaces\
  <guid>\*.xml`; `keyMaterial` is a DPAPI blob under the SYSTEM
  masterkey.
- Server SKUs often lack Wlansvc — the honest lab fixture is a
  LocalSystem-scope `CryptProtectData` blob (same scheduled-task
  pattern as stages 2-4, but `'LocalSystem'` scope), decrypted with the
  recovered MachineKey. WiFi XML parsing gets unit-tested with a real
  captured blob shape instead.

**Testing plan.** E2E against the windows lab (Server 2022): fixture
mints a system-scope blob; module recovers plaintext. Unit tests
forward-build a system masterkey file with known DPAPI_SYSTEM keys
(password-path PBKDF2, the construction already in test_core_dpapi).

**Files.** new module; core/dpapi.py: `decrypt_system_masterkey_file`,
`wifi_passwords(xml)`; tests.

## 2. Windows AD DC lab role (PKINIT field test + Windows KDC)

**Scope.** A 4th role in labs/domain: `windc` — dockurr/windows Server
2022 promoted to a second DC (AD DS + DNS), joined to FORGE.LOCAL
alongside the Samba DC. The Samba DC stays primary for speed.

**Payoff.** The Samba KDC has no PKINIT (proven: our pkinit module's
clean-refusal path is the tested behavior there). A Windows KDC unlocks
real PKINIT (cert -> TGT -> UnPAC-the-hash), LDAPS/Schannel behaviors,
and Windows-KDC-only edge cases — the honest home for several modules
that currently test "refuses cleanly".

**Design notes.**
- dcpromo unattended: `Install-WindowsFeature AD-Domain-Services` +
  `Install-ADDSDomainController` with a generated SafeMode password in
  the oem script; the CA role already proves the multi-phase oem
  pattern (ca.ps1 phase 1/2 + sentinels). Reuse that shape.
- The KDC needs a KDC-template cert for PKINIT — auto-enrollment via
  GPO from the existing Enterprise CA (the lab's CA is already
  published; the policy module answers from it in the ESC tests).
- DNS: the lab compose pins dns to the Samba DC; the Windows DC joins
  as a second NS. Replication DRS between Samba and Windows DCs is the
  known-risk item — validate `repadmin`-equivalents before writing
  module tests on top.
- Build-script discipline applies in full: cold-rebuild validation
  (`lab purge domain` + `lab up domain` + the e2e class) before commit,
  readiness is a real KDC answer (an AS-REQ), not a port.

**Testing plan.** New e2e class: pkinit module against the Windows KDC
with an ESC1-issued cert (already minted in the ESC tests) -> real TGT
-> assert UnPAC'd NTLM hash matches the account's.

**Files.** labs/domain/compose.yml + labs/domain/oem-windc/; nothing in
modules (they're built); wiki/Labs.md build notes.

## 3. More encoders (hex, badchar-aware)

**Scope.** Extend modules/payloads/ encoder set: plain hex encode, and
a badchar-aware transform that takes a BADCHARS option and picks an
encoding that avoids those bytes in the generated shellcode.

**Payoff.** Practical pwn/BOF work; the encoder slot exists, this is
filling it.

**Design notes.** The existing encoder modules define the interface —
match it. Badchar-aware = validate output against BADCHARS post-encode
and refuse loudly when the alphabet can't satisfy it (verify the
artifact). Keep transforms dependency-free (stdlib) unless shikata is
explicitly added later.

**Testing plan.** Unit: roundtrip + badchar assertion on generated
bytes; generate-path e2e already exists for payloads — extend it.

## 4. pwntools exploit helpers

**Scope.** Modules wrapping pwntools for pwn work: `pwn/cyclic`
(pattern gen + offset find against a crash input), `pwn/rop` (ROP chain
builder against a looted binary).

**Payoff.** Keeps BOF/CTF pwn work inside the framework instead of
shelling out.

**Design notes.** `requirements = ["pwntools"]` — declare like
impacket; the console's missing-requirement path handles absence.
Cyclic is pure computation (easy, do first). ROP needs a target binary
— take one from file loot or an option path.

**Testing plan.** Unit for cyclic (deterministic). ROP unit gated on
pwntools presence against a tiny fixture ELF (compile in-test with gcc
when available, skip otherwise — no committed binaries).

## 5. C2-style session channels

**Scope.** Beaconing sessions on top of the handler: poll-based
HTTP(S)/named-pipe channels with jitter + a task queue per session,
replacing raw reverse-TCP for the noisy cases. Staged payload one-
liners (powershell/bash) that beacon instead of connect-back.

**Payoff.** Sessions that survive reality (egress filtering, idle
timeouts, blue-team visibility of long-lived sockets). Turns the
handler into a baby C2.

**Design notes.** core/session.py already abstracts the session
(channel-agnostic IO + pty upgrade + resize sync); a channel interface
(poll/task/result envelopes) slots under it. The listener side reuses
the web lab's HTTP primitives for the fixture. Payloads are new
generator modules so `generate` emits a beacon one-liner.

**Testing plan.** Extend the handler e2e: launch a beacon payload
against a fixture listener, assert task/result round-trip through real
HTTP on the web lab.

## 6. Console `set` raw-value semantics

**Scope.** core/console.py `do_set`: today `shlex.split` eats
backslashes, so `set COMMAND ... C:\Users\...` arrives mangled
(`C:UsersPublic...` — bit us live in the DPAPI fixture work; the
workaround is doubling every backslash).

**Design notes.** The value should be everything after the option name,
verbatim (msfconsole semantics) — but quoted-value behavior changes are
a regression vector for every module/test that relies on shlex
quote-stripping. Approach: keep shlex for the option NAME split only,
take the value as the raw remainder; sweep the test suite for quoted
`set` values before committing. Small change, wide blast radius —
deserves its own commit with the full suite green.

## Considered and deferred

**Proxmox/ESXi API pivot.** Deferred, reasoning recorded so it doesn't
get re-litigated: (1) the framework's purpose is offensive capability
for CTF/certs — hypervisor automation is infrastructure work with no
offensive content; (2) untestable to our standard — ESXi can't be
containerized, Proxmox needs nested-KVM contortions, so modules would
ship mocked or untested; (3) docker labs rebuild from the repo on any
KVM host, which is what lets others reproduce them — a hypervisor API
ties labs to one machine. Revisit only as a v2 lab-infra project if a
real hypervisor host enters the picture; docker labs stay the default
regardless.

**Chrome v20 app-bound triage (off-box).** Explicitly out of scope for
the SMB triage modules: v20 binds the key to the app path + machine via
COM elevation, so off-box decryption is impossible by design. The only
path is on-box (post-exec through the browser process itself) — that's
a post-exploitation payload feature, not a triage module; revisit if C2
channels (item 6) land.

## Conventions for picking an item up

- Spec first, then build, then unit tests, then the lab e2e — in that
  order, one item at a time.
- Reference implementations exist for almost everything: dploot
  (DPAPI), impacket examples (relay, secretsdump, dpapi). Read them
  before designing — solved problems stay solved.
- Fixture rule: mint real state on the lab (scheduled tasks as a domain
  user are the proven pattern — see `dpapi_run_ps1_as_admin` in
  tests/test_integration.py), never synthetic crypto in the artifact
  under test.
- Docs ship in the same commit: README counts, [[Home]], [[Testing]],
  [[Development]], and this file.
