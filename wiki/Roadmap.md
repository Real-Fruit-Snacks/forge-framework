# Roadmap

The working backlog. Each entry carries everything needed to pick it up
cold: scope, payoff, what's already proven, design notes with the
hard-won technical facts, the testing plan (our e2e discipline is not
optional), and the files to touch. Priority order top to bottom. When an
item ships, delete it here and update [[Development]]'s roadmap pointer.

The bar for every item: real modules against real labs, proven on the
artifact itself — no mocked crypto, no "it should work".

## 1. pwntools exploit helpers

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

## 2. C2-style session channels

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

## 3. Console `set` raw-value semantics

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
