# domain lab

**Purpose:** a small Active Directory domain — the minimum topology for
domain-level work (Kerberos, delegation, lateral movement, GPO-shaped
things Samba can emulate):

```
            domain network 10.10.10.0/24
   ┌───────────────────────────────────────────┐
   │  dc  10.10.10.10    Samba AD DC (FORGE.LOCAL, same image as the ad lab)
   │  member  (dhcp)     Windows 11, auto-joins the domain during setup
   └───────────────────────────────────────────┘
```

**How it works:**

- `lab up domain` builds the DC from `../ad` (FORGE.LOCAL provisions
  fresh every boot, ~60s) and starts the Windows member. Readiness waits
  on the DC only.
- First boot: the member downloads the Windows 11 ISO and installs
  unattended (**~20 min**) — watch at `http://127.0.0.1:8008` (noVNC).
  During the final setup phase, dockur/windows runs `C:\OEM\install.bat`,
  which calls `oem/join.ps1`: relax Netlogon secure-channel requirements
  (Samba 4.17 compat), then `Add-Computer forge.local` with retries, then
  reboot. If the join doesn't take, `C:\OEM\JOIN-FAILED.txt` appears in
  the guest — re-run `C:\OEM\join.ps1` elevated, or join manually
  (Settings > Accounts > Access work or school, or `Add-Computer`).
- The member disk persists in the `member-data` volume → later boots are
  ~1 min and stay joined. `lab purge domain` reclaims everything.

**Access:**

| What | Where | Creds |
| ---- | ----- | ----- |
| DC LDAP/Kerberos/SMB | `127.0.0.1:389/88/445` | `FORGE\Administrator / P@ssw0rd123` (same fixtures as the ad lab) |
| member SMB | `127.0.0.1:3445` | local `labadmin / Labpass2024!`, domain creds after join |
| member RDP | `127.0.0.1:33389` | same |
| noVNC | `http://127.0.0.1:8008` | — |

**Gotchas:**

- **Port conflict:** the DC binds 389/88/445 on loopback just like the
  `ad` lab — never run both at once (`lab down ad` first; `lab up`
  preflights this and tells you).
- **Windows firewall vs. rebuilds (the hard lesson):** when the guest
  sees a new network it mints a Public profile and silently stops
  answering SMB/RDP inbound. `oem/join.ps1` therefore pins the Private
  profile and opens the firewall TWICE: at specialize time, and via a
  boot scheduled task (`ForgeLabNetFix`, registered with a proper SYSTEM
  principal — a bare `-User SYSTEM` registration fails silently) that
  waits for a profile to exist before pinning it. The DC's MAC is also
  pinned in compose.yml to minimize churn. Throwaway lab rules — don't
  ship this anywhere real.
- **Win11's Defender kills the psexec pattern** (the second hard
  lesson): service-spawned cmd chains (smb_exec's shape) are detected as
  `VirTool:Win32/MSFPsExecCommand` and quarantined — every SCMR exec
  silently produces no output. Server 2022's Defender tolerates the same
  chain; Win11's doesn't. `oem/join.ps1` disables realtime monitoring +
  cloud protection at install time. If a member ever comes up with exec
  "working but empty", check `Microsoft-Windows-Windows
  Defender/Operational.evtx` first.
- **TSCH on workgroup machines denies local accounts remotely** (UAC
  token filtering: non-RID-500 local admins get filtered tokens —
  `rpc_s_access_denied` on atsvc while SCMR tolerates the same creds).
  Domain accounts bypass it — another reason the member matters.
- **Domain state persists** on the `dc-state` volume: the domain SID is
  stable across restarts, so the member's trust relationship survives.
  `lab purge domain` wipes both volumes (member reinstalls, domain
  re-provisions).
- **DNS:** the member's guest DNS forwards to the DC via the container's
  `dns: 10.10.10.10`, and the DC forwards external lookups
  (`dns forwarder = 8.8.8.8` in the ad lab's entrypoint) — the member
  downloads its ISO through the DC, so without the forwarder the
  install dies at "unable to resolve host".
- **Resources:** DC ~0.5G + member 4G RAM. KVM required (`/dev/kvm`).
- Windows eval licensing per Microsoft's evaluation terms.
