# domain lab

**Purpose:** a small Active Directory domain — the minimum topology for
domain-level work (Kerberos, delegation, lateral movement, GPO-shaped
things Samba can emulate):

```
            domain network 10.10.10.0/24
   ┌───────────────────────────────────────────┐
   │  dc  10.10.10.10    Samba AD DC (FORGE.LOCAL, same image as the ad lab)
   │  member  (dhcp)     Windows 11, auto-joins the domain during setup
   │  ca      (dhcp)     Windows Server 2022, joins + installs AD CS as
   │                     an Enterprise Root CA and publishes VulnWeb
   │                     (ESC1) + WeakWeb (ESC4)
   │  windc 10.10.10.20  Windows Server 2022 — STANDALONE forest
   │                     wforge.local (AD DS + Enterprise Root CA on the
   │                     same box), real AD ports on 127.0.0.2
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
- The **CA** (`ca` service) is a third dockur/windows box: `oem-ca/ca.ps1`
  runs in two phases — phase 1 joins the domain and reboots (membership
  only activates after a reboot), phase 2 resumes from a one-shot boot
  task (`ForgeLabCAPhase2`): renegotiates the secure channel, installs
  AD CS as Enterprise Root `forge-CA`, enriches the fixture **VulnWeb**
  template into ESC1 shape (enrollee-supplies-subject, auto-issue,
  Domain Users enroll), publishes VulnWeb AND WeakWeb (the esc4 target)
  with `certutil -SetCATemplates`, and drops `C:\OEM\CA-READY.txt`
  as the readiness sentinel. First boot is a full Windows install +
  AD CS (~30 min); state persists on `ca-data`. Validated from cold:
  purge + rebuild lands a working CA end to end.
  **Server Core gotcha:** dockur's 2022 is Server CORE — MMC snap-ins
  can't install, so `-IncludeManagementTools` on the AD CS feature kills
  the whole chain silently (task exits 1, nothing installed). The oem
  installs the bare feature; RSAT-AD-PowerShell is a PS module and is
  fine on Core.
  **Netlogon gotcha:** Server 2022 + Samba needs the STRONG secure
  channel (all four Netlogon values = 1). The Win11-style RC4 relax
  breaks 2022's channel at birth — every domain logon fails with
  "trust relationship failed". `Reset-ComputerMachinePassword` post-join
  renegotiates the channel. (The Win11 member keeps the relax; 2022
  must not.)
  **Template gotchas (all observed live):** the CA caches template
  objects — every template change needs a certsvc restart to take
  effect. A template the CA can't READ (no Authenticated-Users read ACE
  on its SD) is reported as "Element not found / Invalid Template" at
  publish time. Without `msPKI-Template-Schema-Version` the policy
  module denies enrollment with "not supported by the AD CS policy"
  even though the template publishes — VulnWeb is a v1 template
  (schema-version 1), the same class as the stock Web Server template.
  And `msPKI-Enrollment-Flag` bit 0x2 means manager approval — requests
  pend instead of issuing, which breaks ESC1.
  **Clock gotcha (the sneakiest one):** the QEMU RTC is seeded from
  host-local time and the Windows image installs with a US Pacific
  timezone — the guest's UTC ends up hours off the DC's, and certsvc's
  policy module then denies EVERY request with `0x80070576`
  (ERROR_TIME_SKEW, misreported as "could not find required Active
  Directory information"). Never "fix" the clock with
  `Set-Date (Get-Date).ToUniversalTime()` — on a non-UTC guest that
  writes the TZ offset INTO the RTC and poisons every later boot. The
  `ForgeLabTimeSync` boot task (`oem-ca/timesync.ps1`) pins the guest
  to UTC, takes the clock from the DC's net time, and restarts certsvc
  on every boot. member/ca also `depends_on` the DC with
  `condition: service_healthy` (an in-container LDAP probe), so the
  Windows boxes only start once Samba is really up.
- The **windc** (`windc` service) is a FOURTH box and its own forest:
  `oem-windc/windc.ps1` phase 1 builds `wforge.local` with
  `Install-ADDSForest` (AD DS ONLY first — `Install-ADDSForest` refuses
  outright when Certificate Services is already installed, "Certificate
  Server is installed"), phase 2 installs AD CS as Enterprise Root
  `wforge-CA` ON the DC, creates VulnWeb when absent (this forest has no
  fixture object — the Samba lab's VulnWeb arrives as one), publishes
  KerberosAuthentication + VulnWeb, enrolls the KDC cert (PKINIT's
  requirement), and creates the `analyst`/`Summer2024!` test user. The
  forest Administrator's password is deterministically reset to
  `P@ssw0rd123` in phase 2 (its post-promo value is otherwise whatever
  the local admin's was).
  **Why standalone instead of a replica DC in FORGE.LOCAL:** dcpromo
  into the Samba domain fails twice, both verified against this exact
  build. Unjoined, the Adprep prerequisite dies with "unable to check
  the specified user's group membership — access denied, Adprep was
  unable to bind to any DC over RPC". Joined, forestprep's LDIF schema
  update to the Samba schema master is refused with Ldap error 50
  (insufficient rights) even as Schema Admin — Samba denies LDAP
  schema writes by default (`dsdb:schema update allowed`), and Windows
  adprep is not a supported schema path against Samba anyway (the
  supported route, `samba-tool domain schemaupgrade`, is experimental
  and caps at 2016/87, below Server 2022's 88). The standalone forest
  delivers the real Windows KDC + DS the framework needs with zero
  experimental risk to the Samba fleet. The Samba<->Windows replication
  goal is documented as not-pursued for exactly these reasons.
  **Ports:** real AD ports on 127.0.0.2 (all of 127/8 is loopback on
  Linux) — 389 LDAP, 88 KDC, 445 SMB — so impacket's hardcoded-AD-port
  assumptions hold exactly as for the Samba DC. Cold build is a full
  Windows install + forest create + CA (~25 min); state persists on
  `windc-data`.

**Access:**

| What | Where | Creds |
| ---- | ----- | ----- |
| DC LDAP/Kerberos/SMB | `127.0.0.1:389/88/445` | `FORGE\Administrator / P@ssw0rd123` (same fixtures as the ad lab) |
| member SMB | `127.0.0.1:3445` | local `labadmin / Labpass2024!`, domain creds after join |
| CA SMB / cert pipe | `127.0.0.1:4445` | domain creds (`analyst` can enroll) |
| windc LDAP/KDC/SMB (wforge.local) | `127.0.0.2:389/88/445` | `WFORGE\Administrator / P@ssw0rd123`, `analyst / Summer2024!` |
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
