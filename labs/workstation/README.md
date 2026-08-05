# workstation lab

**Purpose:** a Windows 11 client — the "user's machine" you land on first
in a real engagement. Complement to the `windows` lab (Server 2022) and
the `domain` lab (which ships its own member with auto-join wired up).

**Build:** NO Dockerfile — uses the upstream `dockurr/windows` image
(KVM VM inside a container). Requires `/dev/kvm` on the host.

**How it works:**

- First boot: downloads the Windows 11 eval ISO and installs unattended.
  **Expect ~20 minutes** (plus ISO download time). Watch it at
  `http://127.0.0.1:8007` (noVNC viewer).
- The disk persists in the `workstation-data` named volume → later
  `lab up` is a normal VM boot (~1 min). `lab purge workstation` reclaims
  everything (image, volume, ISO — several GB).

**Access:**

- `labadmin / Labpass2024!` (local admin — non-RID-500, so UAC token
  filtering blocks it for privileged REMOTE RPC calls)
- `Administrator / Labpass2024!` (RID-500, enabled at install by the oem
  — the account remote admin work actually needs)
- RDP: `127.0.0.1:23389`
- SMB/impacket targets: `127.0.0.1:2445` (set `RPORT 2445` in modules)

**Ports:** 445→2445 (impacket), 3389→23389 (RDP), 8006→8007 (viewer).

**Resources:** 4G RAM, 2 cores, 24G disk. Don't run this, `windows`, and
`domain` all at once on a small machine — each Windows guest wants its
own 4G.

**Gotchas (measured live):**

- The oem (`oem/net-fix.ps1`, bind-mounted) pins the Private network
  profile, opens the firewall on every boot, disables Defender via the
  durable GPO key, and enables RID-500 with the lab password.
- **smb_exec can't produce output here** — Win11's session 0 makes
  console executables launched from a service write nothing, and the
  loopback admin share denies SYSTEM. Commands still EXECUTE (state
  changes land); output never comes back. Use at_exec (atsvc denies
  remotely on these guests too — cleanly reported) or the windows lab.
- Cold installs take ~20 min; readiness waits must cover that, not the
  warm ~1 min boot.
