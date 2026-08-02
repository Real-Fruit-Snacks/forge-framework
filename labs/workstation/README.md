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

- `labadmin / Labpass2024!` (local admin)
- RDP: `127.0.0.1:23389`
- SMB/impacket targets: `127.0.0.1:2445` (set `RPORT 2445` in modules)

**Ports:** 445→2445 (impacket), 3389→23389 (RDP), 8006→8007 (viewer).

**Resources:** 4G RAM, 2 cores, 32G disk. Don't run this, `windows`, and
`domain` all at once on a small machine — each Windows guest wants its
own 4G.
