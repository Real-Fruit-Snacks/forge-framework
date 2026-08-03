# windows lab

**Purpose:** a real Windows target for the things Samba can't emulate —
psexec/wmiexec-style service control, ADMIN$ access, RDP, Windows auth.

**Build:** NO Dockerfile — uses the upstream `dockurr/windows` image,
which runs Windows in a KVM VM **inside** the container. Requires
`/dev/kvm` on the host (present on this machine) and `cap_add: NET_ADMIN`
(for the VM's networking).

**How it works:**

- First boot: downloads the Windows Server 2022 eval ISO and installs it
  unattended. **Expect ~20 minutes** (plus ISO download time). Watch it
  at `http://127.0.0.1:8006` (noVNC viewer).
- The disk persists in the `win-data` named volume → later `lab up` is a
  normal VM boot (~1 min). Reset to a fresh install:
  `docker compose -p forge-lab-windows -f labs/windows/compose.yml down -v`
- `lab up windows` waits for guest SMB with a 2400s READY timeout.
  Ctrl-C during the wait is safe — the install keeps running; check
  `lab status windows` later.

**Access:**

- `labadmin / Labpass2024!` (local admin — what psexec needs)
- RDP: `127.0.0.1:13389`
- SMB/impacket targets: `127.0.0.1:1445` (set `RPORT 1445` in modules)

**Networking note:** `oem/` pins the Private profile and opens the
firewall at specialize time and on every boot (scheduled task) — without
it, a Windows guest that mints a Public NLA profile after a rebuild
silently stops answering SMB/RDP. Throwaway lab rules; never ship it.

**Ports:** 445→1445 (impacket), 3389→13389 (RDP), 8006→8006 (viewer).

**Resources:** 4G RAM, 2 cores, 32G disk (env in compose.yml — raise
RAM_SIZE if the VM feels slow). Windows eval licensing is per Microsoft's
evaluation terms, same as a manual eval VM.
