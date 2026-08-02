# ssh lab

**Purpose:** SSH brute-force and protocol practice target.

**Build:** `debian:bookworm-slim` + `openssh-server`.

**How it's built (Dockerfile):**

1. Install openssh, create `/run/sshd`.
2. Weak users via `useradd` + `chpasswd`: `admin:admin`,
   `user:password`, plus `root:toor`.
3. `sshd_config` edits: `PasswordAuthentication yes`,
   `PermitRootLogin yes` (both deliberate — it's a brute-force lab).
4. Runs `sshd -D -e` (foreground, logs to stderr → `docker logs`).

**Readiness:** `READY` = `banner 12222` (waits for the SSH banner, not
just a TCP accept).

**Port:** container 22 → `127.0.0.1:12222`.

**Modify rule:** credentials are part of the test fixtures — the
integration test brute-forces `admin:admin`.
