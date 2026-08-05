# mssql lab

**Purpose:** a real Microsoft SQL Server for TDS auth modules
(`mssql_login`, `mssql_enum`, `mssql_exec`) — and a SECOND instance
(`mssql2`) auto-linked as `MSSQL2`, so linked-server chain attacks
(mssql_exec's LINK pivot, OPENQUERY) have somewhere to go.

**Build:** no Dockerfile — the stock
`mcr.microsoft.com/mssql/server:2022-latest` image ×2 with credentials
from the environment (`SA_PASSWORD`). Developer edition via `MSSQL_PID`.
A one-shot `link-init` container links MSSQL2 into mssql at every cold
boot (sp_addlinkedserver + sa login + rpc out, retry loop — sqlservr's
first boot outruns any fixed sleep).

**Size warning:** the image is **~1.5 GB** — by far the biggest lab.
`lab purge mssql` reclaims it; don't leave it lying around if you're not
using it. First `lab up mssql` pulls it (slow on cold connections).

**Credentials:** `sa / For9e_SQL!2024` on BOTH instances (SQL auth; meets
the enforced complexity policy). Windows-auth logins need a domain — use
the `ad` or `domain` lab for that shape.

**Ports:** 1433 → `127.0.0.1:11433` (mssql), 1433 → `127.0.0.1:11434`
(mssql2).

**Notes:**

- sqlservr takes 10-30s (longer on cold first boot) to accept logins
  after the port opens — the READY check is a plain tcp connect, so
  poll a REAL TDS login in tests (same pattern as the ad lab's
  LDAP-bind wait).
- Memory: sqlservr refuses to start under ~2GB; compose caps at 3GB
  per instance (6GB total for both).
- xp_cmdshell is Windows-only: SQL Server for Linux (this image)
  refuses it via sp_configure. The chain/query paths (OPENQUERY,
  EXEC (...) AT) work fine; the module reports the Linux case plainly.
