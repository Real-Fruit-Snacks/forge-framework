# mssql lab

**Purpose:** a real Microsoft SQL Server for TDS auth modules
(`mssql_login` today; query/exec modules later — `xp_cmdshell` is the
classic follow-up).

**Build:** no Dockerfile — the stock
`mcr.microsoft.com/mssql/server:2022-latest` image with credentials from
the environment (`SA_PASSWORD`). Developer edition via `MSSQL_PID`.

**Size warning:** the image is **~1.5 GB** — by far the biggest lab.
`lab purge mssql` reclaims it; don't leave it lying around if you're not
using it. First `lab up mssql` pulls it (slow on cold connections).

**Credentials:** `sa / For9e_SQL!2024` (SQL authentication; meets the
enforced complexity policy). Windows-auth logins need a domain — use the
`ad` or `domain` lab for that shape.

**Ports:** 1433 → `127.0.0.1:11433`.

**Notes:**

- sqlservr takes 10-30s to accept logins after the port opens — the
  READY check is a plain tcp connect, so poll a REAL login in tests
  (same pattern as the ad lab's LDAP-bind wait).
- Memory: sqlservr refuses to start under ~2GB; compose caps at 3GB.
