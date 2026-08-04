# web lab

**Purpose:** deterministic HTTP target for dir busting, brute force, and
scanner modules.

**Build:** `python:3-slim`, one stdlib file (`app.py`), no dependencies.

**How it works:** `app.py` is a `http.server` app with a hardcoded route
table (top of the file): hidden 200s (`/admin`, `/backup`, nested
`/admin/panel`, `/backup/db` for recursion), a 403 (`/forbidden`), a 401
basic-auth realm (`/protected`, `admin:hunter2`), and a POST login form
(`/login`, `admin:hunter2`). Everything else is a real 404 with a
fixed-size page — which also makes it a soft-404 fingerprint fixture.

**Catch-all fixtures (for canary/validator work):** `/app/*` answers
every path with the same SPA shell but a VARYING-length build nonce —
exact (status,size) wildcard suppression can't catch it; similarity +
family clustering must. `/.env` is a real KEY=VAL (validators accept),
`/decoy.env` an HTML decoy (validators reject).

**Fixtures:** `wordlists/dirs.txt` (known hits AND known 404 decoys),
`wordlists/canary.txt` (SPA catch-all words + the .env pair),
`wordlists/passwords.txt` (one real hit among decoys).

**Rules if you modify it:** keep it deterministic — fixed routes, fixed
creds, no randomness. Integration tests assert exact behavior; change a
route and update `tests/test_integration.py` to match.

**Port:** container 8080 → `127.0.0.1:18080`.
