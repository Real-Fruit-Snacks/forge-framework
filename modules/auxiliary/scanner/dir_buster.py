"""Web content discovery (dir busting) with proper false-positive handling.

The naive version of this tool — request every word, print anything that
isn't a 404 — is wrong on real servers, and understanding why is most of
the craft:

  1. "Interesting" is more than 200. 401 (auth realm exists), 403 (exists
     but denied), 301/302 (redirect, usually to a login page) all reveal
     content. STATUS_CODES is the report list, not a hardcoded 200.
  2. Some servers never 404: they answer 200 (or 302 to an error page) for
     EVERY path. Before scanning we probe two random paths; if both return
     the same status+size, that's a wildcard/soft-404 fingerprint and
     matching responses are suppressed. Without this you get a wordlist-
     sized pile of garbage.
  3. Decoys belong in your wordlist. A buster tested only against paths
     that exist proves nothing about its filtering.

Structure: pure helpers (parse/filter/fingerprint) at the top so tests can
exercise them without sockets; the module class just wires options to them.
"""

import http.client
import time
import uuid
from collections import namedtuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from core.module import AuxiliaryModule
from core.options import OptAddress, OptBool, OptInt, OptPort, OptString

Response = namedtuple("Response", "status size location")

DEFAULT_CODES = "200,204,301,302,401,403"
MAX_BODY = 2 * 1024 * 1024  # cap reads; we only need a size, not the page
MAX_DIRS_PER_LEVEL = 64     # recursion safety valve


def parse_wordlist(path):
    """Words from a file: skip blanks and '#' comments, strip leading slashes."""
    words = []
    for raw in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if line and not line.startswith("#"):
            words.append(line.lstrip("/"))
    return words


def parse_status_codes(spec):
    """'200,301,403' -> {200, 301, 403}, validating range."""
    codes = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            code = int(part)
        except ValueError:
            raise ValueError(f"invalid HTTP status code: {part!r}")
        if not 100 <= code <= 599:
            raise ValueError(f"status code out of range: {code}")
        codes.add(code)
    if not codes:
        raise ValueError("STATUS_CODES cannot be empty")
    return codes


def build_paths(words, extensions, base="/"):
    """Yield request paths: base-normalized, plus word.ext variants."""
    base = "/" + base.strip("/") + "/" if base.strip("/") else "/"
    return extend_paths(words, extensions, [base])


def extend_paths(words, extensions, prefixes):
    """Cartesian expand: prefixes x words (+ word.ext variants)."""
    for prefix in prefixes:
        for word in words:
            yield f"{prefix}{word}"
            for ext in extensions:
                yield f"{prefix}{word}.{ext}"


def looks_like_dir(status, path):
    """Should we recurse into this finding? Success-ish status, and the last
    segment carries no file extension ("/admin" yes, "/db.sql" no)."""
    last = path.rstrip("/").rsplit("/", 1)[-1]
    return status in (200, 301, 302, 401, 403) and "." not in last


def is_interesting(resp, codes, wildcard):
    """The filter: in the status list, and not matching the wildcard fingerprint."""
    if resp.status not in codes:
        return False
    if wildcard and (resp.status, resp.size) == wildcard:
        return False
    return True


def wildcard_fingerprint(probe):
    """Detect a soft-404 server: two random paths, identical status+size?

    `probe` is a callable path -> Response|None (injected for testability).
    Returns the (status, size) fingerprint, or None for a well-behaved server.
    """
    first = probe(f"/fw-{uuid.uuid4().hex}")
    second = probe(f"/fw-{uuid.uuid4().hex}")
    if first and second and (first.status, first.size) == (second.status, second.size):
        return (first.status, first.size)
    return None


class DirBuster(AuxiliaryModule):
    name = "Web Content Discovery (dir buster)"
    description = """
        Enumerates web content with a wordlist: hidden directories, backup
        files, admin panels. Reports the statuses you ask for (not just 200),
        detects soft-404/wildcard servers so they can't flood you with false
        positives, and records findings as loot. Test it against the web lab:
        lab up web; set WORDLIST labs/web/wordlists/dirs.txt
    """
    authors = ["you"]

    def register_options(self):
        self.options.add(OptAddress("RHOSTS", required=True,
                                    description="Target host(s), comma-separated"))
        self.options.add(OptPort("RPORT", default=80, description="Target port"))
        self.options.add(OptBool("SSL", default=False, description="Use HTTPS"))
        self.options.add(OptString("WORDLIST", required=True,
                                   description="Path to wordlist file"))
        self.options.add(OptString("BASEPATH", default="/",
                                   description="Path prefix to enumerate under"))
        self.options.add(OptString("EXTENSIONS", default="",
                                   description="Also try word.ext: 'php,txt,bak'"))
        self.options.add(OptString("STATUS_CODES", default=DEFAULT_CODES,
                                   description="Codes to report"))
        self.options.add(OptInt("THREADS", default=16, description="Concurrent workers"))
        self.options.add(OptInt("TIMEOUT", default=5, description="Request timeout (seconds)"))
        self.options.add(OptBool("RECURSE", default=False,
                                 description="Descend into discovered directories"))
        self.options.add(OptInt("MAX_DEPTH", default=2,
                                description="Max recursion depth (with RECURSE)"))

    # ------------------------------------------------------------------ probing
    @staticmethod
    def _probe(host, port, use_ssl, path, timeout):
        """GET one path -> Response|None. Redirects are reported, not followed."""
        conn_cls = http.client.HTTPSConnection if use_ssl else http.client.HTTPConnection
        conn = None
        try:
            conn = conn_cls(host, port, timeout=timeout)
            conn.request("GET", path, headers={"User-Agent": "framework/0.4"})
            resp = conn.getresponse()
            body = resp.read(MAX_BODY)
            return Response(resp.status, len(body), resp.getheader("Location") or "")
        except (OSError, http.client.HTTPException):
            return None
        finally:
            if conn is not None:
                conn.close()

    # -------------------------------------------------------------------- run
    def run(self):
        hosts = [h.strip() for h in str(self.get_option("RHOSTS")).split(",") if h.strip()]
        try:
            codes = parse_status_codes(str(self.get_option("STATUS_CODES")))
        except ValueError as e:
            self.print_error(f"Bad STATUS_CODES value: {e}")
            return
        wordlist_path = str(self.get_option("WORDLIST"))
        try:
            words = parse_wordlist(wordlist_path)
        except OSError as e:
            self.print_error(f"Cannot read wordlist: {e}")
            return
        if not words:
            self.print_error(f"Wordlist is empty: {wordlist_path}")
            return

        extensions = [e.strip().lstrip(".")
                      for e in str(self.get_option("EXTENSIONS") or "").split(",")
                      if e.strip()]
        base = str(self.get_option("BASEPATH"))
        base = "/" + base.strip("/") + "/" if base.strip("/") else "/"
        self.print_status(f"{len(words)} words, {len(hosts)} host(s)")
        for host in hosts:
            self._scan_host(host, words, extensions, codes, base)

    def _scan_host(self, host, words, extensions, codes, base):
        port = self.get_option("RPORT")
        use_ssl = self.get_option("SSL")
        timeout = self.get_option("TIMEOUT")
        scheme = "https" if use_ssl else "http"

        probe = lambda p: self._probe(host, port, use_ssl, p, timeout)  # noqa: E731
        wildcard = wildcard_fingerprint(probe)
        if wildcard and wildcard[0] not in codes:
            # e.g. a consistent 404 page: a fingerprint, but one that can
            # never pollute the report — don't cry wolf.
            wildcard = None
        if wildcard:
            self.print_warning(
                f"{host}: soft-404 detected (every path answers "
                f"{wildcard[0]}/{wildcard[1]}b) -- matching responses suppressed"
            )

        recurse = self.get_option("RECURSE")
        max_depth = self.get_option("MAX_DEPTH")
        prefixes = [base]
        visited = {base}
        found_all = []
        done_total = 0
        started = time.time()
        depth = 0
        while prefixes:
            depth += 1
            paths = list(extend_paths(words, extensions, prefixes))
            found, done = self._scan_level(probe, paths, codes, wildcard)
            found_all.extend(found)
            done_total += done
            if not recurse or depth >= max_depth:
                break
            candidates = sorted(
                {p for st, _sz, p, _loc in found if looks_like_dir(st, p)} - visited
            )
            if len(candidates) > MAX_DIRS_PER_LEVEL:
                self.print_warning(
                    f"{host}: capping recursion at {MAX_DIRS_PER_LEVEL} dirs/level"
                )
                candidates = candidates[:MAX_DIRS_PER_LEVEL]
            prefixes = [c.rstrip("/") + "/" for c in candidates]
            visited |= set(prefixes)
            if not prefixes:
                break

        elapsed = max(time.time() - started, 0.001)
        self.print_status(
            f"{host}: {done_total} requests in {elapsed:.1f}s "
            f"({done_total / elapsed:.0f} req/s), {len(found_all)} found"
        )
        if done_total == 0:
            self.print_error(f"{host}:{port} -- no requests completed (host down?)")
            return

        store = getattr(self.framework, "store", None)
        if store is not None and found_all:
            store.add_service(host, port, name=scheme)
            content = "\n".join(
                f"{status} {size:>8}b {path}"
                for status, size, path, _ in sorted(found_all)
            )
            loot_id = store.add_loot(
                "web-dirs", f"dirbuster {host}:{port}", content, address=host
            )
            self.print_status(f"Findings saved as loot {loot_id} ('loot -i {loot_id}')")

    def _scan_level(self, probe, paths, codes, wildcard):
        """One breadth level: probe every path, return (found, attempted)."""
        threads = self.get_option("THREADS")
        found = []
        done = 0
        pool = ThreadPoolExecutor(max_workers=threads)
        futures = {pool.submit(probe, path): path for path in paths}
        try:
            for future in as_completed(futures):
                path = futures[future]
                done += 1
                resp = future.result()
                if resp is not None and is_interesting(resp, codes, wildcard):
                    found.append((resp.status, resp.size, path, resp.location))
                    line = f"{resp.status} {path} ({resp.size}b)"
                    if resp.location:
                        line += f" -> {resp.location}"
                    self.print_good(line)
        except KeyboardInterrupt:
            self.print_warning(f"Interrupted after {done}/{len(paths)} requests")
        finally:
            pool.shutdown(wait=False, cancel_futures=True)
        return found, done
