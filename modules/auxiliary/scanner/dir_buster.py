"""Web content discovery (dir busting) with proper false-positive handling.

The naive version of this tool — request every word, print anything that
isn't a 404 — is wrong on real servers, and understanding why is most of
the craft:

  1. "Interesting" is more than 200. 401 (auth realm exists), 403 (exists
     but denied), 301/302 (redirect, usually to a login page) all reveal
     content. STATUS_CODES is the report list, not a hardcoded 200.
  2. Some servers never 404: they answer 200 (or 302 to an error page) for
     EVERY path. Before scanning we probe two random paths; a shared
     status plus a similar body = a catch-all/SPA canary, and matching
     responses are suppressed. The bodies are compared by SIMILARITY,
     not exact (status,size) — SPAs embed per-request nonces, so exact
     fingerprinting misses them. Without this you get a wordlist-sized
     pile of garbage.
  3. A 200 isn't proof: high-value paths carry content validators
     (/.env must look like KEY=VAL, /actuator like JSON with _links).
     A soft-404 page at a sensitive path fails validation and gets
     suppressed with a debug note.
  4. Decoys belong in your wordlist. A buster tested only against paths
     that exist proves nothing about its filtering.

Structure: pure helpers (parse/filter/fingerprint) at the top so tests can
exercise them without sockets; the module class just wires options to them.
"""

import difflib
import http.client
import re
import time
import uuid
from collections import namedtuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from core.module import AuxiliaryModule
from core.options import OptAddress, OptBool, OptInt, OptPort, OptString

Response = namedtuple("Response", "status size location sample")

DEFAULT_CODES = "200,204,301,302,401,403"
MAX_BODY = 2 * 1024 * 1024  # cap reads; we only need a size, not the page
SAMPLE_BYTES = 512          # canary/validator evidence kept per response
CANARY_SIZE_TOLERANCE = 32  # nonce length wiggle between catch-all answers
CANARY_SIMILARITY = 0.9     # quick_ratio threshold for "same page"
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


def _normalize(sample):
    """Strip volatile tokens before comparing: hex-ish runs (build hashes,
    CSRF tokens, UUIDs) and plain numbers become '#', so a page whose only
    variance is an embedded nonce compares identical to itself."""
    text = sample.decode("utf-8", "replace")
    text = re.sub(r"[0-9a-fA-F]{6,}", "#", text)
    text = re.sub(r"\d+", "#", text)
    return text


def _similarity(a, b):
    """Body similarity for canary work: quick_ratio on normalized samples."""
    na, nb = _normalize(a), _normalize(b)
    if na == nb:
        return 1.0
    return difflib.SequenceMatcher(None, na, nb).quick_ratio()


def wildcard_fingerprint(probe):
    """Detect a catch-all/SPA server: two random paths answering with the
    same status and SIMILAR bodies (nonce variance tolerated) -> canary
    (status, size, sample). Exact-size servers still match too.

    `probe` is a callable path -> Response|None (injected for testability).
    """
    first = probe(f"/fw-{uuid.uuid4().hex}")
    second = probe(f"/fw-{uuid.uuid4().hex}")
    if not first or not second or first.status != second.status:
        return None
    if abs(first.size - second.size) > CANARY_SIZE_TOLERANCE:
        return None
    if _similarity(first.sample, second.sample) < CANARY_SIMILARITY:
        return None
    return (first.status, first.size, first.sample)


def matches_canary(resp, canary):
    """Response belongs to the canary's catch-all family."""
    if resp.status != canary[0]:
        return False
    if abs(resp.size - canary[1]) > CANARY_SIZE_TOLERANCE:
        return False
    return _similarity(resp.sample, canary[2]) >= CANARY_SIMILARITY


def is_interesting(resp, codes, canary):
    """The filter: in the status list, and not matching the canary."""
    if resp.status not in codes:
        return False
    if canary and matches_canary(resp, canary):
        return False
    return True


# ---------------------------------------------------- content validators
def looks_like_env(sample):
    """KEY=VAL lines (comments allowed) — not an HTML page."""
    lines = [l.strip() for l in
             sample.decode("utf-8", "replace").splitlines() if l.strip()]
    lines = [l for l in lines if not l.startswith("#")]
    if not lines or any(l.startswith("<") for l in lines):
        return False
    return all("=" in l for l in lines[:5])


def looks_like_actuator(sample):
    return sample.lstrip().startswith(b"{") and b'"_links"' in sample


def looks_like_phpinfo(sample):
    return b"phpinfo()" in sample or b"PHP Version" in sample


CONTENT_VALIDATORS = {
    ".env": looks_like_env,
    "actuator": looks_like_actuator,
    "phpinfo.php": looks_like_phpinfo,
    "server-status": lambda s: b"Apache Server Status" in s
                               or b"Scoreboard" in s,
}


def validator_for(path):
    """The validator for a path, or None. *.env validates by extension
    (decoy.env and app.env are just as common as .env); the rest by
    basename."""
    base = path.rstrip("/").rsplit("/", 1)[-1].lower()
    if base.endswith(".env"):
        return looks_like_env
    return CONTENT_VALIDATORS.get(base)


FAMILY_MIN = 3  # a catch-all family needs at least this many similar hits


def find_families(found):
    """Cluster findings into canary families: >=FAMILY_MIN same-status
    items whose normalized bodies are near-identical. Prefix-scoped
    catch-alls (/app/*, /api/*) hide from the two-probe fingerprint
    because random paths 404 — but their family resemblance gives them
    away. Returns the list of families (each a list of found items)."""
    families = []
    for item in found:
        status, size, path, loc, sample = item
        for family in families:
            first = family[0]
            if first[0] == status \
                    and abs(size - first[1]) <= CANARY_SIZE_TOLERANCE \
                    and _similarity(sample, first[4]) >= CANARY_SIMILARITY:
                family.append(item)
                break
        else:
            families.append([item])
    return [family for family in families if len(family) >= FAMILY_MIN]


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
            return Response(resp.status, len(body),
                            resp.getheader("Location") or "",
                            body[:SAMPLE_BYTES])
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
        self.print_debug(f"{host}: wildcard fingerprint={wildcard}")
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
            self.print_debug(
                f"{host}: depth {depth}, {len(paths)} probes, "
                f"{len(found)} interesting"
            )
            if not recurse or depth >= max_depth:
                break
            candidates = sorted(
                {p for st, _sz, p, _loc, _sm in found if looks_like_dir(st, p)} - visited
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
        # prefix-scoped catch-alls: families of similar responses that the
        # root fingerprint can't see (their random paths genuinely 404)
        families = find_families(found_all)
        suppressed = 0
        for family in families:
            suppressed += len(family)
            status, size, path, _loc, _sample = family[0]
            self.print_warning(
                f"{host}: suppressing {len(family)} catch-all responses "
                f"({status}, ~{size}b, like {path})")
        if families:
            killed = {item[2] for family in families for item in family}
            found_all = [item for item in found_all if item[2] not in killed]
        self.print_status(
            f"{host}: {done_total} requests in {elapsed:.1f}s "
            f"({done_total / elapsed:.0f} req/s), {len(found_all)} found"
            + (f" ({suppressed} catch-all suppressed)" if suppressed else "")
        )
        if done_total == 0:
            self.print_error(f"{host}:{port} -- no requests completed (host down?)")
            return

        store = getattr(self.framework, "store", None)
        if store is not None and found_all:
            store.add_service(host, port, name=scheme)
            content = "\n".join(
                f"{status} {size:>8}b {path}"
                for status, size, path, _loc, _sm in sorted(found_all)
            )
            loot_id = store.add_loot(
                "web-dirs", f"dirbuster {host}:{port}", content, address=host
            )
            self.print_status(f"Findings saved as loot {loot_id} ('loot -i {loot_id}')")

    def _scan_level(self, probe, paths, codes, wildcard):
        """One breadth level: probe every path, filter catch-all families
        BEFORE printing (the SPA flood never reaches the screen), and
        return (found, attempted)."""
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
                if resp is None or not is_interesting(resp, codes, wildcard):
                    continue
                validator = validator_for(path)
                if validator is not None and resp.sample and \
                        not validator(resp.sample):
                    base = path.rstrip("/").rsplit("/", 1)[-1]
                    self.print_debug(
                        f"{path}: {resp.status} but fails {base} content "
                        f"validation — catch-all page, suppressed")
                    continue
                found.append((resp.status, resp.size, path, resp.location,
                              resp.sample))
        except KeyboardInterrupt:
            self.print_warning(f"Interrupted after {done}/{len(paths)} requests")
        finally:
            pool.shutdown(wait=False, cancel_futures=True)
        for family in find_families(found):
            status, size, path, _loc, _sample = family[0]
            self.print_warning(
                f"suppressing {len(family)} catch-all responses "
                f"({status}, ~{size}b, like {path})")
        killed = {item[2] for family in find_families(found)
                  for item in family}
        survivors = [item for item in found if item[2] not in killed]
        for status, size, path, location, _sample in survivors:
            line = f"{status} {path} ({size}b)"
            if location:
                line += f" -> {location}"
            self.print_good(line)
        return survivors, done
