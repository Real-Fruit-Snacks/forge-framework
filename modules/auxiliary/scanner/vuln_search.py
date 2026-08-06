"""Vulnerability/PoC search: SearchSploit + GitHub, scored and ranked.

Enumerate first, then ask "what works against this?" — the loop every
engagement actually runs. This module queries Exploit-DB (via the
searchsploit binary, when present) and the GitHub repo-search API in
parallel, merges the results, and ranks them with a relevance rubric:
service in title, exact/fuzzy version match, exploit-class keywords,
recency, PoC signal, EDB curated bonus.

Two modes: explicit SERVICE/VERSION, or store-driven (leave SERVICE
blank — every service in the evidence store with a name/info string is
searched, so `port_scan` banners feed it directly). Results land in
loot, ranked.

searchsploit and git are OPTIONAL externals (probed with `which`);
GitHub search works unauthenticated (rate-limited; GITHUB_TOKEN env
raises the ceiling). Scoring and version matching are adapted from
pwndex's rubric (ninjarobots/oscp).
"""

import difflib
import json
import os
import re
import shutil
import subprocess
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from core.module import AuxiliaryModule
from core.options import OptBool, OptInt, OptPassword, OptString

EXPLOIT_TYPES = {
    "rce": {"label": "Remote Code Execution",
            "keywords": {"rce", "remote code execution", "remote command",
                         "code exec", "command injection", "webshell",
                         "shell upload", "reverse shell"}},
    "lpe": {"label": "Local Privilege Escalation",
            "keywords": {"privilege escalation", "privesc", "lpe",
                         "local privilege", "local root",
                         "elevation of privilege", "eop", "suid",
                         "sudo exploit", "kernel exploit"}},
    "sqli": {"label": "SQL Injection",
             "keywords": {"sql injection", "sqli", "blind sql",
                          "union select"}},
    "lfi": {"label": "Local File Inclusion",
            "keywords": {"local file inclusion", "lfi", "path traversal",
                         "directory traversal", "arbitrary file"}},
    "ssrf": {"label": "Server-Side Request Forgery",
             "keywords": {"ssrf", "server-side request forgery"}},
    "auth": {"label": "Auth Bypass",
             "keywords": {"auth bypass", "authentication bypass",
                          "default password", "default creds",
                          "backdoor account"}},
    "dos": {"label": "Denial of Service",
            "keywords": {"denial of service", "dos", "crash", "poc dos"}},
    "xxe": {"label": "XXE",
            "keywords": {"xxe", "xml external entity"}},
}

VERSION_TOKEN_RE = re.compile(r"[\d]+(?:[._-][\w]+)*")
POC_WORDS = {"poc", "exploit", "rce", "shell", "privesc", "lpe",
             "injection", "bypass", "overflow"}


def version_score(a, b):
    return difflib.SequenceMatcher(None, a.lower(), b.lower()).ratio()


def version_matches(text, version, threshold=0.6):
    """Version string appears (exactly or fuzzily) in text."""
    if not version:
        return True
    if version.lower() in text.lower():
        return True
    tokens = VERSION_TOKEN_RE.findall(text)
    return any(version_score(t, version) >= threshold for t in tokens)


def relevance_score(result, service, version, type_key):
    """0-100 relevance. Adapted from pwndex's rubric."""
    score = 0.0
    svc = service.lower()
    ver = (version or "").lower()
    title = result["title"].lower()
    desc = (result.get("desc") or "").lower()
    combined = f"{title} {desc}"

    words = svc.split()
    if svc in title:
        score += 25
    elif all(w in title for w in words):
        score += 18
    elif any(w in title for w in words):
        score += 10
    elif svc in desc:
        score += 5

    if ver:
        if ver in title:
            score += 20
        elif ver in desc:
            score += 12
        else:
            tokens = VERSION_TOKEN_RE.findall(combined)
            best = max((version_score(t, ver) for t in tokens), default=0)
            if best >= 0.8:
                score += 10
            elif best >= 0.6:
                score += 5
    else:
        score += 8

    if type_key and type_key in EXPLOIT_TYPES:
        kws = EXPLOIT_TYPES[type_key]["keywords"]
        score += min(15, sum(1 for kw in kws if kw in combined) * 5)
    else:
        score += min(8, sum(1 for kw in POC_WORDS if kw in combined) * 2)

    updated = result.get("updated", "")
    if updated:
        import datetime
        try:
            age = (datetime.date.today()
                   - datetime.date.fromisoformat(updated[:10])).days
            score += 15 if age < 90 else 10 if age < 365 else 5 if age < 730 else 0
        except ValueError:
            pass

    stars = result.get("stars", 0)
    score += 10 if stars >= 500 else 6 if stars >= 100 else 3 if stars >= 10 else 0
    score += min(10, sum(2 for kw in POC_WORDS if kw in title) * 5)
    if result["kind"] == "searchsploit":
        score += 5
    return score


def fetch_searchsploit(service, version, type_key):
    """Query the searchsploit binary; [] when absent or failing."""
    if not shutil.which("searchsploit"):
        return []
    query = service + (f" {version}" if version else "")
    try:
        proc = subprocess.run(
            ["searchsploit", "--json", query],
            capture_output=True, text=True, timeout=30)
        data = json.loads(proc.stdout or "{}")
    except (subprocess.SubprocessError, json.JSONDecodeError):
        return []
    out = []
    for row in data.get("RESULTS_EXPLOIT", []):
        title = row.get("Title", "")
        if type_key and type_key in EXPLOIT_TYPES:
            kws = EXPLOIT_TYPES[type_key]["keywords"]
            if not any(kw in title.lower() for kw in kws):
                continue
        if not version_matches(title, version):
            continue
        out.append({"kind": "searchsploit", "title": title,
                    "desc": row.get("Type", "") + "/" + row.get("Platform", ""),
                    "url": f"https://www.exploit-db.com/exploits/{row.get('EDB-ID', '')}",
                    "updated": row.get("Date", ""), "stars": 0,
                    "edb": row.get("EDB-ID", "")})
    return out


def fetch_github(service, version, type_key, token=""):
    """GitHub repo search; [] on failure/rate-limit."""
    type_hint = type_key if type_key and type_key in EXPLOIT_TYPES else "exploit poc"
    queries = [f"{service} {version} {type_hint}".strip(),
               f"{service} CVE"]
    seen = set()
    out = []
    for q in queries:
        url = ("https://api.github.com/search/repositories?q="
               + urllib.parse.quote(q) + "&sort=updated&per_page=10")
        headers = {"Accept": "application/vnd.github+json",
                   "X-GitHub-Api-Version": "2022-11-28"}
        if not token:
            token = os.environ.get("GITHUB_TOKEN", "")
        if token:
            headers["Authorization"] = f"Bearer {token}"
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=20) as resp:
                data = json.loads(resp.read().decode())
        except Exception:
            continue
        for repo in data.get("items", []):
            full = repo.get("full_name", "")
            if full in seen:
                continue
            text = f"{repo.get('name', '')} {repo.get('description') or ''}"
            if not all(w in text.lower() for w in service.lower().split()[:1]):
                continue
            if not version_matches(text, version):
                continue
            seen.add(full)
            out.append({"kind": "github", "title": full,
                        "desc": repo.get("description") or "",
                        "url": repo.get("html_url", ""),
                        "updated": (repo.get("pushed_at") or "")[:10],
                        "stars": repo.get("stargazers_count", 0)})
    return out


def _service_version(text):
    """Banner string -> (service, version). Knows the common shapes:
    'Apache/2.4.49' (product/version), 'SSH-2.0-OpenSSH_9.2p1 ...',
    then a generic first-word + first-version-token fallback."""
    m = re.match(r"([A-Za-z][\w-]*)/([0-9][\w.]*)", text)
    if m:
        return m.group(1).lower(), m.group(2)
    m = re.search(r"openssh[_ ]([\w.]+)", text, re.IGNORECASE)
    if m:
        return "openssh", m.group(1)
    words = text.split()
    svc = words[0].lower().strip(":,") if words else ""
    version = next((w for w in words if VERSION_TOKEN_RE.fullmatch(w)), "")
    return svc, version


class VulnSearch(AuxiliaryModule):
    name = "Vulnerability / PoC Search"
    description = """
        Searches Exploit-DB (searchsploit binary, if installed) and the
        GitHub repo-search API for exploits against a SERVICE/VERSION,
        ranked by a relevance rubric (title/version/type match, recency,
        PoC signal, EDB bonus). TYPE narrows by exploit class. Leave
        SERVICE blank to search every named service in the store
        (port_scan's banners feed it). Set GITHUB_TOKEN to raise the
        API rate limit (falls back to the GITHUB_TOKEN env var). The
        token is masked in `show options`. Results looted ranked.
    """
    authors = ["you"]

    def register_options(self):
        self.options.add(OptString("SERVICE", default="",
                                   description="Service/product, e.g. 'apache' "
                                               "(blank = every named store service)"))
        self.options.add(OptString("VERSION", default="",
                                   description="Version string, e.g. '2.4.49'"))
        self.options.add(OptString("TYPE", default="",
                                   description="Exploit class: rce,lpe,sqli,lfi,"
                                               "ssrf,auth,dos,xxe (blank = any)"))
        self.options.add(OptPassword("GITHUB_TOKEN", default="",
                                     description="GitHub token for higher "
                                                 "search rate limits "
                                                 "(env GITHUB_TOKEN fallback)"))
        self.options.add(OptBool("NO_GITHUB", default=False,
                                 description="Skip the GitHub repo search"))
        self.options.add(OptBool("NO_SEARCHSPLOIT", default=False,
                                 description="Skip the searchsploit binary"))
        self.options.add(OptInt("LIMIT", default=10,
                                description="Results per service query"))

    def _queries(self):
        """[(service, version)] — explicit, or store-driven."""
        service = str(self.get_option("SERVICE") or "").strip()
        if service:
            return [(service, str(self.get_option("VERSION") or "").strip())]
        store = getattr(self.framework, "store", None)
        if store is None:
            return []
        queries = []
        for row in store.services():
            text = row["info"] or row["name"]
            if not text:
                continue
            svc, version = _service_version(text)
            if svc:
                queries.append((svc, version))
        return queries

    def run(self):
        type_key = str(self.get_option("TYPE") or "").strip().lower()
        if type_key and type_key not in EXPLOIT_TYPES:
            self.print_error(f"TYPE must be one of {sorted(EXPLOIT_TYPES)}")
            return
        queries = self._queries()
        if not queries:
            self.print_error("No service to search (set SERVICE, or run "
                             "port_scan first to populate the store)")
            return
        no_gh = bool(self.get_option("NO_GITHUB"))
        no_ss = bool(self.get_option("NO_SEARCHSPLOIT"))
        if not no_ss and not shutil.which("searchsploit"):
            self.print_status("searchsploit not installed — GitHub only")
        limit = int(self.get_option("LIMIT"))
        token = str(self.get_option("GITHUB_TOKEN") or "").strip()
        store = getattr(self.framework, "store", None)

        for service, version in queries:
            label = service + (f" {version}" if version else "")
            with ThreadPoolExecutor(max_workers=2) as pool:
                futures = []
                if not no_ss:
                    futures.append(pool.submit(fetch_searchsploit,
                                               service, version, type_key))
                if not no_gh:
                    futures.append(pool.submit(fetch_github,
                                               service, version, type_key, token))
                results = []
                for f in futures:
                    try:
                        results.extend(f.result())
                    except Exception as e:
                        self.print_debug(f"fetch failed: {e}")
            if not results:
                self.print_line(f"[-] {label}: no PoCs found")
                continue
            for r in results:
                r["score"] = relevance_score(r, service, version, type_key)
            results.sort(key=lambda r: -r["score"])
            self.print_status(f"{label}: {len(results)} candidate(s)")
            lines = []
            for r in results[:limit]:
                line = (f"[{r['score']:.0f}] {r['kind']}: {r['title']} "
                        f"({r['url']})")
                self.print_good(f"  {line}")
                lines.append(line)
            if store is not None:
                store.add_loot("vuln-search", f"pocs for {label}",
                               "\n".join(lines))
