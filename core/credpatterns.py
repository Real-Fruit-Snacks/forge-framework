"""Credential pattern corpus: regexes, tiers, and false-positive filtering.

Every org leaks credentials into files: web.config connection strings,
unattend.xml autologons, .env files, history files full of `net use`.
This module is the shared corpus for hunting them — pure data and logic,
no I/O, so every consumer (cred_hunt over SMB today, web/dir scanning
tomorrow) grades findings identically.

Three cooperating pieces:

  tier_filename(path)     — classify by NAME before any content read
                            (content reads cost a round trip over SMB):
                            CRITICAL proof containers (.kdbx/.ppk/.pfx/
                            .keytab), INTEREST (keys, .env, backups,
                            databases), NAME (password/secret/cred in
                            the filename)
  scan_text(name, text)   — per-line regex pass over file content,
                            gated per tier, returns (severity, label,
                            excerpt) hits
  looks_like_placeholder  — the FP filter: template variables, secret
                            references, already-encrypted wrappers, and
                            placeholder values are NOT findings

The corpus is curated from CredsHunter (NeCr00/Credential-Hunting) —
trimmed to high-signal patterns, translated to Python re.
"""

import re

# ---------------------------------------------------------------- tiers
CRITICAL_EXTS = {".kdbx", ".ppk", ".pfx", ".p12", ".keytab", ".jks"}
INTEREST_EXTS = {
    ".pem", ".key", ".p8", ".env", ".keystore", ".sqlite", ".sqlite3",
    ".db", ".mdb", ".accdb", ".bak", ".backup", ".old", ".pcap", ".rdg",
    ".rdp", ".kdb", ".csx", ".vnc", ".ovpn", ".ps1xml", ".clixml",
}
NAME_TOKENS = ("password", "passwd", "pwd", "secret", "credential",
               "creds", "unattend", "sysprep", "autologon", "htpasswd",
               "netrc", "id_rsa", "id_ed25519", "shadow", "ntds")

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "KEY": 2, "INTEREST": 1, "NAME": 0}


def tier_filename(path):
    """(severity, reason) for a share path, or None when uninteresting."""
    name = path.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
    stem, dot, ext = name.rpartition(".")
    ext = dot + ext if dot else ""
    if ext in CRITICAL_EXTS:
        return "CRITICAL", f"credential container ({ext})"
    if ext in INTEREST_EXTS:
        return "INTEREST", f"interesting file ({ext})"
    for token in NAME_TOKENS:
        if token in name:
            return "NAME", f"filename mentions {token}"
    return None


# ------------------------------------------------------- content patterns
# (label, severity, compiled regex) — applied per line.
def _c(label, severity, pattern, flags=re.IGNORECASE):
    return label, severity, re.compile(pattern, flags)


CRED_PATTERNS = [
    # generic k=v secrets
    _c("password assignment", "HIGH",
       r"(?:password|passwd|pwd)\s*[:=]\s*[\"']?([^\s\"',;]{4,})"),
    _c("connection string password", "HIGH",
       r"(?:password|pwd)\s*=\s*([^;\s]{4,})\s*;", re.IGNORECASE),
    _c("connection string user", "INTEREST",
       r"user\s*(?:id|name)?\s*=\s*([^;\s]{2,})\s*;"),
    _c("URL-embedded creds", "HIGH",
       r"[a-z][a-z0-9+.-]*://([^/\s:@]{1,64}):([^/\s@]{3,64})@[^/\s]+"),
    _c("GPP cpassword", "HIGH", r"cpassword\s*[=:]\s*[\"']?([A-Za-z0-9+/=]{8,})"),
    _c("unattend password value", "HIGH",
       r"<Password>.*?<Value>([^<]{3,})</Value>"),
    _c("AutoLogon registry password", "HIGH",
       r"DefaultPassword[\"']?\s*[=:]\s*[\"']?([^\s\"']{3,})"),

    # command-line credentials (history files, scripts)
    _c("net use with password", "HIGH",
       r"net\s+use\s+\S+\s+(\S+)\s+/user:\S+"),
    _c("net use alt order", "HIGH",
       r"net\s+use\s+/user:\S+\s+\S+\s+(\S+)"),
    _c("net user with password", "HIGH", r"net\s+user\s+\S+\s+(\S{3,})"),
    _c("mysql inline password", "HIGH", r"mysql\s+.*?-p(\S{3,})"),
    _c("sqlcmd inline password", "HIGH", r"sqlcmd\s+.*?-P\s+[\"']?([^\s\"']{3,})"),
    _c("sshpass", "HIGH", r"sshpass\s+-p\s+[\"']?([^\s\"']{3,})"),
    _c("sc config password", "HIGH", r"sc\s+\S*\s*config\s+\S+\s+password\s*=\s*(\S+)"),
    _c("schtasks runas password", "HIGH", r"schtasks\s+.*?/rp\s+(\S+)"),
    _c("cmdkey add", "HIGH", r"cmdkey\s+/add:\S+\s+/user:\S+\s+/pass:(\S+)"),
    _c("runas savecred", "INTEREST", r"runas\s+/savecred"),
    _c("curl --user", "HIGH", r"curl\s+.*?--user\s+[\"']?([^\s:\"']+:[^\s\"']+)"),
    _c("powershell plaintext password", "HIGH",
       r"(?:ConvertTo-SecureString|NetworkCredential)[^\n]{0,80}"
       r"-AsPlainText[^\n]{0,40}[\"']([^\"']{3,})[\"']"),

    # web framework configs
    _c("wp-config DB_PASSWORD", "HIGH", r"DB_PASSWORD[\"',\s)]+[\"']([^\"']{3,})[\"']"),
    _c("define() password", "HIGH",
       r"define\s*\(\s*[\"'][A-Z_]*(?:PASS|SECRET)[A-Z_]*[\"']\s*,\s*[\"']([^\"']{3,})[\"']"),
    _c("PDO/mysqli positional password", "HIGH",
       r"(?:mysqli|PDO)\s*\(\s*[\"'][^\"']+[\"']\s*,\s*[\"'][^\"']+[\"']\s*,\s*[\"']([^\"']{3,})[\"']"),

    # auth files
    _c("htpasswd entry", "HIGH", r"^\s*([^\s:#]{2,}:\$(?:apr1|2y|2a)\$[^\s:]+)"),
    _c("netrc password", "HIGH", r"machine\s+\S+.*?password\s+(\S+)"),
    _c("aws access key", "CRITICAL", r"\b(AKIA[0-9A-Z]{16})\b"),
    _c("aws secret key", "CRITICAL",
       r"(?i)aws.{0,20}(?:secret|key).{0,10}[\"']([0-9a-zA-Z/+]{40})[\"']"),
    _c("github token", "CRITICAL", r"\b((?:ghp|github_pat)_[0-9A-Za-z_]{20,})\b"),
    _c("slack token", "CRITICAL", r"\b(xox[baprs]-[0-9A-Za-z-]{10,})\b"),
    _c("stripe key", "CRITICAL", r"\b((?:sk|pk)_(?:live|test)_[0-9A-Za-z]{16,})\b"),

    # hashes (crackable)
    _c("NTLM hash line", "HIGH",
       r"^([^\s:]+:\d+:[0-9a-f]{32}:[0-9a-f]{32}:::)$"),
    _c("shadow hash", "HIGH", r"^([^\s:]+:\$[156y]\$[^\s:]+)"),
    _c("kerberoast hash", "HIGH", r"(\$krb5tgs\$\d+\$[^\s]+)"),
    _c("asrep hash", "HIGH", r"(\$krb5asrep\$\d+\$[^\s:]+)"),

    # private keys (multiline markers)
    _c("private key block", "CRITICAL",
       r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----"),
    _c("putty key file", "CRITICAL", r"PuTTY-User-Key-File-[23]:"),
]

TEXT_EXTS = {
    "", ".txt", ".xml", ".config", ".ini", ".cfg", ".conf", ".json",
    ".yaml", ".yml", ".env", ".properties", ".php", ".asp", ".aspx",
    ".jsp", ".ps1", ".bat", ".cmd", ".sh", ".bash", ".history", ".csv",
    ".reg", ".rdp", ".vnc", ".ovpn", ".sql", ".log",
}

UNATTEND_NAMES = {"unattend.xml", "sysprep.xml", "autounattend.xml"}


def is_text_candidate(path, max_size=None):
    """True when the filename looks like a text file worth a content read."""
    name = path.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
    _stem, dot, ext = name.rpartition(".")
    return (dot + ext if dot else "") in TEXT_EXTS


def looks_like_placeholder(value):
    """True when a matched 'secret' is a template/reference, not a value.

    The FP filter. We deliberately keep weak real passwords; we drop:
    template variables (${...}, <%= %>), secret references (getenv,
    keyvault, ${self.}), already-encrypted wrappers (ENC(), {cipher},
    $ANSIBLE_VAULT), and obvious placeholders (changeme, your_password).
    """
    v = value.strip().strip("\"'")
    low = v.lower()
    if not v or len(v) < 3:
        return True
    if low in {"password", "changeme", "changeit", "secret", "null",
               "none", "true", "false", "yes", "no", "todo", "xxx",
               "your_password", "yourpassword", "insert", "placeholder",
               "example", "sample", "test", "admin", "root"}:
        return True
    if v.startswith(("${", "<%", "{%", "{{", "%(", "$env", "env:")):
        return True
    if low.startswith(("getenv", "env.get", "os.environ", "system.getenv",
                       "self.", "this.", "keyvault", "vault:", "enc(",
                       "{cipher}", "{enc}", "$ansible_vault", "pbkdf2:")):
        return True
    if re.fullmatch(r"[x*•\-_=]+", v):
        return True
    if re.fullmatch(r"(.)\1{2,}", v):  # aaaa, 1111
        return True
    return False


def decode_maybe_utf16(data):
    """Bytes -> text, sniffing UTF-16 by NUL stride. .reg exports, task
    XML, and unicode logs are UTF-16 on Windows shares; counting NULs on
    even vs odd offsets beats the 'NUL means binary' naive check."""
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return data[2:].decode("utf-16-le", errors="replace")
    sample = data[:4096]
    if not sample:
        return ""
    even_nuls = sum(1 for i in range(0, len(sample) - 1, 2) if sample[i + 1] == 0
                    and sample[i] != 0)
    if even_nuls >= max(4, len(sample) // 8):
        return data.decode("utf-16-le", errors="replace")
    return data.decode("utf-8", errors="replace")


def scan_text(name, text, min_severity="INTEREST"):
    """Scan file content for credentials.

    Returns [(severity, label, excerpt)] with placeholders filtered and
    duplicates collapsed, best-first. min_severity gates the noise floor.
    """
    floor = SEVERITY_RANK[min_severity]
    hits = []
    seen = set()
    lines = text.splitlines()
    is_unattend = name.lower() in UNATTEND_NAMES
    for i, line in enumerate(lines):
        for label, severity, pattern in CRED_PATTERNS:
            if SEVERITY_RANK[severity] < floor:
                continue
            m = pattern.search(line)
            if not m:
                continue
            value = m.group(1) if m.groups() else m.group(0)
            if looks_like_placeholder(value):
                continue
            key = (label, value)
            if key in seen:
                continue
            seen.add(key)
            excerpt = line.strip()[:120]
            hits.append((severity, label, excerpt))
    if is_unattend and SEVERITY_RANK["HIGH"] >= floor:
        # autologon blocks span lines: <Password> ... <Value>x</Value>
        for m in re.finditer(
                r"<Password>\s*<Value>([^<]{3,})</Value>\s*</Password>",
                text, re.IGNORECASE | re.DOTALL):
            if not looks_like_placeholder(m.group(1)):
                hits.append(("HIGH", "unattend autologon password",
                             m.group(1)[:60]))
    hits.sort(key=lambda h: -SEVERITY_RANK[h[0]])
    return hits
