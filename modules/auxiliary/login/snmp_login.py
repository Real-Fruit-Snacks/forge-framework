"""SNMP community string spray (v1/v2c), stdlib wire codec.

SNMP's auth model is a shared secret sent in the clear, and half the
network gear on earth answers "public" (read) or "private" (read-write).
The trap in spraying it: SNMP answers NOTHING for a wrong community —
a miss is indistinguishable from a dead host. This module reads silence
honestly: attempts are "possible" (inconclusive), never "no service",
and only an actual answer counts as valid. The engine's "possible"
verdict class exists for exactly this (core/brute.py).

The wire codec is core/snmp.py (BER GetRequest/GetResponse, shared with
the snmp lab's agent). sysDescr answers are captured as proof.
"""

import socket
import time

from core import snmp
from core.brute import brute_force
from core.module import AuxiliaryModule
from core.options import OptAddress, OptInt, OptPort, OptString
from core.wordlists import build_combos, creds_from_options

ERROR_CIRCUIT = 3  # consecutive transport errors before a host is skipped


class SnmpLogin(AuxiliaryModule):
    name = "SNMP Community Spray (v1/v2c)"
    description = """
        Tries community strings over SNMP v2c (and v1 with VERSION 1).
        Only a real sysDescr answer counts as valid — SNMP stays silent
        for wrong communities, so misses report as "possible"
        (inconclusive), never as proof of absence. Defaults are the
        classic trio (public/private/community); COMMUNITIES or
        COMMUNITY_FILE for more. Valid communities land in the store.
    """
    authors = ["you"]

    def register_options(self):
        self.options.add(OptAddress("RHOSTS", required=True,
                                    description="Target host(s), comma-separated"))
        self.options.add(OptPort("RPORT", default=161, description="SNMP port"))
        self.options.add(OptString("VERSION", default="2c",
                                   description="SNMP version: 1 or 2c"))
        self.options.add(OptString("COMMUNITIES", default="public,private,community",
                                   description="Community strings, comma-separated"))
        self.options.add(OptString("COMMUNITY_FILE", default="",
                                   description="File of community strings"))
        self.options.add(OptInt("THREADS", default=8,
                                description="Concurrent attempts"))
        self.options.add(OptInt("TIMEOUT", default=3,
                                description="Per-attempt answer wait (seconds)"))

    def _try(self, host, port, version, timeout, state, _user, community):
        """One GetRequest -> success | possible | error. UDP silence is
        "possible": wrong community OR dead host — SNMP won't tell us."""
        if state["abort"]:
            return None
        try:
            value = snmp.query(host, port, community, timeout=timeout,
                               version=version)
        except socket.timeout:
            # silence: wrong community OR dead host — SNMP won't tell us
            return "possible", "silence"
        except ConnectionRefusedError:
            # ICMP port-unreachable (docker-proxy / filtered port): the
            # network answered SOMETHING, but it still can't tell a wrong
            # community from a dead service — inconclusive
            return "possible", "port unreachable"
        except OSError as e:
            state["errors"] += 1
            if state["errors"] >= ERROR_CIRCUIT:
                state["abort"] = True
                state["dead"] = str(e)
            return "error", str(e)
        except ValueError as e:
            self.print_debug(f"{host}: malformed answer for {community}: {e}")
            return "possible", "malformed answer"
        if value is not None:
            return "success", value.decode("utf-8", "replace")[:80]
        return "possible", "silence"

    def run(self):
        version_text = str(self.get_option("VERSION")).lower()
        if version_text not in ("1", "2", "2c"):
            self.print_error("VERSION must be 1 or 2c")
            return
        version = 0 if version_text == "1" else 1
        try:
            raw = creds_from_options(self.get_option, "COMMUNITIES",
                                     "COMMUNITY_FILE")
        except OSError as e:
            self.print_error(f"Cannot read community file: {e}")
            return
        communities = [c.strip() for v in raw for c in v.split(",") if c.strip()]
        if not communities:
            self.print_error("Need at least one community string")
            return
        combos = list(build_combos(["snmp"], communities))
        self.print_status(f"{len(communities)} community string(s) to try")
        port = int(self.get_option("RPORT"))
        timeout = int(self.get_option("TIMEOUT"))
        for host in [h.strip() for h in str(self.get_option("RHOSTS")).split(",")
                     if h.strip()]:
            self._attack_host(host, port, version, timeout, combos)

    def _attack_host(self, host, port, version, timeout, combos):
        state = {"abort": False, "errors": 0, "dead": None}
        attempt = lambda u, c: self._try(host, port, version, timeout,  # noqa: E731
                                         state, u, c)
        classify = lambda verdict: verdict[0]  # noqa: E731

        def on_success(combo, result):
            self.print_good(f"{host}: community '{combo[1]}' — {result[1]}")

        started = time.time()
        found, attempts, errors, possibles = brute_force(
            combos, attempt, classify,
            threads=self.get_option("THREADS"),
            join_timeout=timeout + 2,
            on_success=on_success,
        )
        elapsed = max(time.time() - started, 0.001)
        if state["dead"]:
            self.print_warning(f"{host}: {ERROR_CIRCUIT} consecutive "
                               f"transport errors — host skipped")
        self.print_status(
            f"{host}: {attempts} attempts in {elapsed:.1f}s, "
            f"{len(found)} valid, {possibles} inconclusive "
            f"(silence proves nothing over UDP), {errors} errors")

        store = getattr(self.framework, "store", None)
        if store is not None and found:
            store.add_service(host, port, proto="udp", name="snmp")
            for _u, community in found:
                store.add_cred(host, "snmp", "snmp", community,
                               source="snmp-spray")
                self.print_status("Community saved ('creds' to view)")
