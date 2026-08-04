"""MSSQL recon: version, roles, databases, linked servers.

The read-only opener for the MSSQL attack surface: connect with SQL or
Windows creds and map what's there — version, whether your login is
sysadmin (the gate for xp_cmdshell), the databases, and the linked
servers (the pivot points for chain exec). impacket's TDS client does
the wire work; SQL auth and Windows (domain) auth both supported.
"""

from core.module import AuxiliaryModule
from core.options import OptAddress, OptPort, OptString

try:
    from impacket import tds
except ImportError:
    tds = None  # console gates run() on requirements


def open_connection(host, port, database, user, password, domain="",
                    windows_auth=False, timeout=15):
    ms_sql = tds.MSSQL(host, port)
    ms_sql.connect(timeout=timeout)
    ms_sql.login(database, user, password, domain, None, windows_auth)
    return ms_sql


class MssqlEnum(AuxiliaryModule):
    name = "MSSQL Enum (roles, databases, links)"
    description = """
        Maps an MSSQL instance: version, whether your login is
        sysadmin (the xp_cmdshell gate), the databases, the server
        logins, and the linked servers (chain pivots). SQL auth by
        default; set DOMAIN for Windows auth.
    """
    authors = ["you"]
    requirements = ["impacket"]

    def register_options(self):
        self.options.add(OptAddress("RHOSTS", required=True,
                                    description="Target(s), comma-separated"))
        self.options.add(OptPort("RPORT", default=1433, description="MSSQL port"))
        self.options.add(OptString("DATABASE", default="master",
                                   description="Initial database"))
        self.options.add(OptString("USERNAME", required=True,
                                   description="Login (sa or a Windows user)"))
        self.options.add(OptString("PASSWORD", required=True,
                                   description="Password"))
        self.options.add(OptString("DOMAIN", default="",
                                   description="Domain for Windows auth "
                                               "(blank = SQL auth)"))

    def run(self):
        database = str(self.get_option("DATABASE"))
        user = str(self.get_option("USERNAME"))
        password = str(self.get_option("PASSWORD"))
        domain = str(self.get_option("DOMAIN") or "")
        for host in [h.strip() for h in str(self.get_option("RHOSTS")).split(",")
                     if h.strip()]:
            self._enum(host, int(self.get_option("RPORT")), database,
                       user, password, domain)

    def _enum(self, host, port, database, user, password, domain):
        try:
            ms_sql = open_connection(host, port, database, user, password,
                                     domain, bool(domain))
        except Exception as e:
            self.print_error(f"{host}:{port}: login failed - {e}")
            return
        try:
            rows = self._query(ms_sql, "SELECT @@VERSION")
            version = rows[0][0].splitlines()[0] if rows else "unknown"
            self.print_good(f"{host}:{port}: {version}")

            rows = self._query(ms_sql, "SELECT IS_SRVROLEMEMBER('sysadmin')")
            sysadmin = rows and rows[0][0] == 1
            note = "SYSADMIN" if sysadmin else "not sysadmin"
            if sysadmin:
                self.print_good(f"{host}:{port}: {user} is {note} — "
                                f"xp_cmdshell is reachable")
            else:
                self.print_status(f"{host}:{port}: {user} is {note}")
            store = getattr(self.framework, "store", None)
            if store is not None:
                store.add_cred(host, "mssql", user, password,
                               source="mssql_enum")
                if sysadmin:
                    store.add_service(host, port, "mssql", version,
                                      info="sysadmin")

            rows = self._query(ms_sql,
                               "SELECT name, state_desc FROM sys.databases")
            self.print_status(f"{host}:{port}: {len(rows)} database(s):")
            for name, state in rows:
                self.print_line(f"  {name} ({state})")

            rows = self._query(
                ms_sql,
                "SELECT name, type_desc FROM sys.server_principals "
                "WHERE type_desc IN ('SQL_LOGIN', 'WINDOWS_LOGIN', "
                "'WINDOWS_GROUP') ORDER BY name")
            self.print_status(f"{host}:{port}: {len(rows)} login(s):")
            for name, kind in rows:
                self.print_line(f"  {name} [{kind}]")

            rows = self._query(
                ms_sql,
                "SELECT name, product, provider, data_source "
                "FROM sys.servers WHERE is_linked = 1")
            if rows:
                self.print_status(f"{host}:{port}: {len(rows)} linked "
                                  f"server(s) — chain pivots:")
                for name, product, provider, source in rows:
                    self.print_line(f"  {name} -> {source} ({provider})")
                    if store is not None:
                        store.add_note(host, "mssql-link",
                                       f"{name} -> {source}")
            else:
                self.print_status(f"{host}:{port}: no linked servers")
        finally:
            try:
                ms_sql.socket.close()
            except Exception:
                pass

    def _query(self, ms_sql, statement):
        try:
            return [tuple(row) for row in
                    ms_sql.RunSQLQuery("master", statement, tuplemode=True)]
        except Exception as e:
            self.print_error(f"query failed: {e}")
            return []
