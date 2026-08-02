# Getting Started

## Install

```bash
cd ~/coding/Projects/framework
./forge.py            # that's it — stdlib only
```

Or install it as a real command, isolated (the Arch-clean way):

```bash
pipx install .                                        # from the checkout
pipx install git+https://github.com/Real-Fruit-Snacks/forge-framework  # from the repo
forge
```

A pipx install sees only stdlib + whatever you `pipx inject` into it
(`pipx inject forge paramiko impacket pwntools` for the full module set).

Prerequisites for the full experience:

- **docker** (for labs and integration tests) — your user in the `docker`
  group; see [[Troubleshooting]] if `lab up` says permission denied.
- **paramiko** (`sudo pacman -S python-paramiko`) for `ssh_login`.
- **impacket** (project `.venv` or AUR) for `smb_enum`.
- **pwntools** (`sudo pacman -S python-pwntools`) for the shellcode payload.

Modules with missing dependencies still load — the console tells you what
to install when you try to `run` them. See [[Modules#requirements]].

## The core loop

```
forge > search port                          # find a module
forge > use auxiliary/scanner/port_scan      # load it
forge (auxiliary/scanner/port_scan) > show options
forge (auxiliary/scanner/port_scan) > set RHOSTS 10.10.10.10
forge (auxiliary/scanner/port_scan) > run
```

That's the whole mental model — same as Metasploit, on purpose. Everything
else is depth: `run -j` for background jobs, `sessions` for shells,
`creds`/`loot`/`report` for evidence, `lab up` for local targets.

## First five minutes with a real target

```bash
sudo systemctl start docker    # once per boot
./forge.py
```

```
forge > lab up web                            # local target, ~seconds
forge > use auxiliary/scanner/dir_buster
forge (auxiliary/scanner/dir_buster) > set RHOSTS 127.0.0.1
forge (auxiliary/scanner/dir_buster) > set RPORT 18080
forge (auxiliary/scanner/dir_buster) > set WORDLIST labs/web/wordlists/dirs.txt
forge (auxiliary/scanner/dir_buster) > set RECURSE true
forge (auxiliary/scanner/dir_buster) > run
forge (auxiliary/scanner/dir_buster) > loot -i 1     # your findings
forge (auxiliary/scanner/dir_buster) > lab down web
```

## Your first shell

Two consoles, one tool:

```
# console 1 — the listener
forge > use exploits/multi/handler
forge (exploits/multi/handler) > set LHOST 0.0.0.0
forge (exploits/multi/handler) > set LPORT 4444
forge (exploits/multi/handler) > run -j

# console 1 — generate the payload
forge (exploits/multi/handler) > use payloads/python_reverse_tcp
forge (payloads/python_reverse_tcp) > set LHOST 127.0.0.1
forge (payloads/python_reverse_tcp) > generate
```

Run the printed one-liner anywhere (another terminal works):
`[+] Session 1 opened` appears. `sessions -i 1` to interact,
`sessions -u 1` for the full pty upgrade. `jobs -k 1` stops the listener.

## Where things live

- Your data: `~/.forge/` (db, history, loot, logs, config) — see
  [[Data-and-Evidence]]
- Your modules: `~/.forge/modules/` (shadows bundled ones) — see
  [[Modules]]
- Docs: `wiki/` in the repo — you're reading them

Next: [[Console-Commands]] for the full reference, or [[Workflows]] to see
a full engagement pattern.
