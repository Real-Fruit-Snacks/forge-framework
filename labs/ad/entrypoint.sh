#!/bin/bash
# First boot: provision FORGE.LOCAL with CAP_SYS_ADMIN (build-time
# provisioning fails on overlayfs — NT ACL xattrs). The domain state
# lives on the ad-state volume: later boots skip the ~60s provision and
# the domain SID survives restarts (the domain lab's member keeps its
# trust relationship). `lab purge ad` reclaims the volume; fixture or
# entrypoint edits only take effect after a purge.
#
# Fixtures are reviewable LDIF files under fixtures/ (applied in name
# order; the extension picks the tool: .add.ldif -> ldbadd,
# .mod.ldif -> ldbmodify; __WEB_SID__ becomes web_svc's SID).
# Password-bearing accounts go through samba-tool below. The set:
#
#   analyst (Ana Lyst)     plain user / Helpdesk member  (ad_enum, ad_groups)
#   Helpdesk               group fixture + PSO target
#   backup_svc             kerberoastable, unconstrained delegation,
#                          RBCD target, password-in-description
#   web_svc                kerberoastable, constrained delegation + T2A4D
#   noauth                 DONT_REQUIRE_PREAUTH + PASSWD_NOTREQD
#   10  noauth UAC flags
#   20  backup_svc/web_svc delegation attributes
#   30  sql_svc$             gMSA (enumerable; no KDS key -> no password)
#   40+45+50               LAPS schema + computer class + WS01 cleartext
#   60  WeakServicePSO       weak fine-grained policy on Helpdesk
#   70                       site subnet 10.10.10.0/24
#   80  VulnWeb              ESC1-shaped certificate template
#   90                       BitLocker recovery key on WS01
#   Groups.xml             GPP cpassword (MS-published key) in SYSVOL
#   [shared]               guest-readable share with a flag
set -e

SAM=/var/lib/samba/private/sam.ldb
# schema writes need this exact option name (the "dsdb:schema:allow
# updates" spelling from old wikis is wrong)
SCHEMA_OPT="dsdb:schema update allowed=yes"

# fast path: a previous boot already provisioned onto the volume
if [ -f "$SAM" ]; then
    ln -sf /var/lib/samba/smb.conf /etc/samba/smb.conf
    exec samba -i -d3
fi

rm -f /etc/samba/smb.conf
rm -rf /var/lib/samba/private /var/lib/samba/sysvol

samba-tool domain provision --realm=FORGE.LOCAL --domain=FORGE \
    --server-role=dc --dns-backend=SAMBA_INTERNAL \
    --adminpass='P@ssw0rd123' --use-rfc2307

# --- accounts and groups (password-bearing, so samba-tool) ------------
samba-tool user create analyst 'Summer2024!' --given-name=Ana --surname=Lyst
samba-tool group create Helpdesk
samba-tool group addmembers Helpdesk analyst
samba-tool user create backup_svc 'Backup2024!' \
    --description='Nightly backup service (temp password: Backup2024!)'
samba-tool user setexpiry --noexpiry backup_svc
samba-tool spn add HTTP/web.forge.local backup_svc
samba-tool user create noauth 'Noauth2024!'
samba-tool user create web_svc 'Web2024!'
samba-tool user setexpiry --noexpiry web_svc
samba-tool spn add HTTP/intranet.forge.local web_svc

WEB_SID=$(ldbsearch -H "$SAM" '(sAMAccountName=web_svc)' objectSid \
    | awk '/^objectSid:/ {print $2}')

# --- LDIF fixtures, name-ordered; extension picks the tool ------------
for f in /fixtures/*.ldif; do
    case "$f" in
        *.add.ldif) tool=ldbadd ;;
        *.mod.ldif) tool=ldbmodify ;;
        *) echo "fixture with unknown tool extension: $f" >&2; exit 1 ;;
    esac
    sed "s/__WEB_SID__/$WEB_SID/g" "$f" \
        | "$tool" -H "$SAM" --option="$SCHEMA_OPT" /dev/stdin
done

# --- GPP fixture: cpassword XML in the Default Domain Policy ----------
# readable by every authenticated user, like real sysvol content
GPP_DIR="/var/lib/samba/sysvol/forge.local/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/Machine/Preferences/Groups"
mkdir -p "$GPP_DIR"
cp /fixtures/Groups.xml "$GPP_DIR/Groups.xml"
chmod -R a+rX "$GPP_DIR"

# --- smb.conf tuning ----------------------------------------------------
# DRSUAPI (DCSync) speaks ncacn_ip_tcp only: endpoint mapper on 135, then
# a dynamic RPC port. Pin the range so compose can publish it 1:1.
sed -i '/^\[global\]/a \   rpc server dynamic port range = 49152-49160' /etc/samba/smb.conf
# when the DC is a lab's DNS server (domain lab), it must also resolve
# the outside world — members download things through it
sed -i '/^\[global\]/a \   dns forwarder = 8.8.8.8' /etc/samba/smb.conf
printf '[shared]\n   path = /srv/shared\n   read only = yes\n   guest ok = yes\n' \
    >> /etc/samba/smb.conf
mkdir -p /srv/shared
echo 'flag{ad_l4b_sh4re}' > /srv/shared/readme.txt

# persist the finished smb.conf on the volume for fast-path boots
cp /etc/samba/smb.conf /var/lib/samba/smb.conf
ln -sf /var/lib/samba/smb.conf /etc/samba/smb.conf

exec samba -i -d3
