#!/bin/bash
# Provision FORGE.LOCAL fresh on every start — labs are throwaway, and
# provisioning at build time fails on overlayfs (NT ACL xattrs), so it
# happens here at runtime with CAP_SYS_ADMIN granted in compose.yml.
#
# Fixtures (deterministic):
#   Administrator/P@ssw0rd123, analyst/Summer2024!,
#   backup_svc (kerberoastable SPN + unconstrained delegation),
#   web_svc (constrained delegation with protocol transition, and RBCD
#   delegate on backup_svc), guest-readable share [shared].
set -e

rm -f /etc/samba/smb.conf
rm -rf /var/lib/samba/private /var/lib/samba/sysvol

samba-tool domain provision --realm=FORGE.LOCAL --domain=FORGE \
    --server-role=dc --dns-backend=SAMBA_INTERNAL \
    --adminpass='P@ssw0rd123' --use-rfc2307
samba-tool user create analyst 'Summer2024!' --given-name=Ana --surname=Lyst
# group fixture: a non-default group with a known member, so group
# enumeration has something deterministic to find
samba-tool group create Helpdesk
samba-tool group addmembers Helpdesk analyst
samba-tool user create backup_svc 'Backup2024!' \
    --description='Nightly backup service (temp password: Backup2024!)'
samba-tool user setexpiry --noexpiry backup_svc
samba-tool spn add HTTP/web.forge.local backup_svc
# asreproastable fixture: DONT_REQUIRE_PREAUTH (0x400000 = 4194304) on top
# of a normal account (512) -> 4194816
samba-tool user create noauth 'Noauth2024!'
printf 'dn: CN=noauth,CN=Users,DC=forge,DC=local\nchangetype: modify\nreplace: userAccountControl\nuserAccountControl: 4194816\n' \
    > /tmp/preauth.ldif
ldbmodify -H /var/lib/samba/private/sam.ldb /tmp/preauth.ldif
rm /tmp/preauth.ldif
# delegation fixtures:
#   backup_svc — unconstrained: normal account (512) + TRUSTED_FOR_DELEGATION
#     (0x80000) -> 524800; plus an RBCD rule letting web_svc impersonate
#     against it (msDS-AllowedToActOnBehalfOfOtherIdentity, an SDDL descriptor)
#   web_svc — constrained: msDS-AllowedToDelegateTo + protocol transition
#     (0x1000000 on top of 512 -> 16777728), with its own SPN so the
#     account is a realistic service principal
samba-tool user create web_svc 'Web2024!'
samba-tool user setexpiry --noexpiry web_svc
samba-tool spn add HTTP/intranet.forge.local web_svc
WEB_SID=$(ldbsearch -H /var/lib/samba/private/sam.ldb '(sAMAccountName=web_svc)' objectSid \
    | awk '/^objectSid:/ {print $2}')
printf 'dn: CN=backup_svc,CN=Users,DC=forge,DC=local\nchangetype: modify\nreplace: userAccountControl\nuserAccountControl: 524800\n-\nadd: msDS-AllowedToActOnBehalfOfOtherIdentity\nmsDS-AllowedToActOnBehalfOfOtherIdentity: O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;%s)\n\n' \
    "$WEB_SID" > /tmp/deleg.ldif
printf 'dn: CN=web_svc,CN=Users,DC=forge,DC=local\nchangetype: modify\nadd: msDS-AllowedToDelegateTo\nmsDS-AllowedToDelegateTo: HTTP/api.forge.local\n-\nreplace: userAccountControl\nuserAccountControl: 16777728\n' \
    >> /tmp/deleg.ldif
ldbmodify -H /var/lib/samba/private/sam.ldb /tmp/deleg.ldif
rm /tmp/deleg.ldif
# DRSUAPI (DCSync) speaks ncacn_ip_tcp only: endpoint mapper on 135, then
# a dynamic RPC port. Pin the range so compose can publish it 1:1.
sed -i '/^\[global\]/a \   rpc server dynamic port range = 49152-49160' /etc/samba/smb.conf
printf '[shared]\n   path = /srv/shared\n   read only = yes\n   guest ok = yes\n' \
    >> /etc/samba/smb.conf
mkdir -p /srv/shared
echo 'flag{ad_l4b_sh4re}' > /srv/shared/readme.txt

exec samba -i -d3
