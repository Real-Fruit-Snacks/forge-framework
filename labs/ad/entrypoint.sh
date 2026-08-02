#!/bin/bash
# Provision FORGE.LOCAL fresh on every start — labs are throwaway, and
# provisioning at build time fails on overlayfs (NT ACL xattrs), so it
# happens here at runtime with CAP_SYS_ADMIN granted in compose.yml.
#
# Fixtures (deterministic):
#   Administrator/P@ssw0rd123, analyst/Summer2024!,
#   backup_svc (kerberoastable SPN), guest-readable share [shared].
set -e

rm -f /etc/samba/smb.conf
rm -rf /var/lib/samba/private /var/lib/samba/sysvol

samba-tool domain provision --realm=FORGE.LOCAL --domain=FORGE \
    --server-role=dc --dns-backend=SAMBA_INTERNAL \
    --adminpass='P@ssw0rd123' --use-rfc2307
samba-tool user create analyst 'Summer2024!' --given-name=Ana --surname=Lyst
samba-tool user create backup_svc 'Backup2024!'
samba-tool user setexpiry --noexpiry backup_svc
samba-tool spn add HTTP/web.forge.local backup_svc
printf '[shared]\n   path = /srv/shared\n   read only = yes\n   guest ok = yes\n' \
    >> /etc/samba/smb.conf
mkdir -p /srv/shared
echo 'flag{ad_l4b_sh4re}' > /srv/shared/readme.txt

exec samba -i
