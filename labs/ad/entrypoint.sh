#!/bin/bash
# Provision FORGE.LOCAL fresh on every start — labs are throwaway, and
# provisioning at build time fails on overlayfs (NT ACL xattrs), so it
# happens here at runtime with CAP_SYS_ADMIN granted in compose.yml.
#
# Fixtures (deterministic):
#   Administrator/P@ssw0rd123, analyst/Summer2024!,
#   backup_svc (kerberoastable SPN + unconstrained delegation),
#   web_svc (constrained delegation with protocol transition, and RBCD
#   delegate on backup_svc), sql_svc$ (gMSA — enumerable, but this Samba
#   build never constructs the managed password), guest-readable share
#   [shared].
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
# of a normal account (512) -> 4194816; plus PASSWD_NOTREQD (0x20) so the
# misconfig battery has a finding -> 4194848
samba-tool user create noauth 'Noauth2024!'
printf 'dn: CN=noauth,CN=Users,DC=forge,DC=local\nchangetype: modify\nreplace: userAccountControl\nuserAccountControl: 4194848\n' \
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
# gMSA fixture: Samba 4.17 hosts the object but has no KDS root key, so
# it can be ENUMERATED but msDS-ManagedPassword is never constructed —
# exactly the split the gmsa_dump module documents. Retrieval list is
# Builtin Administrators (SDDL BA).
printf 'dn: CN=sql_svc,CN=Managed Service Accounts,DC=forge,DC=local\nchangetype: add\nobjectClass: msDS-GroupManagedServiceAccount\nsAMAccountName: sql_svc$\nuserAccountControl: 4096\nmsDS-ManagedPasswordInterval: 30\nservicePrincipalName: HTTP/sql.forge.local\nmsDS-GroupMSAMembership: O:SYG:SYD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)\n' \
    > /tmp/gmsa.ldif
ldbadd -H /var/lib/samba/private/sam.ldb /tmp/gmsa.ldif
rm /tmp/gmsa.ldif
# LAPS fixture: schema lacks the LAPS attributes, so extend it. Samba
# refuses schema writes unless "dsdb:schema update allowed" is set —
# pass it as an ldb option (the schema_data ldb module checks this exact
# name; "dsdb:schema:allow updates" is a red herring from old wikis).
SCHEMA_OPT="dsdb:schema update allowed=yes"
cat > /tmp/laps.ldif <<'LDIF'
dn: CN=ms-Mcs-AdmPwd,CN=Schema,CN=Configuration,DC=forge,DC=local
changetype: add
objectClass: attributeSchema
lDAPDisplayName: ms-Mcs-AdmPwd
adminDisplayName: ms-Mcs-AdmPwd
attributeID: 1.2.840.113556.1.8000.2554.50051
attributeSyntax: 2.5.5.5
oMSyntax: 19
isSingleValued: TRUE
searchFlags: 904
showInAdvancedViewOnly: TRUE

dn: CN=ms-Mcs-AdmPwdExpirationTime,CN=Schema,CN=Configuration,DC=forge,DC=local
changetype: add
objectClass: attributeSchema
lDAPDisplayName: ms-Mcs-AdmPwdExpirationTime
adminDisplayName: ms-Mcs-AdmPwdExpirationTime
attributeID: 1.2.840.113556.1.8000.2554.50052
attributeSyntax: 2.5.5.16
oMSyntax: 65
isSingleValued: TRUE
searchFlags: 0
showInAdvancedViewOnly: TRUE
LDIF
ldbadd -H /var/lib/samba/private/sam.ldb --option="$SCHEMA_OPT" /tmp/laps.ldif
# allow the attributes on computer objects (a modify, so ldbmodify)
cat > /tmp/laps-class.ldif <<'LDIF'
dn: CN=Computer,CN=Schema,CN=Configuration,DC=forge,DC=local
changetype: modify
add: mayContain
mayContain: ms-Mcs-AdmPwd
-
add: mayContain
mayContain: ms-Mcs-AdmPwdExpirationTime

dn:
changetype: modify
add: schemaUpdateNow
schemaUpdateNow: 1
LDIF
ldbmodify -H /var/lib/samba/private/sam.ldb --option="$SCHEMA_OPT" /tmp/laps-class.ldif
printf 'dn: CN=WS01,CN=Computers,DC=forge,DC=local\nchangetype: add\nobjectClass: computer\nsAMAccountName: WS01$\nuserAccountControl: 4096\ndNSHostName: ws01.forge.local\nms-Mcs-AdmPwd: W0rkstation!2024\n' \
    > /tmp/laps-host.ldif
ldbadd -H /var/lib/samba/private/sam.ldb /tmp/laps-host.ldif
rm /tmp/laps.ldif /tmp/laps-class.ldif /tmp/laps-host.ldif
# PSO fixture: a weak fine-grained policy applying to Helpdesk — no
# lockout, 4-char minimum. The spray-target dream, and deterministic
# for ad_policies to find.
cat > /tmp/pso.ldif <<'LDIF'
dn: CN=WeakServicePSO,CN=Password Settings Container,CN=System,DC=forge,DC=local
changetype: add
objectClass: msDS-PasswordSettings
name: WeakServicePSO
msDS-PasswordSettingsPrecedence: 10
msDS-PasswordComplexityEnabled: TRUE
msDS-MinimumPasswordLength: 4
msDS-PasswordHistoryLength: 0
msDS-MinimumPasswordAge: 0
msDS-MaximumPasswordAge: -36288000000000
msDS-LockoutThreshold: 0
msDS-LockoutObservationWindow: -18000000000
msDS-LockoutDuration: -18000000000
msDS-PasswordReversibleEncryptionEnabled: FALSE
msDS-PSOAppliesTo: CN=Helpdesk,CN=Users,DC=forge,DC=local
LDIF
ldbadd -H /var/lib/samba/private/sam.ldb /tmp/pso.ldif
rm /tmp/pso.ldif
# subnet fixture: a registered site subnet for ad_infra to map
printf 'dn: CN=10.10.10.0/24,CN=Subnets,CN=Sites,CN=Configuration,DC=forge,DC=local\nchangetype: add\nobjectClass: subnet\nsiteObject: CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=forge,DC=local\n' \
    > /tmp/subnet.ldif
ldbadd -H /var/lib/samba/private/sam.ldb /tmp/subnet.ldif
rm /tmp/subnet.ldif
# DRSUAPI (DCSync) speaks ncacn_ip_tcp only: endpoint mapper on 135, then
# a dynamic RPC port. Pin the range so compose can publish it 1:1.
sed -i '/^\[global\]/a \   rpc server dynamic port range = 49152-49160' /etc/samba/smb.conf
printf '[shared]\n   path = /srv/shared\n   read only = yes\n   guest ok = yes\n' \
    >> /etc/samba/smb.conf
mkdir -p /srv/shared
echo 'flag{ad_l4b_sh4re}' > /srv/shared/readme.txt

exec samba -i -d3
