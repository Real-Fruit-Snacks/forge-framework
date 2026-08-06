# Build a STANDALONE Windows AD forest (wforge.local) on this server
# (labs/domain `windc`), with an AD CS Enterprise Root CA on the same
# box. Runs automatically via C:\OEM\install.bat during Windows setup.
#
# Why standalone instead of a replica DC in the Samba domain: dcpromo
# into the Samba domain fails twice, both verified against this build —
# the Adprep prerequisite dies unjoined ("unable to check the specified
# user's group membership — access denied, Adprep was unable to bind to
# any DC over RPC"), and from a joined box forestprep's LDIF schema
# update to the Samba schema master is denied with Ldap error 50
# (insufficient rights) even as Schema Admin: Samba refuses LDAP
# schema writes by default (dsdb:schema update allowed), and Windows
# adprep is not a supported schema path against Samba anyway (the
# supported route, samba-tool domain schemaupgrade, is experimental and
# caps at 2016/87, below Server 2022's 88). A standalone forest gives
# the real Windows KDC + DS that pkinit / relay_smb / rbcd need with
# zero experimental risk to the Samba fleet.
#
# What the unlock is FOR: the Samba DC has no PKINIT and refuses RBCD
# writes twice over — a real Windows KDC (PKINIT, KerberosAuthentication
# cert from this box's own CA) and a real Windows DS (RBCD writes
# accepted, machine-account self-write included) make pkinit, relay_smb
# and rbcd provable end to end.
#
# Two phases, the ca.ps1 shape: phase 1 builds the forest (reboots),
# phase 2 runs from a scheduled task: CA install, template publish,
# fixtures, sentinel.

$ErrorActionPreference = 'Continue'
$marker = 'C:\OEM\phase.marker'

# --- netlogon + firewall + timesync tasks (all phases; idempotent) ------
Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory Private
Set-NetFirewallProfile -All -Enabled False
$fixAction = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument (
    '-NoProfile -Command "while (-not (Get-NetConnectionProfile ' +
    '-ErrorAction SilentlyContinue)) { Start-Sleep -Seconds 5 }; ' +
    'Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory Private; ' +
    'Set-NetFirewallProfile -All -Enabled False"')
$fixPrincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' `
    -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName 'ForgeLabNetFix' -Action $fixAction `
    -Trigger (New-ScheduledTaskTrigger -AtStartup) -Principal $fixPrincipal -Force

$tsAction = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument (
    '-NoProfile -ExecutionPolicy Bypass -File C:\OEM\timesync.ps1')
Register-ScheduledTask -TaskName 'ForgeLabTimeSync' -Action $tsAction `
    -Trigger (New-ScheduledTaskTrigger -AtStartup) -Principal $fixPrincipal -Force

$resumeAction = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument (
    '-NoProfile -ExecutionPolicy Bypass -File C:\OEM\windc.ps1')
Register-ScheduledTask -TaskName 'ForgeLabDCResume' -Action $resumeAction `
    -Trigger (New-ScheduledTaskTrigger -AtStartup) `
    -Principal $fixPrincipal -Force

# --- clock: UTC-pinned, synced from the Samba DC (Kerberos dies on skew)
Set-TimeZone -Id 'UTC'
for ($i = 0; $i -lt 24; $i++) {
    & net time \\10.10.10.10 /set /y 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) { break }
    Start-Sleep -Seconds 10
}

$nl = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
Set-ItemProperty -Path $nl -Name RequireSignOrSeal    -Value 1 -Type DWord
Set-ItemProperty -Path $nl -Name RequireStrongKey     -Value 1 -Type DWord
Set-ItemProperty -Path $nl -Name SealSecureChannel    -Value 1 -Type DWord
Set-ItemProperty -Path $nl -Name SignSecureChannel    -Value 1 -Type DWord
Set-ItemProperty -Path $nl -Name DisablePasswordChange -Value 1 -Type DWord

$phase = ''
if (Test-Path $marker) { $phase = (Get-Content $marker -Raw).Trim() }

# ======================================================================
# Phase 1: the forest (reboots itself)
# ======================================================================
if ($phase -eq '') {
    # AD DS ONLY here: Install-ADDSForest refuses outright when
    # Certificate Services is already present (verified: "Certificate
    # Server is installed" prerequisite failure). Promote first, AD CS
    # second — and an Enterprise CA needs the domain to exist anyway.
    Install-WindowsFeature AD-Domain-Services | Out-String

    $safe = ConvertTo-SecureString 'SafeMode2024!' -AsPlainText -Force
    try {
        Install-ADDSForest -DomainName 'wforge.local' `
            -SafeModeAdministratorPassword $safe `
            -InstallDns:$true -Force:$true -ErrorAction Stop | Out-String
    } catch {
        "Install-ADDSForest: $($_.Exception.Message)" |
            Out-File -FilePath C:\OEM\FOREST-FAILED.txt
        exit 1
    }
    'phase2' | Out-File -FilePath $marker
    exit 0
}

# ======================================================================
# Phase 2: CA, template, fixtures, sentinel (runs as SYSTEM on the DC)
# ======================================================================

# wait for the local AD services after the promo reboot
for ($i = 0; $i -lt 60; $i++) {
    $kdc = Get-Service kdc -ErrorAction SilentlyContinue
    if ($kdc -and $kdc.Status -eq 'Running' -and
        (Resolve-DnsName 'wforge.local' -ErrorAction SilentlyContinue)) { break }
    Start-Sleep -Seconds 5
}

# deterministic forest-admin creds: the domain Administrator's post-promo
# password is whatever the local admin's was — reset it to a KNOWN value
# first (SYSTEM on a DC can reset domain account passwords)
$pw = ConvertTo-SecureString 'P@ssw0rd123' -AsPlainText -Force
Set-ADAccountPassword -Identity Administrator -Reset -NewPassword $pw `
    -ErrorAction Continue
Enable-ADAccount -Identity Administrator -ErrorAction Continue
$cred = New-Object PSCredential('WFORGE\Administrator', $pw)

# --- the CA: Enterprise Root on this DC -------------------------------
Install-WindowsFeature ADCS-Cert-Authority | Out-String
Get-ChildItem 'C:\ProgramData\Microsoft\Crypto\Keys' -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -notmatch 'TSSecKeySet1' } |
    ForEach-Object { Remove-Item $_.FullName -Force -ErrorAction Continue }
try {
    Install-AdcsCertificationAuthority -CAType EnterpriseRootCA `
        -CACommonName 'wforge-CA' -Credential $cred -Force -ErrorAction Stop | Out-String
} catch {
    "Install-AdcsCertificationAuthority: $($_.Exception.Message)" |
        Out-File -FilePath C:\OEM\CA-INSTALL-FAILED.txt
    exit 1
}

# KDC cert for PKINIT: publish the Kerberos templates and ask — on a
# stock CA the DC's auto-enrollment also fires on its own
& certutil -SetCATemplates +KerberosAuthentication 2>&1 | Out-String
& certutil -SetCATemplates +DomainControllerAuthentication 2>&1 | Out-String
Restart-Service certsvc -ErrorAction Continue

# --- the ESC1 template --------------------------------------------------
# The Samba lab's VulnWeb arrives as a fixture object; this forest has
# no fixture, so CREATE it when absent (stock Web Server shape), then
# apply the same verified field set either way
$type = [type]'System.DirectoryServices.DirectoryEntry'
$up = $cred.UserName
$pwd = $cred.GetNetworkCredential().Password
$target = New-Object $type (
    'LDAP://CN=VulnWeb,CN=Certificate Templates,CN=Public Key Services,' +
    'CN=Services,CN=Configuration,DC=wforge,DC=local'), $up, $pwd
if (-not $target.Guid) {
    $container = New-Object $type (
        'LDAP://CN=Certificate Templates,CN=Public Key Services,' +
        'CN=Services,CN=Configuration,DC=wforge,DC=local'), $up, $pwd
    $target = $container.Create('pKICertificateTemplate', 'CN=VulnWeb')
}
if ($target) {
    $props = @{
        displayName = 'VulnWeb'
        flags = 131648
        revision = 3
        'msPKI-Template-Schema-Version' = 1
        'msPKI-Template-Minor-Revision' = 1
        'msPKI-Certificate-Name-Flag' = 1
        'msPKI-Enrollment-Flag' = 0
        'msPKI-Private-Key-Flag' = 16842752
        'msPKI-Minimal-Key-Size' = 2048
        'msPKI-RA-Signature' = 0
        'msPKI-Cert-Template-OID' = '1.3.6.1.4.1.311.21.8.11828726.19999999'
        # Client Auth for ESC1 generic use; Smart Card Logon so the
        # issued cert works for PKINIT against a real Windows KDC.
        pKIExtendedKeyUsage = @('1.3.6.1.5.5.7.3.2',
                                '1.3.6.1.4.1.311.20.2.2')
        'msPKI-Certificate-Application-Policy' = @('1.3.6.1.5.5.7.3.2',
                                                   '1.3.6.1.4.1.311.20.2.2')
        pKIDefaultKeySpec = 1
        pKIMaxIssuingDepth = 0
    }
    foreach ($k in $props.Keys) { $target.Properties[$k].Value = $props[$k] }
    $target.Put('pKIKeyUsage', [byte[]](0xa0, 0x00))
    $target.Put('pKIExpirationPeriod',
                [byte[]](0x00, 0x40, 0x39, 0x87, 0x2e, 0xe1, 0xfe, 0xff))
    $target.Put('pKIOverlapPeriod',
                [byte[]](0x00, 0x80, 0xa6, 0x0a, 0xff, 0xde, 0xff, 0xff))
    # Commit the template object first; on a fresh forest the ACL set
    # fails during the same commit as Create() (the object ACE is
    # rejected with a null-valued expression), leaving the default ACL
    # that only DA/SY can enroll from.
    $target.CommitChanges()

    # AU read so the CA can publish the template; AU enroll so any
    # domain user (the test's analyst) can request ESC1 certs. The
    # old (A;;0x20094;;;AU) plain access mask is rejected as invalid
    # SDDL on a fresh 2022 forest and the template falls back to a
    # default ACL that only DA/SY can enroll from.
    $target = New-Object $type (
        'LDAP://CN=VulnWeb,CN=Certificate Templates,CN=Public Key Services,' +
        'CN=Services,CN=Configuration,DC=wforge,DC=local'), $up, $pwd
    $sddl = ('O:DAG:DAD:(A;;FA;;;DA)(A;;FA;;;SY)(A;;LCRPLORC;;;AU)' +
             '(A;;FA;;;EA)' +
             '(OA;;CR;0e10c968-78fb-11d2-90d4-00c04f79dc55;;AU)')
    $target.ObjectSecurity.SetSecurityDescriptorSddlForm($sddl)
    $target.CommitChanges()
}
& certutil -SetCATemplates +VulnWeb 2>&1 | Out-String
Restart-Service certsvc -ErrorAction Continue

# --- fixtures: the test user -------------------------------------------
$upw = ConvertTo-SecureString 'Summer2024!' -AsPlainText -Force
New-ADUser -Name 'analyst' -SamAccountName 'analyst' `
    -AccountPassword $upw -Enabled $true `
    -PasswordNeverExpires $true -ErrorAction Continue

# --- KDC cert enrollment (PKINIT needs it in the DC's store) -----------
$haveKdc = Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
    Where-Object { $_.EnhancedKeyUsageList.FriendlyName -match 'KDC' }
if (-not $haveKdc) {
    for ($i = 0; $i -lt 30; $i++) {
        try {
            Get-Certificate -Template 'KerberosAuthentication' `
                -CertStoreLocation Cert:\LocalMachine\My -ErrorAction Stop |
                Out-Null
            $haveKdc = Get-ChildItem Cert:\LocalMachine\My `
                -ErrorAction SilentlyContinue |
                Where-Object { $_.EnhancedKeyUsageList.FriendlyName -match 'KDC' }
            if ($haveKdc) { break }
        } catch {
            Start-Sleep -Seconds 20
        }
    }
}
if (-not $haveKdc) {
    'KDC cert not enrolled (PKINIT will refuse; check certsvc)' |
        Out-File -FilePath C:\OEM\KDCCERT-FAILED.txt
}

$kdc = Get-Service kdc -ErrorAction SilentlyContinue
$svc = Get-Service certsvc -ErrorAction SilentlyContinue
if ($kdc -and $kdc.Status -eq 'Running' -and
    $svc -and $svc.Status -eq 'Running') {
    # ascii on purpose: Out-File's UTF-16 default breaks byte compares
    'ready' | Out-File -FilePath C:\OEM\WINDC-READY.txt -Encoding ascii
} else {
    'kdc or certsvc not running after build' |
        Out-File -FilePath C:\OEM\WINDC-SVC-FAILED.txt -Encoding ascii
}

# one-shot task done — don't run the build again on later boots
Unregister-ScheduledTask -TaskName 'ForgeLabDCResume' -Confirm:$false `
    -ErrorAction SilentlyContinue
Remove-Item $marker -Force -ErrorAction SilentlyContinue
