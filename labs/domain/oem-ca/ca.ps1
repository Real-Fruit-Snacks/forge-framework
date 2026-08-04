# Build an AD CS Enterprise Root CA on this server (labs/domain `ca`).
# Runs automatically via C:\OEM\install.bat during Windows setup.
#
# Two phases: install.bat runs this once; phase 1 joins the domain and
# reboots (domain membership only activates after a reboot), phase 2
# runs from a scheduled task and does the AD CS build.
#
# Hard-won requirements (each one cost real debugging time — don't
# regress them):
#   1. NO -IncludeManagementTools: dockur's 2022 is Server CORE; MMC
#      snap-ins don't exist and the flag fails the whole feature chain.
#   2. ADCS install runs with DOMAIN ADMIN creds: an Enterprise CA
#      writes forest-wide (Cert Publishers, Pre-Win2000 group, default
#      templates) and local admin / SYSTEM gets ERROR_ACCESS_DENIED.
#   3. Install-AdcsCertificationAuthority checks for a leftover key
#      container named after the CA (C:\ProgramData\Microsoft\Crypto\
#      Keys\<hash-named file>) and refuses "private key already exists"
#      on re-runs — the file is hash-named, so match by AGE, not name.
#   4. Server 2022 + Samba NEEDS the strong netlogon channel (all four
#      values = 1). The Win11-style RC4 relax (zeros) breaks 2022's
#      channel AT BIRTH — every domain logon then fails with "trust
#      relationship failed". Reset-ComputerMachinePassword post-join
#      renegotiates the channel with the strong values in force.
#   5. Publish templates via the registry Templates list and RESTART
#      certsvc: the CA caches template objects, so any template change
#      (publish or attribute edit) is invisible to enrollment until the
#      service restarts.
#   6. The VulnWeb template object already exists in the config NC
#      (ad-lab fixture) — ENRICH it in place; don't create it. Its SD
#      MUST carry an Authenticated-Users read ACE: without it the CA
#      can't read the object and reports "Element not found / Invalid
#      Template" at publish time. The Enroll right is an OBJECT ace —
#      (OA;;CR;<guid>;;DU), two semicolons before the SID; the plain-A
#      form is rejected as invalid SDDL.
#   7. msPKI-Template-Schema-Version must be 1. ABSENT, the policy
#      module denies enrollment with CERTSRV_E_UNSUPPORTED_TEMPLATE
#      ("not supported by the AD CS policy") even though the template
#      publishes; 2, without the full v2 apparatus (RA policies, CSP
#      list), fails publish-time validation. VulnWeb is a v1 template —
#      the same class as the stock Web Server template ESC1 abuses.
#   8. msPKI-Enrollment-Flag = 0: bit 0x2 is CT_FLAG_PEND_ALL_REQUESTS
#      (manager approval) — requests pend instead of issuing, which
#      breaks ESC1's auto-issuance requirement.
#   9. The guest clock must be UTC-pinned AND synced from the DC
#      (timesync.ps1, every boot). The QEMU RTC is seeded from
#      host-local time and the image's timezone is US Pacific; left
#      alone, certsvc's policy module denies every request with
#      0x80070576 ERROR_TIME_SKEW (misreported as "could not find
#      required Active Directory information"). NEVER "fix" it with
#      Set-Date (Get-Date).ToUniversalTime() — that writes the TZ
#      offset into the RTC and poisons every later boot.

$ErrorActionPreference = 'Continue'
$marker = 'C:\OEM\phase2.marker'

# --- netlogon + firewall (both phases; idempotent) ----------------------
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

# every-boot clock correction (see oem-ca/timesync.ps1 for the why —
# ERROR_TIME_SKEW breaks certsvc's policy module otherwise)
$tsAction = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument (
    '-NoProfile -ExecutionPolicy Bypass -File C:\OEM\timesync.ps1')
Register-ScheduledTask -TaskName 'ForgeLabTimeSync' -Action $tsAction `
    -Trigger (New-ScheduledTaskTrigger -AtStartup) -Principal $fixPrincipal -Force

# --- clock, before anything Kerberos touches the DC --------------------
# Pin the guest to UTC and take the clock from the DC. NEVER the old
# "Set-Date (Get-Date).ToUniversalTime()" trick: with a non-UTC guest
# timezone that writes the TZ offset INTO the RTC, and every later boot
# is skewed by exactly that offset (the 0x80070576 ERROR_TIME_SKEW that
# cost a day of CA debugging).
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

$pw   = ConvertTo-SecureString 'P@ssw0rd123' -AsPlainText -Force
$cred = New-Object PSCredential('FORGE\Administrator', $pw)

# ======================================================================
# Phase 1: join + reboot
# ======================================================================
if (-not (Test-Path $marker)) {
    $joined = $false
    for ($i = 0; $i -lt 12; $i++) {
        try {
            Add-Computer -DomainName 'forge.local' -Credential $cred -Force -ErrorAction Stop
            $joined = $true
            break
        } catch {
            Start-Sleep -Seconds 10
        }
    }
    if (-not $joined) {
        'Domain join failed — ADCS install will not run.' |
            Out-File -FilePath C:\OEM\JOIN-FAILED.txt
        exit 1
    }
    # resume into phase 2 after the reboot that domain membership needs
    'phase2' | Out-File -FilePath $marker
    $p2Action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument (
        '-NoProfile -ExecutionPolicy Bypass -File C:\OEM\ca.ps1')
    Register-ScheduledTask -TaskName 'ForgeLabCAPhase2' -Action $p2Action `
        -Trigger (New-ScheduledTaskTrigger -AtStartup) `
        -Principal $fixPrincipal -Force
    Restart-Computer -Force
    exit 0
}

# ======================================================================
# Phase 2: AD CS build (runs as SYSTEM from the AtStartup task)
# ======================================================================

# wait for the domain to be reachable after the reboot
for ($i = 0; $i -lt 60; $i++) {
    if (Resolve-DnsName 'forge.local' -ErrorAction SilentlyContinue) { break }
    Start-Sleep -Seconds 5
}

# renegotiate the secure channel with the strong netlogon values in
# force (see note 4)
Reset-ComputerMachinePassword -Credential $cred -ErrorAction Continue

# --- leftover key container cleanup (re-runs) ---------------------------
Get-ChildItem 'C:\ProgramData\Microsoft\Crypto\Keys' -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -notmatch 'TSSecKeySet1' } |
    ForEach-Object { Remove-Item $_.FullName -Force -ErrorAction Continue }

# --- the feature (Server Core: NO -IncludeManagementTools) -------------
Install-WindowsFeature ADCS-Cert-Authority | Out-String

# --- the CA itself, as DOMAIN ADMIN ------------------------------------
try {
    Install-AdcsCertificationAuthority -CAType EnterpriseRootCA `
        -CACommonName 'forge-CA' -Credential $cred -Force -ErrorAction Stop | Out-String
} catch {
    "Install-AdcsCertificationAuthority: $($_.Exception.Message)" |
        Out-File -FilePath C:\OEM\CA-INSTALL-FAILED.txt
    exit 1
}

# --- enrich the fixture VulnWeb into a full ESC1 template --------------
# Field set verified by bisecting certutil -SetCATemplates + live
# enrollment against this exact build (see notes 6-8).
$type = [type]'System.DirectoryServices.DirectoryEntry'
$up = $cred.UserName
$pwd = $cred.GetNetworkCredential().Password
$target = New-Object $type (
    'LDAP://CN=VulnWeb,CN=Certificate Templates,CN=Public Key Services,' +
    'CN=Services,CN=Configuration,DC=forge,DC=local'), $up, $pwd
if ($target.Guid) {
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
        pKIExtendedKeyUsage = '1.3.6.1.5.5.7.3.2'
        'msPKI-Certificate-Application-Policy' = '1.3.6.1.5.5.7.3.2'
        pKIDefaultKeySpec = 1
        pKIMaxIssuingDepth = 0
    }
    foreach ($k in $props.Keys) { $target.Properties[$k].Value = $props[$k] }
    $target.Put('pKIKeyUsage', [byte[]](0xa0, 0x00))
    $target.Put('pKIExpirationPeriod',
                [byte[]](0x00, 0x40, 0x39, 0x87, 0x2e, 0xe1, 0xfe, 0xff))
    $target.Put('pKIOverlapPeriod',
                [byte[]](0x00, 0x80, 0xa6, 0x0a, 0xff, 0xde, 0xff, 0xff))
    # DA/SY/EA full, Authenticated-Users READ (note 6), Domain-Users Enroll
    $sddl = ('O:DAG:DAD:(A;;FA;;;DA)(A;;FA;;;SY)(A;;0x20094;;;AU)' +
             '(A;;FA;;;EA)' +
             '(OA;;CR;0e10c968-78fb-11d2-90d4-00c04f79dc55;;DU)')
    $target.ObjectSecurity.SetSecurityDescriptorSddlForm($sddl)
    $target.CommitChanges()
}

# --- publish on the CA (registry + restart — see note 5) ---------------
$policyKey = "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\forge-CA\Policy"
if (Test-Path $policyKey) {
    $current = @((Get-ItemProperty -Path $policyKey -Name Templates -ErrorAction SilentlyContinue).Templates)
    foreach ($tmpl in @('VulnWeb', 'WeakWeb')) {
        if ($current -notcontains $tmpl) {
            Set-ItemProperty -Path $policyKey -Name Templates -Value ($current + $tmpl)
            $current = @($current + $tmpl)
        }
    }
    Restart-Service certsvc -ErrorAction Continue
    Start-Sleep -Seconds 5
}

$svc = Get-Service certsvc -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq 'Running') {
    # ascii on purpose: Out-File's UTF-16 default breaks byte compares
    'ready' | Out-File -FilePath C:\OEM\CA-READY.txt -Encoding ascii
} else {
    'certsvc not running after install' | Out-File -FilePath C:\OEM\CA-SVC-FAILED.txt -Encoding ascii
}

# one-shot task done — don't run the build again on later boots
Unregister-ScheduledTask -TaskName 'ForgeLabCAPhase2' -Confirm:$false `
    -ErrorAction SilentlyContinue
Remove-Item $marker -Force -ErrorAction SilentlyContinue
