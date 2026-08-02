# Join this machine to FORGE.LOCAL (labs/domain). Runs automatically via
# C:\OEM\install.bat during Windows setup. Safe to re-run by hand from an
# elevated prompt if the join didn't take:
#   powershell -ExecutionPolicy Bypass -File C:\OEM\join.ps1

$joined = $false

# Samba-AD compatibility: relax Netlogon secure-channel requirements
# (Samba 4.17 doesn't implement every AES/sealing combination the modern
# Windows client insists on by default).
$nl = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
Set-ItemProperty -Path $nl -Name RequireSignOrSeal    -Value 0 -Type DWord
Set-ItemProperty -Path $nl -Name RequireStrongKey     -Value 0 -Type DWord
Set-ItemProperty -Path $nl -Name SealSecureChannel    -Value 0 -Type DWord
Set-ItemProperty -Path $nl -Name SignSecureChannel    -Value 0 -Type DWord
Set-ItemProperty -Path $nl -Name DisablePasswordChange -Value 1 -Type DWord

$pw   = ConvertTo-SecureString 'P@ssw0rd123' -AsPlainText -Force
$cred = New-Object PSCredential('FORGE\Administrator', $pw)

# The DC may still be provisioning when Windows setup reaches us — retry.
for ($i = 0; $i -lt 12; $i++) {
    try {
        Add-Computer -DomainName 'forge.local' -Credential $cred -Force -ErrorAction Stop
        $joined = $true
        break
    } catch {
        Start-Sleep -Seconds 10
    }
}

if ($joined) {
    shutdown /r /t 10 /f
} else {
    'Domain join failed after retries. Re-run C:\OEM\join.ps1 elevated, ' +
        'or join manually (see labs/domain/README.md).' |
        Out-File -FilePath C:\OEM\JOIN-FAILED.txt
}
