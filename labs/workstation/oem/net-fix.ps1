# Lab networking for the workstation lab: Windows guests mint a Public
# NLA profile on network change and the firewall then silently drops
# inbound SMB/RDP. Pin Private + open the firewall now, and on every
# boot via a scheduled task that waits for a profile to exist (a task
# that fires before the network does nothing; registering it needs a
# proper SYSTEM principal). Throwaway lab rules — never ship anywhere real.

# Lab target hygiene: Win11's Defender kills the psexec pattern (service
# -> cmd chains) silently — every SCMR-class exec returns "no output".
# Server 2022 tolerates the same chain; the domain member's oem carries
# this same switch. The durable off is the GPO key, not Set-MpPreference
# (Defender self-heals that one within hours).
$wd = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
New-Item -Path $wd -Force | Out-Null
Set-ItemProperty -Path $wd -Name DisableAntiSpyware -Value 1 -Type DWord

# Enable the built-in Administrator (RID-500) with the lab password —
# remote atsvc/SMB work needs it: UAC token filtering denies non-RID-500
# local admins remotely, and dockur ships the account disabled.
net user Administrator /active:yes
net user Administrator Labpass2024!

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
