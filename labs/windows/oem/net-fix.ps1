# Lab networking for the windows lab: Windows guests mint a Public NLA
# profile on network change and the firewall then silently drops inbound
# SMB/RDP. Pin Private + open the firewall now, and on every boot via a
# scheduled task that waits for a profile to exist (a task that fires
# before the network does nothing; registering it needs a proper SYSTEM
# principal). Throwaway lab rules — never ship this anywhere real.

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
