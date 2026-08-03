@echo off
REM dockur/windows executes C:\OEM\install.bat during the final setup phase.
powershell -NoProfile -ExecutionPolicy Bypass -File C:\OEM\net-fix.ps1
REM UAC token filtering: non-RID-500 local admins (labadmin is RID 1000)
REM get filtered tokens over the network — interfaces like atsvc (TSCH)
REM refuse them (rpc_s_access_denied). Enable the built-in RID-500
REM account with the lab password so TSCH/EPM-class modules have an
REM unfiltered principal.
net user Administrator /active:yes
net user Administrator Labpass2024!
