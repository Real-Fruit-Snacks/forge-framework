@echo off
REM dockur/windows executes C:\OEM\install.bat during the final setup phase.
powershell -NoProfile -ExecutionPolicy Bypass -File C:\OEM\join.ps1
