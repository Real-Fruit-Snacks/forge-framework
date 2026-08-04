# Every-boot clock correction for the CA guest (ForgeLabTimeSync task).
#
# Why this exists: the QEMU RTC is not UTC (dockur feeds it host-local
# time) and the Windows image installs with a US Pacific timezone — the
# guest's UTC ends up hours off the DC's. Kerberos and certsvc's policy
# module then deny everything with ERROR_TIME_SKEW (0x80070576, which
# the CA misreports as "could not find required Active Directory
# information"). Setting the clock once is not enough — the RTC is
# re-seeded on every VM start.
#
# The fix: pin the guest to UTC and take the clock from the DC (Samba's
# net time answer is correct), retrying while the DC comes up, then
# restart certsvc so the policy module re-initializes against AD.
Set-TimeZone -Id 'UTC'
for ($i = 0; $i -lt 24; $i++) {
    & net time \\10.10.10.10 /set /y 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) { break }
    Start-Sleep -Seconds 10
}
if (Get-Service certsvc -ErrorAction SilentlyContinue) {
    Restart-Service certsvc -Force -ErrorAction Continue
}
