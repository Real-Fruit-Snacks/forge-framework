# Every-boot clock correction for the windc guest (ForgeLabTimeSync
# task). Same why as the CA's: the QEMU RTC is not UTC and the image's
# timezone is US Pacific — Kerberos dies on skew. Pin UTC, take the
# clock from the DC, then bounce kdc so it re-reads its clock.
Set-TimeZone -Id 'UTC'
for ($i = 0; $i -lt 24; $i++) {
    & net time \\10.10.10.10 /set /y 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) { break }
    Start-Sleep -Seconds 10
}
if (Get-Service kdc -ErrorAction SilentlyContinue) {
    Restart-Service kdc -Force -ErrorAction Continue
}
