$baseDir = "tools"
if (!(Test-Path -Path $baseDir)) { New-Item -ItemType Directory -Path $baseDir | Out-Null }

Write-Host "[+] Downloading Safe Sysinternals Suite Components..." -ForegroundColor Cyan

$tools = @{
    "procdump.exe" = "https://live.sysinternals.com/procdump.exe";
    "autorunsc.exe" = "https://live.sysinternals.com/autorunsc.exe";
    "accesschk.exe" = "https://live.sysinternals.com/accesschk.exe";
    "handle.exe" = "https://live.sysinternals.com/handle.exe";
    "tcpview.exe" = "https://live.sysinternals.com/Tcpview.exe";
    "sigcheck.exe" = "https://live.sysinternals.com/sigcheck.exe";
    "whois.exe" = "https://live.sysinternals.com/whois.exe";
    "psloglist.exe" = "https://live.sysinternals.com/psloglist.exe"
}

foreach ($tool in $tools.Keys) {
    try {
        $out = "$baseDir\$tool"
        Invoke-WebRequest -Uri $tools[$tool] -OutFile $out
        Write-Host "    - $tool Downloaded" -ForegroundColor Green
    } catch {
        Write-Host "    ! Failed to download $tool" -ForegroundColor Red
    }
}

Write-Host "`n[!] ADVANCED / OFFENSIVE TOOLS REQUIRED" -ForegroundColor Yellow
Write-Host "For the full Omniscient Arsenal, you must manually populate the 'tools/' folder with these binaries:"
Write-Host " - Rubeus.exe (Kerberos Abuse)"
Write-Host " - winPEASx64.exe (Privilege Escalation)"
Write-Host " - Watson.exe (Vulnerability Scanner)"
Write-Host " - Certify.exe (AD CS Abuse)"
Write-Host " - SweetPotato.exe (PrivEsc)"
Write-Host " - mimikatz.exe (InfoSec Standard)"
Write-Host " - chisel.exe (Tunneling)"
Write-Host "`n[+] Download Script Completed."

Start-Sleep -Seconds 3
