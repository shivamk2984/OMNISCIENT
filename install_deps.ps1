<#
.SYNOPSIS
    Robust dependency installer for OMNISCIENT.
    Attempts multiple methods to install Python requirements.

.DESCRIPTION
    This script installs the dependencies listed in requirements.txt.
    It handles missing pip, path issues, and python launcher variations.

.NOTES
    Author: codeinecasket
    Version: 1.0
#>

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ReqFile = Join-Path $ScriptDir "requirements.txt"

Write-Host "[*] OMNISCIENT Dependency Installer & Environment Prep" -ForegroundColor Cyan
Write-Host "[*] Target: $ReqFile" -ForegroundColor Gray

# 0. Check for Git and Auto-Install if missing
Write-Host "`n[*] Checking Environment..." -ForegroundColor Gray
try {
    $gitVersion = git --version 2>&1
    Write-Host "[+] Git found: $gitVersion" -ForegroundColor Green
}
catch {
    Write-Host "[!] Git not found. Auto-installing Portable Git (MinGit)..." -ForegroundColor Yellow
    $GitUrl = "https://github.com/git-for-windows/git/releases/download/v2.41.0.windows.1/MinGit-2.41.0-64-bit.zip"
    $BinDir = Join-Path $ScriptDir "bin"
    $GitZip = Join-Path $BinDir "mingit.zip"
    
    if (-not (Test-Path $BinDir)) { New-Item -ItemType Directory -Path $BinDir | Out-Null }
    
    # Check if we already have it to avoid redownloading loop
    if (-not (Test-Path $GitZip) -and -not (Test-Path (Join-Path $BinDir "cmd\git.exe"))) {
        try {
            Write-Host "    Downloading MinGit..." -NoNewline
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -Uri $GitUrl -OutFile $GitZip
            Write-Host "Done." -ForegroundColor Green
            
            Write-Host "    Extracting..." -NoNewline
            Expand-Archive -Path $GitZip -DestinationPath $BinDir -Force
            Remove-Item $GitZip -Force
            Write-Host "Done." -ForegroundColor Green
        }
        catch {
            Write-Host "`n[!] Download/Extract failed: $_" -ForegroundColor Red
        }
    }
        
    # PERSISTENT PATH UPDATE
    $GitCmdPath = Join-Path $BinDir "cmd"
    $CurrentPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if ($CurrentPath -notlike "*$GitCmdPath*") {
        Write-Host "    Adding Git to User PATH permanently..." -NoNewline
        [Environment]::SetEnvironmentVariable("Path", "$CurrentPath;$GitCmdPath", "User")
        $env:Path = "$GitCmdPath;$env:Path" # Apply to current session too
        Write-Host "Done." -ForegroundColor Green
    }
    else {
        Write-Host "    Git is already in User PATH." -ForegroundColor Gray
    }
}

# 5. Fix Sysinternals EULA (Prevents Hanging)
try {
    Write-Host "`n[*] Pre-Accepting Sysinternals EULA..." -ForegroundColor Gray
    $RegPath = "HKCU:\Software\Sysinternals"
    if (-not (Test-Path $RegPath)) { New-Item -Path $RegPath -Force | Out-Null }
    New-ItemProperty -Path $RegPath -Name "EulaAccepted" -Value 1 -PropertyType DWORD -Force | Out-Null
    Write-Host "[+] Sysinternals EULA globally accepted." -ForegroundColor Green
}
catch {
    Write-Host "[!] Failed to set EULA registry key. Tools might still prompt." -ForegroundColor Yellow
}

# 6. Check Python
try {
    $pyVersion = python --version 2>&1
    Write-Host "[+] Python found: $pyVersion" -ForegroundColor Green
}
catch {
    Write-Host "[!] 'python' command not found. Checking for 'py' launcher..." -ForegroundColor Yellow
    try {
        $pyVersion = py --version 2>&1
        Write-Host "[+] 'py' launcher found: $pyVersion" -ForegroundColor Green
    }
    catch {
        Write-Host "[CRITICAL] Python is not installed or not in PATH." -ForegroundColor Red
        Write-Host "Please install Python 3.x from python.org and check 'Add to PATH'."
        exit 1
    }
}

# 2. Define Installation Strategies
$strategies = @(
    # Strategy A: Standard 'pip'
    { pip install -r $ReqFile },
    
    # Strategy B: Python Module 'python -m pip'
    { python -m pip install -r $ReqFile },
    
    # Strategy C: Py Launcher 'py -m pip'
    { py -m pip install -r $ReqFile },

    # Strategy D: Explicit Python Executable (Last Resort)
    { 
        $pyPath = (Get-Command python -ErrorAction SilentlyContinue).Source
        if ($pyPath) { & $pyPath -m pip install -r $ReqFile }
        else { throw "Explicit python path not found" }
    }
)

# 3. Execute Strategies
$success = $false

foreach ($strategy in $strategies) {
    try {
        Write-Host "`n[*] Attempting installation strategy..." -ForegroundColor Gray
        & $strategy
        if ($LASTEXITCODE -eq 0) {
            $success = $true
            break
        }
    }
    catch {
        Write-Host "[-] Strategy failed. Trying next..." -ForegroundColor DarkGray
    }
}

# 4. Final verification
if ($success) {
    Write-Host "`n[+] Dependencies installed successfully!" -ForegroundColor Green
    Write-Host "[*] You can now run 'python main.py'" -ForegroundColor Cyan
}
else {
    Write-Host "`n[!] All installation strategies failed." -ForegroundColor Red
    Write-Host "Manual fix: Ensure 'pip' is installed and run 'pip install -r requirements.txt'"
}

Read-Host -Prompt "Press Enter to exit"
