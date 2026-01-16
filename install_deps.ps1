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

Write-Host "[*] OMNISCIENT Dependency Installer" -ForegroundColor Cyan
Write-Host "[*] Target: $ReqFile" -ForegroundColor Gray

# 1. Check if Python is installed
try {
    $pyVersion = python --version 2>&1
    Write-Host "[+] Python found: $pyVersion" -ForegroundColor Green
} catch {
    Write-Host "[!] 'python' command not found. Checking for 'py' launcher..." -ForegroundColor Yellow
    try {
        $pyVersion = py --version 2>&1
        Write-Host "[+] 'py' launcher found: $pyVersion" -ForegroundColor Green
    } catch {
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
    } catch {
        Write-Host "[-] Strategy failed. Trying next..." -ForegroundColor DarkGray
    }
}

# 4. Final verification
if ($success) {
    Write-Host "`n[+] Dependencies installed successfully!" -ForegroundColor Green
    Write-Host "[*] You can now run 'python main.py'" -ForegroundColor Cyan
} else {
    Write-Host "`n[!] All installation strategies failed." -ForegroundColor Red
    Write-Host "Manual fix: Ensure 'pip' is installed and run 'pip install -r requirements.txt'"
}

Read-Host -Prompt "Press Enter to exit"
