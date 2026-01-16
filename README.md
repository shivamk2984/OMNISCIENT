# OMNISCIENT

![Version](https://img.shields.io/badge/Version-1.0-white?style=for-the-badge&logo=windows)
![Platform](https://img.shields.io/badge/Platform-Windows-white?style=for-the-badge&logo=windows)
![License](https://img.shields.io/badge/License-GPLv3-white?style=for-the-badge&logo=gnu-bash)


**OMNISCIENT** is a high-precision digital forensics and red-team orchestration artifact for Windows environments. It unifies deep system reconnaissance, vulnerability analysis, and offensive tool management into a single, brutalist terminal interface.

> *"Visibility is absolute. Shadows are a myth."*

---

## 👁️ Capabilities

### 1. Total Sight (Deep Forensics)
OMNISCIENT sees what traditional tools miss by querying low-level Windows APIs (WMI, WinReg, Win32).
*   **Event Log Hunter**: Scans 20GB+ logs in seconds. Detects:
    *   Log Clearing (Event ID 1102)
    *   Obfuscated PowerShell Scripts (Event ID 4104)
    *   RDP Hijacking & Service Installations
*   **Live Connection Map**: Real-time correlation of TCP/UDP connections to owning Process IDs and Service Names. Found a connection to `192.168.x.x`? Omniscient tells you exactly which process started it.
*   **Physical Trace (USB)**: Recovers the complete history of every USB device ever connected to the machine (Serial Numbers, Friendly Names) from the Registry `USBSTOR` hive.

### 2. Total Recall (Persistence & Artifacts)
*   **Persistence Hunter**: Audits Run Keys, Startup Folders, and Scheduled Tasks for hidden malware hooks.
*   **Browser Forensics**: Extracts history and download logs to trace user activity or malware drops.
*   **Sensitive Data Audit**: Sweeps the disk for left-behind keys (`.pem`, `.ppk`, `.kdbx`) and config files.

### 3. Total Control (External Arsenal Bridge)
Stop managing 20 different tool windows. The **Arsenal Bridge** acts as a unified wrapper for your entire Red Team toolkit. Drop your binaries in `tools/`, and Omniscient manages the execution and reporting.
*   **Supported Integrations**: `Mimikatz`, `Rubeus`, `WinPEAS`, `Watson`, `Seatbelt`, `SharpHound`, `LaZagne`, `Chisel`, `Ligolo`, `PrintNightmare`, and full `Sysinternals Suite`.

---

## ⚡ Installation

1.  **Clone the Artifact**:
    ```powershell
    git clone https://github.com/shivamk2984/OMNISCIENT.git
    cd OMNISCIENT
    ```

2.  **Install Python Dependencies**:
    ```powershell
    pip install -r requirements.txt
    ```

3.  **Populate the Arsenal**:
    OMNISCIENT helps you fetch safe tools automatically.
    ```powershell
    powershell -ExecutionPolicy Bypass -File tools/download_tools.ps1
    ```
    *   *Note*: This script downloads Sysinternals (ProcDump, Autoruns).
    *   *Note*: for Offensive Tools (Mimikatz, Rubeus), you must manually place the `.exe` files in the `tools/` directory.

---

## ⚔️ Usage

Launch the console with administrative privileges for maximum visibility:

```powershell
python main.py
```

### The Interface

*   **System Recon**: OS Build, Hotfixes, Architecture.
*   **Config Hardening**: UAC, Firewall Profiles, Unquoted Paths.
*   **Deep Insight (Modules 10-12)**: Access the heavy forensic scanners.
*   **External Bridge (Option 8)**: Execute your loaded Red Team tools.
*   **Help / Manual (Option 9)**: In-tool documentation.
*   **INITIATE TOTAL AUDIT (Option 13)**: Runs EVERY module and generates a professional HTML report.

---

## 📂 Report Artifacts

Every scan generates a high-contrast, professional HTML report in the `reports/` folder.
*   **Theme**: Dark/Monochrome (Brutalist).
*   **Features**: Sortable DataTables, Risk Scoring, and Executive Summary.
*   **Format**: `Omniscient_Report_YYYYMMDD_HHMMSS.html`

---

## ⚠️ Disclaimer

**OMNISCIENT** is a security auditing tool. It is intended for:
1.  System Administrators securing their networks.
2.  Authorized Penetration Testers and Red Teamers.
3.  Forensic Analysts.

The misuse of this tool to scan targets without permission is illegal. The developers assume no liability for misuse.

---

*"Trust, but verify. Then verify again."*


