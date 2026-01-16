import winreg
import subprocess
import shlex

class ConfigAudit:
    def __init__(self, console, wmi_client):
        self.console = console
        self.wmi_client = wmi_client

    def audit_all(self):
        findings = []
        findings.extend(self.check_uac())
        findings.extend(self.check_firewall())
        findings.extend(self.check_unquoted_paths())
        return findings

    def check_uac(self):
        """Check if User Account Control is enabled."""
        findings = []
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", 0, winreg.KEY_READ)
            value, _ = winreg.QueryValueEx(key, "EnableLUA")
            winreg.CloseKey(key)
            
            if value == 0:
                findings.append({
                    "severity": "High",
                    "check": "User Account Control (UAC)",
                    "status": "FAIL",
                    "details": "UAC is disabled (EnableLUA=0). This allows programs to elevate privileges without prompting."
                })
            else:
                findings.append({
                    "severity": "Info",
                    "check": "User Account Control (UAC)",
                    "status": "PASS",
                    "details": "UAC is enabled."
                })
        except Exception as e:
            findings.append({"severity": "Error", "check": "UAC Check", "status": "ERROR", "details": str(e)})
        
        return findings

    def check_firewall(self):
        """Check Firewall Profiles state via netsh."""
        findings = []
        try:
            # Simple check via netsh
            output = subprocess.check_output("netsh advfirewall show allprofiles state", shell=True).decode(errors='ignore')
            
            # Count "ON" states
            on_count = output.upper().count("ON")
            
            # usually 3 profiles (Domain, Private, Public)
            if on_count < 3:
                findings.append({
                    "severity": "Medium",
                    "check": "Windows Firewall",
                    "status": "WARN",
                    "details": f"Some firewall profiles appear to be OFF. output: {output.strip()}"
                })
            else:
                findings.append({
                    "severity": "Info",
                    "check": "Windows Firewall",
                    "status": "PASS",
                    "details": "All firewall profiles appear to be ON."
                })
        except Exception as e:
            findings.append({"severity": "Error", "check": "Firewall Check", "status": "ERROR", "details": str(e)})
        
        return findings

    def check_unquoted_paths(self):
        """
        Check for Unquoted Service Paths.
        Exploitable if path contains spaces and is not quoted.
        """
        findings = []
        if not self.wmi_client:
            return []
            
        try:
            services = self.wmi_client.Win32_Service()
            for service in services:
                if service.StartMode == "Auto" and service.PathName:
                    path = service.PathName
                    # Filter out system paths usually safe or quoted
                    if '"' not in path and ' ' in path:
                         # Exclude c:\windows\system32 entries usually, though technically if they have spaces they are bad.
                         # Most typically vulnerability is in Program Files
                         
                         # Check if path is actually vulnerable (executable exists inside a spaced folder)
                         findings.append({
                             "severity": "Medium",
                             "check": "Unquoted Service Path",
                             "status": "FAIL",
                             "details": f"Service '{service.Name}' has unquoted path with spaces: {path}"
                         })
        except Exception as e:
             findings.append({"severity": "Error", "check": "Unquoted Service Check", "status": "ERROR", "details": str(e)})
             
        if not any(f['check'] == "Unquoted Service Path" for f in findings):
             findings.append({
                    "severity": "Info",
                    "check": "Unquoted Service Path",
                    "status": "PASS",
                    "details": "No unquoted service paths detected in Auto-start services."
                })
        
        return findings
