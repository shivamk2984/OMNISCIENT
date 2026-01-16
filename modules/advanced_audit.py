import os
import subprocess
import glob
import re

class AdvancedAuditor:
    def __init__(self, wmi_client=None):
        self.wmi_client = wmi_client

    def run_all_checks(self):
        findings = []
        findings.extend(self.audit_services())
        findings.extend(self.audit_processes()) # Enhanced
        findings.extend(self.audit_suspicious_files())
        findings.extend(self.audit_registry_security())
        findings.extend(self.audit_lsa_packages()) # New
        return findings

    def audit_services(self):
        findings = []
        dangerous_services = {
            "Spooler": {"risk": "High", "reason": "Print Spooler (PrintNightmare). Disable on DCs."},
            "TermService": {"risk": "Medium", "reason": "RDP Service. Ensure NLA is active."},
            "TlntSvr": {"risk": "Critical", "reason": "Telnet detected! (Unsecure)."},
            "XblAuthManager": {"risk": "Low", "reason": "Xbox Live Service (Bloatware)."}
        }

        if self.wmi_client:
            try:
                for srv_name, info in dangerous_services.items():
                    matches = self.wmi_client.Win32_Service(Name=srv_name)
                    if matches:
                        service = matches[0]
                        if service.State == "Running":
                            findings.append({
                                "severity": info['risk'],
                                "check": f"Service: {srv_name}",
                                "status": "FAIL",
                                "details": f"{info['reason']} (State: Running)"
                            })
            except Exception as e:
                pass
        return findings

    def audit_processes(self):
        """
        Scans running processes for suspicious anomalies.
        """
        findings = []
        if not self.wmi_client:
            return findings

        suspicious_paths = [r"c:\temp", r"c:\windows\temp", r"appdata"]
        
        try:
            for process in self.wmi_client.Win32_Process():
                path = process.ExecutablePath
                name = process.Name
                pid = process.ProcessId
                
                if not path:
                    continue

                path_lower = path.lower()
                for sus_path in suspicious_paths:
                    if sus_path in path_lower:
                        findings.append({
                            "severity": "High",
                            "check": "Suspicious Process Path",
                            "status": "WARN",
                            "details": f"Process {name} (PID: {pid}) running from suspicious path: {path}"
                        })
                
                if "mimikatz" in name.lower():
                     findings.append({
                            "severity": "Critical",
                            "check": "Malware Detection",
                            "status": "FAIL",
                            "details": f"Known malware process name detected: {name} (PID: {pid})"
                        })

        except Exception:
            pass
        return findings

    def audit_suspicious_files(self):
        findings = []
        suspicious_paths = [
            r"C:\ProgramData\*.exe",
            r"C:\Users\Public\*.exe",
            r"C:\Windows\Temp\*.exe"
        ]
        
        for p in suspicious_paths:
            try:
                files = glob.glob(p)
                for f in files:
                    findings.append({
                        "severity": "Medium",
                        "check": "Suspicious Binary",
                        "status": "WARN",
                        "details": f"Executable found in loose folder: {f}"
                    })
            except: pass
        return findings

    def audit_registry_security(self):
        import winreg
        findings = []
        
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\Installer", 0, winreg.KEY_READ)
            val, _ = winreg.QueryValueEx(key, "AlwaysInstallElevated")
            if val == 1:
                findings.append({
                    "severity": "Critical",
                    "check": "AlwaysInstallElevated",
                    "status": "FAIL",
                    "details": "AlwaysInstallElevated is ON. Massive PrivEsc risk."
                })
        except: pass

        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest", 0, winreg.KEY_READ)
            val, _ = winreg.QueryValueEx(key, "UseLogonCredential")
            if val == 1:
                findings.append({
                    "severity": "High",
                    "check": "WDigest Cached Creds",
                    "status": "FAIL",
                    "details": "WDigest UseLogonCredential=1. LSASS dumping risk."
                })
        except: pass

        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa", 0, winreg.KEY_READ)
            val, _ = winreg.QueryValueEx(key, "RunAsPPL")
            if val != 1:
                findings.append({
                    "severity": "Medium",
                    "check": "LSA Protection",
                    "status": "WARN",
                    "details": "RunAsPPL not enabled."
                })
        except: 
             findings.append({
                    "severity": "Medium",
                    "check": "LSA Protection",
                    "status": "WARN",
                    "details": "RunAsPPL not explicitly configured."
                })

        return findings

    def audit_lsa_packages(self):
        """
        Check for malicious LSA Security Packages (SSP Injection).
        """
        import winreg
        findings = []
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa", 0, winreg.KEY_READ)
            val, _ = winreg.QueryValueEx(key, "Security Packages")
            
            standard = ["kerberos", "msv1_0", "schannel", "wdigest", "tspkg", "pku2u"]
            
            current_pkgs = []
            if isinstance(val, list):
                current_pkgs = val
            elif isinstance(val, str):
                current_pkgs = val.split()
            
            for pkg in current_pkgs:
                if pkg.lower() not in standard:
                     findings.append({
                        "severity": "High",
                        "check": "LSA Security Packages",
                        "status": "WARN",
                        "details": f"Unknown LSA Security Package found: '{pkg}'. Potential SSP Injection persistence."
                    })
        except: pass
        return findings
