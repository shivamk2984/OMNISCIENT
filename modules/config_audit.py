import winreg
import subprocess
import shlex
import os

class ConfigAudit:
    def __init__(self, console, wmi_client):
        self.console = console
        self.wmi_client = wmi_client

    def audit_all(self):
        findings = []
        findings.extend(self.check_uac())
        findings.extend(self.check_firewall())
        findings.extend(self.check_unquoted_paths())
        findings.extend(self.check_always_install_elevated())
        findings.extend(self.check_lsa_protection())
        findings.extend(self.check_cached_logons())
        findings.extend(self.check_laps())
        findings.extend(self.check_smb_config())
        findings.extend(self.check_autologon())
        findings.extend(self.check_mcafee_configs())
        return findings

    def _get_reg_value(self, hive, subkey, value_name):
        try:
            key = winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ)
            value, _ = winreg.QueryValueEx(key, value_name)
            winreg.CloseKey(key)
            return value
        except FileNotFoundError:
            return None
        except Exception:
            return None

    def check_uac(self):
        """Check if User Account Control is enabled."""
        findings = []
        val = self._get_reg_value(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA")
        
        if val == 0:
            findings.append({
                "severity": "High",
                "check": "User Account Control (UAC)",
                "status": "FAIL",
                "details": "UAC is disabled (EnableLUA=0). PrivEsc potential."
            })
        else:
            findings.append({
                "severity": "Info",
                "check": "User Account Control (UAC)",
                "status": "PASS",
                "details": "UAC is enabled."
            })
        return findings

    def check_firewall(self):
        """Check Firewall Profiles state via netsh."""
        findings = []
        try:
            output = subprocess.check_output("netsh advfirewall show allprofiles state", shell=True).decode(errors='ignore')
            on_count = output.upper().count("ON")
            if on_count < 3:
                findings.append({
                    "severity": "Medium",
                    "check": "Windows Firewall",
                    "status": "WARN",
                    "details": f"Some firewall profiles appear to be OFF."
                })
            else:
                findings.append({
                    "severity": "Info",
                    "check": "Windows Firewall",
                    "status": "PASS",
                    "details": "All firewall profiles appear to be ON."
                })
        except:
             pass
        return findings

    def check_unquoted_paths(self):
        """Check for Unquoted Service Paths."""
        findings = []
        if not self.wmi_client: return []
        try:
            services = self.wmi_client.Win32_Service()
            for service in services:
                if service.StartMode == "Auto" and service.PathName:
                    path = service.PathName
                    if '"' not in path and ' ' in path and "system32" not in path.lower():
                         findings.append({
                             "severity": "Medium",
                             "check": "Unquoted Service Path",
                             "status": "FAIL",
                             "details": f"Service '{service.Name}' has unquoted path: {path}"
                         })
        except: pass
        return findings

    def check_always_install_elevated(self):
        """Impact: Critical PrivEsc if both HKLM and HKCU set this to 1."""
        findings = []
        hklm = self._get_reg_value(winreg.HKEY_LOCAL_MACHINE, r"Software\Policies\Microsoft\Windows\Installer", "AlwaysInstallElevated")
        hkcu = self._get_reg_value(winreg.HKEY_CURRENT_USER, r"Software\Policies\Microsoft\Windows\Installer", "AlwaysInstallElevated")
        
        if hklm == 1 or hkcu == 1:
            findings.append({
                "severity": "Critical",
                "check": "AlwaysInstallElevated",
                "status": "FAIL",
                "details": f"Windows Installer run-as-admin policy enabled! (HKLM: {hklm}, HKCU: {hkcu})"
            })
        else:
             findings.append({"severity": "Info", "check": "AlwaysInstallElevated", "status": "PASS", "details": "Policy not enabled."})
        return findings

    def check_lsa_protection(self):
        findings = []
        run_as_ppl = self._get_reg_value(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa", "RunAsPPL")
        if run_as_ppl != 1:
            findings.append({
                "severity": "High",
                "check": "LSA Protection (RunAsPPL)",
                "status": "WARN",
                "details": "LSA Protection is DISABLED. Mimikatz can easily dump credentials."
            })
        else:
            findings.append({"severity": "Info", "check": "LSA Protection", "status": "PASS", "details": "LSA Protection Enabled."})
        return findings

    def check_cached_logons(self):
        findings = []
        count = self._get_reg_value(winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", "CachedLogonsCount")
        count = int(count) if count is not None else 10 # Default is 10
        
        if count > 2:
            findings.append({
                "severity": "Medium",
                "check": "Cached Logon Count",
                "status": "WARN",
                "details": f"Excessive Cached Logons stored ({count}). Risk of hash extraction."
            })
        return findings

    def check_laps(self):
        findings = []
        # Check if AdmPwd.dll exists in System32 (Indicator of LAPS)
        laps_path = os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "System32", "AdmPwd.dll")
        if not os.path.exists(laps_path):
             findings.append({
                "severity": "High",
                "check": "LAPS (Local Admin Password Solution)",
                "status": "WARN",
                "details": "LAPS does not appear to be installed (AdmPwd.dll missing)."
            })
        else:
            findings.append({"severity": "Info", "check": "LAPS", "status": "PASS", "details": "LAPS installed."})
        return findings

    def check_smb_config(self):
        findings = []
        # SMBv1
        smb1 = self._get_reg_value(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "SMB1")
        if smb1 == 1:
             findings.append({"severity": "Critical", "check": "SMBv1 Status", "status": "FAIL", "details": "SMBv1 is ENABLED. Vulnerable to EternalBlue/Ghost."})
        
        # Signing
        signing = self._get_reg_value(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters", "RequireSecuritySignature")
        if signing != 1:
            findings.append({"severity": "Medium", "check": "SMB Signing", "status": "WARN", "details": "SMB Signing not enforced."})
            
        return findings

    def check_autologon(self):
        findings = []
        pwd = self._get_reg_value(winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", "DefaultPassword")
        if pwd:
            findings.append({
                "severity": "Critical",
                "check": "Autologon Credentials",
                "status": "FAIL",
                "details": "Cleartext Autologon password found in Registry!"
            })
        return findings

    def check_mcafee_configs(self):
        findings = []
        path = r"C:\ProgramData\McAfee\Common Framework\SiteList.xml"
        if os.path.exists(path):
            try:
                with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                    if "Password" in f.read():
                        findings.append({
                            "severity": "Critical",
                            "check": "McAfee SiteList.xml",
                            "status": "FAIL",
                            "details": "Found potential hardcoded McAfee password in SiteList.xml"
                        })
            except: pass
        return findings
