import winreg
import os
import subprocess
import csv
import io

class PersistenceAuditor:
    def __init__(self, console, wmi_client=None):
        self.console = console
        self.wmi_client = wmi_client

    def run_audit(self):
        findings = []
        self.console.print("[dim]   - Scanning Registry Run Keys...[/dim]")
        findings.extend(self.check_registry_run())
        
        self.console.print("[dim]   - Scanning Startup Folders...[/dim]")
        findings.extend(self.check_startup_folder())
        
        self.console.print("[dim]   - Analyzing Scheduled Tasks (This may take a moment)...[/dim]")
        findings.extend(self.check_scheduled_tasks())
        
        self.console.print("[dim]   - Checking Winlogon Helpers...[/dim]")
        findings.extend(self.check_winlogon_helpers())
        
        self.console.print("[dim]   - Checking Image File Execution Options (IFEO)...[/dim]")
        findings.extend(self.check_ifeo_backdoors())
        
        if self.wmi_client:
            self.console.print("[dim]   - Scanning WMI Event Persistence...[/dim]")
            findings.extend(self.check_wmi_persistence())
            
        return findings

    def check_registry_run(self):
        findings = []
        registry_locations = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run")
        ]

        suspicious_keywords = ["powershell", "cmd.exe", "wscript", "cscript", "temp", "appdata", "programdata", "users\\public"]

        for hive, subkey in registry_locations:
            try:
                key = winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ)
                count = winreg.QueryInfoKey(key)[1]
                for i in range(count):
                    name, value, _ = winreg.EnumValue(key, i)
                    
                    severity = "Info"
                    status = "INFO"
                    
                    if any(s in value.lower() for s in suspicious_keywords):
                        severity = "High"
                        status = "WARN"
                    
                    findings.append({
                        "severity": severity,
                        "check": "Registry Run Key",
                        "status": status,
                        "details": f"Key: {name} | Value: {value} | Path: {subkey}"
                    })
                winreg.CloseKey(key)
            except Exception:
                pass
        return findings

    def check_startup_folder(self):
        findings = []
        startup_paths = [
            os.path.join(os.getenv('APPDATA'), r"Microsoft\Windows\Start Menu\Programs\Startup"),
            os.path.join(os.getenv('PROGRAMDATA'), r"Microsoft\Windows\Start Menu\Programs\Startup")
        ]

        for path in startup_paths:
            if os.path.exists(path):
                try:
                    for file in os.listdir(path):
                        if file.lower() == "desktop.ini": 
                            continue
                            
                        filepath = os.path.join(path, file)
                        severity = "Info"
                        if file.endswith(".bat") or file.endswith(".vbs") or file.endswith(".ps1") or file.endswith(".exe"):
                            severity = "Medium"
                        
                        findings.append({
                            "severity": severity,
                            "check": "Startup Folder",
                            "status": "WARN" if severity == "Medium" else "INFO",
                            "details": f"File detected: {file} in {path}"
                        })
                except Exception:
                    pass
        return findings

    def check_scheduled_tasks(self):
        findings = []
        try:
            # Use CSV output for easier parsing
            result = subprocess.check_output('schtasks /query /fo CSV /v', shell=True).decode(errors='ignore')
            f = io.StringIO(result)
            reader = csv.DictReader(f)
            
            suspicious_actions = ["powershell", "cmd", "wscript", "cscript", "rundll32", "regsvr32", "temp", "appdata"]
            
            for row in reader:
                task_name = row.get('TaskName', 'Unknown')
                action = row.get('Task To Run', '')
                
                if not action or action == 'N/A':
                    continue
                    
                # Heuristic Analysis
                is_suspicious = False
                for kw in suspicious_actions:
                    if kw in action.lower():
                        is_suspicious = True
                        break
                
                if is_suspicious:
                     findings.append({
                        "severity": "Medium",
                        "check": "Suspicious Scheduled Task",
                        "status": "WARN",
                        "details": f"Task: {task_name} | Action: {action[:100]}..." # Truncate long actions
                    })

        except Exception as e:
             # schtasks might require admin or fail on some envs
             pass
        return findings

    def check_winlogon_helpers(self):
        """
        Checks for Winlogon Shell/Userinit modifications.
        """
        findings = []
        key_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_READ)
            
            # Check Shell (Standard: explorer.exe)
            try:
                shell, _ = winreg.QueryValueEx(key, "Shell")
                if shell.lower() != "explorer.exe":
                    findings.append({
                        "severity": "Critical",
                        "check": "Winlogon Shell Hijack",
                        "status": "FAIL",
                        "details": f"Winlogon Shell is NOT just explorer.exe. Value: {shell}"
                    })
            except: pass

            # Check Userinit (Standard: C:\Windows\system32\userinit.exe,)
            try:
                userinit, _ = winreg.QueryValueEx(key, "Userinit")
                if "userinit.exe" not in userinit.lower() or len(userinit.split(',')) > 2: # >2 because of trailing comma
                     findings.append({
                        "severity": "High",
                        "check": "Winlogon Userinit Hijack",
                        "status": "WARN",
                        "details": f"Suspicious Userinit value: {userinit}"
                    })
            except: pass
            
            winreg.CloseKey(key)
        except: pass
        return findings

    def check_ifeo_backdoors(self):
        """
        Checks Image File Execution Options for 'Debugger' value (Sticky Keys Backdoor).
        """
        findings = []
        base_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
        targets = ["sethc.exe", "utilman.exe", "osk.exe", "magnify.exe", "narrator.exe"]
        
        try:
            base_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base_path, 0, winreg.KEY_READ)
            
            for target in targets:
                try:
                    # Try to open subkey
                    key = winreg.OpenKey(base_key, target, 0, winreg.KEY_READ)
                    # Check for 'Debugger' value
                    val, _ = winreg.QueryValueEx(key, "Debugger")
                    
                    findings.append({
                        "severity": "Critical",
                        "check": f"IFEO Backdoor ({target})",
                        "status": "FAIL",
                        "details": f"Debugger Attached: {val}. This is a known persistence/backdoor technique."
                    })
                    winreg.CloseKey(key)
                except FileNotFoundError:
                    continue
            winreg.CloseKey(base_key)
        except: pass
        return findings

    def check_wmi_persistence(self):
        """
        Checks for WMI Event Consumers (Fileless Persistence).
        """
        findings = []
        if not self.wmi_client:
            return findings

        # Check ActiveScriptEventConsumer (often used by malware for fileless scripts)
        try:
            consumers = self.wmi_client.ActiveScriptEventConsumer()
            if consumers:
                for c in consumers:
                     findings.append({
                        "severity": "High",
                        "check": "WMI Persistence (Script)",
                        "status": "WARN",
                        "details": f"Found ActiveScriptEventConsumer: {c.Name}"
                    })
        except: pass
        
        # Check CommandLineEventConsumer
        try:
            consumers = self.wmi_client.CommandLineEventConsumer()
            if consumers:
                for c in consumers:
                     findings.append({
                        "severity": "High",
                        "check": "WMI Persistence (CmdLine)",
                        "status": "WARN",
                        "details": f"Found CommandLineEventConsumer: {c.Name} | Cmd: {c.CommandLineTemplate}"
                    })
        except: pass

        return findings
