import os
import re
from rich.progress import track

class SensitiveDataAuditor:
    def __init__(self, console):
        self.console = console
        self.findings = []
        self.patterns = {
            "Password": re.compile(r"password\s*=\s*['\"](.*?)['\"]", re.IGNORECASE),
            "API Key": re.compile(r"(api_key|apikey|access_token)\s*[:=]\s*['\"]?[a-zA-Z0-9_\-]{20,}", re.IGNORECASE),
            "Connection String": re.compile(r"Data Source=.*;User ID=.*;Password=.*", re.IGNORECASE),
            "Private Key": re.compile(r"-----BEGIN RSA PRIVATE KEY-----"),
            "Azure Token": re.compile(r"eyJ0eXAiOiJKV1Qi") # Potential JWT start
        }

    def run_audit(self):
        self.findings = []
        self.console.print("\n[bold cyan]STARTING DEEP FORENSIC SCAN (Secrets & Tokens)[/bold cyan]")
        
        self.check_cloud_tokens()
        self.check_unattend_xml()
        self.check_powershell_history()
        self.file_hunter()
        
        return self.findings

    def check_cloud_tokens(self):
        user_home = os.path.expanduser("~")
        targets = [
            (os.path.join(user_home, ".azure", "accessTokens.json"), "Azure Access Token"),
            (os.path.join(user_home, ".aws", "credentials"), "AWS Credentials"),
            (os.path.join(user_home, ".gcloud", "credentials.db"), "GCloud Credentials"),
            (os.path.join(user_home, "AppData", "Local", "Microsoft", "OneNote", "16.0", "cache"), "OneNote Cache"),
            (os.path.join(user_home, "AppData", "Roaming", "Discord", "Local Storage", "leveldb"), "Discord Tokens")
        ]
        
        for path, name in targets:
            if os.path.exists(path):
                self.findings.append({
                    "severity": "Critical",
                    "check": "Cloud Token Exposure",
                    "status": "FAIL",
                    "details": f"Found {name} at: {path}"
                })

    def check_unattend_xml(self):
        # Classic Windows Install Secret locations
        paths = [
            r"C:\Windows\Panther\Unattend.xml",
            r"C:\Windows\Panther\Unattended.xml",
            r"C:\Windows\System32\Sysprep\unattend.xml",
            r"C:\Windows\System32\Sysprep\Panther\unattend.xml"
        ]
        for p in paths:
            if os.path.exists(p):
                # Analyze content for "Password"
                try:
                    with open(p, 'r', errors='ignore') as f:
                        if "Password" in f.read():
                            self.findings.append({
                                "severity": "Critical",
                                "check": "Unattend.xml Secrets",
                                "status": "FAIL",
                                "details": f"Found Unattend.xml with potential password at {p}"
                            })
                except: pass

    def check_powershell_history(self):
        history_path = os.path.join(os.environ['APPDATA'], "Microsoft", "Windows", "PowerShell", "PSReadLine", "ConsoleHost_history.txt")
        if os.path.exists(history_path):
             self.findings.append({
                "severity": "Medium",
                "check": "PowerShell History",
                "status": "WARN",
                "details": f"PowerShell History found at {history_path}. Check for typed credentials."
            })
    
    def file_hunter(self):
        user_home = os.path.expanduser("~")
        scan_dirs = [
            os.path.join(user_home, "Desktop"),
            os.path.join(user_home, "Documents"),
            os.path.join(user_home, "Downloads"),
            r"C:\Users\Public"
        ]
        
        target_exts = ['.txt', '.config', '.xml', '.ini', '.kdbx', '.db', '.ovpn', '.pem', '.json']
        
        for root_dir in scan_dirs:
            if not os.path.exists(root_dir): continue
            
            # Simple walk with depth limit logic
            for root, _, files in os.walk(root_dir):
                if root.count(os.sep) - root_dir.count(os.sep) > 3: continue # Don't go too deep
                
                for file in files:
                    lower = file.lower()
                    fpath = os.path.join(root, file)

                    # 1. Filename Checks
                    if lower.endswith(".kdbx"):
                        self.findings.append({"severity": "High", "check": "Password Manager File", "status": "FAIL", "details": f"KeePass DB found: {fpath}"})
                    elif lower == "users.db" or lower == "secrets.db":
                        self.findings.append({"severity": "High", "check": "Sensitive DB", "status": "FAIL", "details": f"Sensitive Database found: {fpath}"})
                    elif lower.endswith(".ovpn"):
                        self.findings.append({"severity": "Medium", "check": "VPN Config", "status": "WARN", "details": f"OpenVPN Config found: {fpath}"})

                    # 2. Content Grep (Text types only)
                    if any(lower.endswith(e) for e in ['.txt', '.config', '.xml', '.ini', '.json', '.yaml']):
                        try:
                            # Read first 10KB only to be fast
                            if os.path.getsize(fpath) > 1024 * 50: continue 
                            
                            with open(fpath, 'r', errors='ignore') as f:
                                content = f.read()
                                for name, pattern in self.patterns.items():
                                    if pattern.search(content):
                                        self.findings.append({
                                            "severity": "High",
                                            "check": f"Hardcoded Secrets ({name})",
                                            "status": "FAIL",
                                            "details": f"Found {name} pattern in {fpath}"
                                        })
                                        break # Found one secret, move entirely to next file
                        except: pass

