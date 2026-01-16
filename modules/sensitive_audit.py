import os

class SensitiveDataAuditor:
    def __init__(self, console):
        self.console = console

    def run_audit(self):
        findings = []
        user_home = os.path.expanduser("~")
        search_paths = [
            os.path.join(user_home, "Desktop"),
            os.path.join(user_home, "Documents"),
            os.path.join(user_home, "Downloads")
        ]
        
        suspicious_extensions = ['.kdbx', '.pem', '.ppk', '.p12', '.ovpn']
        suspicious_names = ['password', 'credential', 'secret', 'login', 'config']

        self.console.print("[dim]Scanning user directories for sensitive files (Quick Scan)...[/dim]")

        for path in search_paths:
            if os.path.exists(path):
                try:
                    for root, dirs, files in os.walk(path):
                        # Limit depth to avoid long scans
                        if root.count(os.sep) - path.count(os.sep) > 2:
                            continue
                            
                        for file in files:
                            lower_file = file.lower()
                            
                            is_suspicious = False
                            reason = ""
                            
                            # Check extension
                            for ext in suspicious_extensions:
                                if lower_file.endswith(ext):
                                    is_suspicious = True
                                    reason = f"Sensitive extension ({ext})"
                                    break
                            
                            # Check filename
                            if not is_suspicious:
                                for name in suspicious_names:
                                    if name in lower_file:
                                        is_suspicious = True
                                        reason = f"Sensitive filename keyword ({name})"
                                        break
                            
                            if is_suspicious:
                                findings.append({
                                    "severity": "Medium",
                                    "check": "Sensitive File Exposure",
                                    "status": "WARN",
                                    "details": f"Found: {file} in {root} [{reason}]"
                                })
                                
                except Exception:
                    pass
                    
        if not findings:
            findings.append({
                "severity": "Info",
                "check": "Sensitive File Scan",
                "status": "PASS",
                "details": "No obvious sensitive files found in Desktop/Documents/Downloads (Quick Scan)."
            })
            
        return findings
