import os
import glob
import json

class BrowserAuditor:
    def __init__(self, console):
        self.console = console

    def run_audit(self):
        findings = []
        findings.extend(self.audit_chrome_extensions())
        findings.extend(self.audit_edge_extensions())
        return findings

    def audit_chrome_extensions(self):
        return self._scan_extensions(
            os.path.join(os.getenv('LOCALAPPDATA'), r"Google\Chrome\User Data\Default\Extensions"),
            "Chrome"
        )

    def audit_edge_extensions(self):
        return self._scan_extensions(
            os.path.join(os.getenv('LOCALAPPDATA'), r"Microsoft\Edge\User Data\Default\Extensions"),
            "Edge"
        )

    def _scan_extensions(self, path, browser_name):
        findings = []
        if not os.path.exists(path):
            return findings

        try:
            # Each folder here is an Extension ID
            for ext_id in os.listdir(path):
                ext_path = os.path.join(path, ext_id)
                if os.path.isdir(ext_path):
                    # Try to find manifest to get name
                    name = "Unknown"
                    try:
                        # Version folder inside ID folder
                        versions = os.listdir(ext_path)
                        if versions:
                            manifest_path = os.path.join(ext_path, versions[0], "manifest.json")
                            if os.path.exists(manifest_path):
                                with open(manifest_path, 'r', encoding='utf-8', errors='ignore') as f:
                                    data = json.load(f)
                                    name = data.get('name', 'Unknown')
                    except:
                        pass
                    
                    findings.append({
                        "severity": "Info",
                        "check": f"{browser_name} Extension",
                        "status": "INFO",
                        "details": f"Found Extension: '{name}' (ID: {ext_id})"
                    })
        except Exception as e:
            findings.append({"severity": "Error", "check": f"{browser_name} Audit", "status": "ERROR", "details": str(e)})
            
        return findings
