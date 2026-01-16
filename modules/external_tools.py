import os
import subprocess
import json

class ExternalArsenalBridge:
    def __init__(self, console):
        self.console = console
        self.tools_path = os.path.join(os.getcwd(), "tools")
        self._ensure_tools_dir()
        
        # Define supported tools and their audit commands
        # Define supported tools and their audit commands (Binaries must be in tools/ folder)
        self.supported_tools = {
            "mimikatz": {
                "bin": "mimikatz.exe", "args": '"version" "exit"', "name": "Mimikatz (Credentials)", "category": "RedTeam", "risk": "Critical"
            },
            "rubeus": {
                "bin": "Rubeus.exe", "args": "triage", "name": "Rubeus (Kerberos)", "category": "RedTeam", "risk": "Critical"
            },
            "winpeas": {
                "bin": "winPEASx64.exe", "args": "systeminfo", "name": "WinPEAS (PrivEsc)", "category": "Post-Exploitation", "risk": "High"
            },
            "watson": {
                "bin": "Watson.exe", "args": "", "name": "Watson (Patch Vulns)", "category": "VulnScan", "risk": "High"
            },
            "seatbelt": {
                "bin": "Seatbelt.exe", "args": "-group=system", "name": "Seatbelt (Enum)", "category": "Enum", "risk": "Info"
            },
            "sharphound": {
                "bin": "SharpHound.exe", "args": "--help", "name": "SharpHound (AD Map)", "category": "AD Recon", "risk": "Info"
            },
            "lazagne": {
                "bin": "lazagne.exe", "args": "all", "name": "LaZagne (Passwords)", "category": "RedTeam", "risk": "High"
            },
            "certify": {
                "bin": "Certify.exe", "args": "find", "name": "Certify (AD CS)", "category": "AD Recon", "risk": "High"
            },
            "bloodyad": {
                "bin": "BloodyAD.exe", "args": "-h", "name": "BloodyAD", "category": "AD Exploitation", "risk": "Critical"
            },
            "printnightmare": {
                "bin": "PrintNightmare.exe", "args": "", "name": "PrintNightmare POC", "category": "Exploit", "risk": "Critical"
            },
            "sweetpotato": {
                "bin": "SweetPotato.exe", "args": "", "name": "SweetPotato (PrivEsc)", "category": "Exploit", "risk": "Critical"
            },
            "kerbrute": {
                "bin": "kerbrute.exe", "args": "version", "name": "Kerbrute (BruteForce)", "category": "RedTeam", "risk": "Medium"
            },

            "chisel": {
                "bin": "chisel.exe", "args": "--help", "name": "Chisel (Tunneling)", "category": "Network", "risk": "High"
            },
            "ligolo": {
                "bin": "ligolo.exe", "args": "--help", "name": "Ligolo (Tunneling)", "category": "Network", "risk": "High"
            },
            "nc": {
                "bin": "nc.exe", "args": "-h", "name": "Netcat", "category": "Network", "risk": "Medium"
            },
            "plink": {
                "bin": "plink.exe", "args": "-V", "name": "Plink (PuTTY)", "category": "Network", "risk": "Medium"
            },

             "procdump": {
                "bin": "procdump.exe", "args": "-accepteula -?", "name": "ProcDump", "category": "Sysinternals", "risk": "High"
            },
            "autorunsc": {
                "bin": "autorunsc.exe", "args": "-accepteula -a * -c", "name": "AutorunsC", "category": "Persistence", "risk": "Medium"
            },
            "accesschk": {
                "bin": "accesschk.exe", "args": "-accepteula /accepteula", "name": "AccessChk", "category": "Sysinternals", "risk": "Info"
            },
            "psloglist": {
                "bin": "psloglist.exe", "args": "-accepteula /?", "name": "PsLogList", "category": "Sysinternals", "risk": "Info"
            },
            "tcpview": {
                "bin": "Tcpview.exe", "args": "-accepteula -c -n", "name": "TcpView (CLI)", "category": "Sysinternals", "risk": "Info"
            },
            "handle": {
                "bin": "handle.exe", "args": "-accepteula", "name": "Handle Viewer", "category": "Sysinternals", "risk": "Info"
            },
            "sigcheck": {
                "bin": "sigcheck.exe", "args": "-accepteula -h", "name": "SigCheck", "category": "Sysinternals", "risk": "Info"
            },
            "whois": {
                "bin": "whois.exe", "args": "-accepteula -v", "name": "Whois", "category": "Sysinternals", "risk": "Info"
            }
        }

    def _ensure_tools_dir(self):
        if not os.path.exists(self.tools_path):
            try:
                os.makedirs(self.tools_path)
            except: pass

    def run_audit(self):
        findings = []
        self.console.print(f"[dim]   - Scanning Arsenal at: {self.tools_path}[/dim]")
        
        installed_tools = []
        
        for key, config in self.supported_tools.items():
            path = os.path.join(self.tools_path, config['bin'])
            if os.path.exists(path):
                installed_tools.append((key, path))

        if not installed_tools:
            findings.append({
                "severity": "Info",
                "category": "Arsenal",
                "check": "Tool Availability",
                "status": "EMPTY",
                "details": f"No external binaries found in {self.tools_path}. Add 'mimikatz.exe', 'autorunsc.exe', etc. to enable advanced bridges."
            })
            return findings

        for key, path in installed_tools:
            config = self.supported_tools[key]
            self.console.print(f"[bold cyan]   > Executing Bridge: {config['name']}...[/bold cyan]")
            
            try:
                full_cmd = f'"{path}" {config["args"]}'
                
                try:
                    output = subprocess.check_output(full_cmd, shell=True, stderr=subprocess.STDOUT, timeout=15).decode(errors='ignore')
                    
                    description = f"Tool executed successfully. Output length: {len(output)} chars."
                    status = "PASS"
                    
                    if key == "mimikatz":
                        if "Mimikatz" in output:
                            status = "FAIL"
                            description = "Mimikatz execution successful! Endpoint Protection failed to block."
                    
                    if key == "autorunsc":
                        description = "Deep persistence scan via AutorunsC completed. (See logs for raw data)."
                    
                    findings.append({
                        "severity": config['risk'],
                        "category": config['category'],
                        "check": f"{config['name']} Check",
                        "status": status,
                        "details": description
                    })

                except subprocess.TimeoutExpired:
                    findings.append({
                        "severity": "Medium",
                        "category": config['category'],
                        "check": f"{config['name']} Timeout",
                        "status": "WARN",
                        "details": "Tool hanging or waiting for input. Deployment verified but execution timed out."
                    })
                    
            except subprocess.CalledProcessError as e:
                status = "INFO"
                det = f"Execution returned non-zero. Likely blocked by AV or permissions. (Code {e.returncode})"
                if key in ["mimikatz", "lazagne"]:
                    status = "PASS" 
                    det = "Malicious tool execution BLOCKED (Expected behavior for secured system)."
                
                findings.append({
                    "severity": "Info",
                    "category": config['category'],
                    "check": f"{config['name']} Status",
                    "status": status,
                    "details": det
                })
                
        return findings
