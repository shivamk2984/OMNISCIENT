import os
import subprocess
import json
from datetime import datetime

class ExternalArsenalBridge:
    def __init__(self, console):
        self.console = console
        self.tools_path = os.path.join(os.getcwd(), "tools")
        self.logs_path = os.path.join(os.getcwd(), "logs", f"arsenal_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        self._ensure_paths()
        
        # Define supported tools and their audit commands (Binaries must be in tools/ folder)
        self.supported_tools = {
            "mimikatz": {
                "bin": "mimikatz.exe", 
                "args": '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "exit"', 
                "name": "Mimikatz (Credentials)", 
                "category": "RedTeam", 
                "risk": "Critical"
            },
            "rubeus": {
                "bin": "Rubeus.exe", 
                "args": "triage /nowrap", 
                "name": "Rubeus (Kerberos)", 
                "category": "RedTeam", 
                "risk": "Critical"
            },
            "winpeas": {
                "bin": "winPEASx64.exe", 
                "args": "quiet systeminfo userinfo networkinfo servicesinfo applicationsinfo", 
                "name": "WinPEAS (PrivEsc)", 
                "category": "Post-Exploitation", 
                "risk": "High"
            },
            "watson": {
                "bin": "Watson.exe", 
                "args": "", 
                "name": "Watson (Patch Vulns)", 
                "category": "VulnScan", 
                "risk": "High"
            },
            "seatbelt": {
                "bin": "Seatbelt.exe", 
                "args": "-group=system -full", 
                "name": "Seatbelt (Enum)", 
                "category": "Enum", 
                "risk": "Info"
            },
            "sharphound": {
                "bin": "SharpHound.exe", 
                "args": "-c LocalAdmin,Session --zipfilename SH_Out.zip", 
                "name": "SharpHound (AD Map)", 
                "category": "AD Recon", 
                "risk": "Info"
            },
            "lazagne": {
                "bin": "lazagne.exe", 
                "args": "all", 
                "name": "LaZagne (Passwords)", 
                "category": "RedTeam", 
                "risk": "High"
            },
            "certify": {
                "bin": "Certify.exe", 
                "args": "find /vulnerable", 
                "name": "Certify (AD CS)", 
                "category": "AD Recon", 
                "risk": "High"
            },
            "bloodyad": {
                "bin": "BloodyAD.exe", 
                "args": "-h", 
                "name": "BloodyAD (Requires Auth Info)", 
                "category": "AD Exploitation", 
                "risk": "Critical"
            },
            "printnightmare": {
                "bin": "PrintNightmare.exe", 
                "args": "", 
                "name": "PrintNightmare POC", 
                "category": "Exploit", 
                "risk": "Critical"
            },
            "sweetpotato": {
                "bin": "SweetPotato.exe", 
                "args": "-e EfsRpc", 
                "name": "SweetPotato (PrivEsc)", 
                "category": "Exploit", 
                "risk": "Critical"
            },
            "kerbrute": {
                "bin": "kerbrute.exe", 
                "args": "userenum --help", 
                "name": "Kerbrute (Enum Mode)", 
                "category": "RedTeam", 
                "risk": "Medium"
            },

            "chisel": {
                "bin": "chisel.exe", 
                "args": "--help", 
                "name": "Chisel (Tunneling)", 
                "category": "Network", 
                "risk": "High"
            },
            "ligolo": {
                "bin": "ligolo.exe", 
                "args": "--help", 
                "name": "Ligolo (Tunneling)", 
                "category": "Network", 
                "risk": "High"
            },
            "nc": {
                "bin": "nc.exe", 
                "args": "-h", 
                "name": "Netcat", 
                "category": "Network", 
                "risk": "Medium"
            },
            "plink": {
                "bin": "plink.exe", 
                "args": "-V", 
                "name": "Plink (PuTTY)", 
                "category": "Network", 
                "risk": "Medium"
            },

             "procdump": {
                "bin": "procdump.exe", 
                "args": "-accepteula -ma lsass.exe lsass_dump.dmp", 
                "name": "ProcDump (LSASS)", 
                "category": "Sysinternals", 
                "risk": "High"
            },
            "autorunsc": {
                "bin": "autorunsc.exe", 
                "args": "-accepteula -a * -c * -h -s -t", 
                "name": "AutorunsC", 
                "category": "Persistence", 
                "risk": "Medium"
            },
            "accesschk": {
                "bin": "accesschk.exe", 
                "args": "-accepteula -uwcqv *", 
                "name": "AccessChk (Writeable Svcs)", 
                "category": "Sysinternals", 
                "risk": "Info"
            },
            "psloglist": {
                "bin": "psloglist.exe", 
                "args": "-accepteula security -n 100", 
                "name": "PsLogList (Last 100 SecEvents)", 
                "category": "Sysinternals", 
                "risk": "Info"
            },
            "tcpview": {
                "bin": "Tcpview.exe", 
                "args": "-accepteula -a -n -c", 
                "name": "TcpView (CLI)", 
                "category": "Sysinternals", 
                "risk": "Info"
            },
            "handle": {
                "bin": "handle.exe", 
                "args": "-accepteula -a -u", 
                "name": "Handle Viewer", 
                "category": "Sysinternals", 
                "risk": "Info"
            },
            "sigcheck": {
                "bin": "sigcheck.exe", 
                "args": "-accepteula -u -e c:\\windows\\system32", 
                "name": "SigCheck (Unsigned)", 
                "category": "Sysinternals", 
                "risk": "Info"
            },
            "whois": {
                "bin": "whois.exe", 
                "args": "-accepteula -v google.com", 
                "name": "Whois Test", 
                "category": "Sysinternals", 
                "risk": "Info"
            }
        }

    def _ensure_paths(self):
        if not os.path.exists(self.tools_path):
            try: os.makedirs(self.tools_path)
            except: pass
        if not os.path.exists(self.logs_path):
            try: os.makedirs(self.logs_path)
            except: pass

    def run_audit(self):
        findings = []
        self.console.print(f"[dim]   - Scanning Arsenal at: {self.tools_path}[/dim]")
        self.console.print(f"[dim]   - Tool outputs will be saved to: {self.logs_path}[/dim]")
        
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
                "details": f"No external binaries found. Add tools to {self.tools_path}"
            })
            return findings

        for key, path in installed_tools:
            config = self.supported_tools[key]
            self.console.print(f"[bold cyan]   > Executing Bridge: {config['name']}...[/bold cyan]")
            
            try:
                full_cmd = f'"{path}" {config["args"]}'
                
                try:
                    output = subprocess.check_output(full_cmd, shell=True, stderr=subprocess.STDOUT, timeout=20).decode(errors='ignore')
                    
                    # Save Output to Log File
                    log_file_name = f"{key}_output.txt"
                    log_file_path = os.path.join(self.logs_path, log_file_name)
                    with open(log_file_path, "w", encoding="utf-8") as f:
                        f.write(f"COMMAND: {full_cmd}\n")
                        f.write("="*50 + "\n")
                        f.write(output)
                    
                    description = f"Executed. Output saved to: logs/{os.path.basename(self.logs_path)}/{log_file_name}"
                    status = "PASS"
                    
                    if key == "mimikatz":
                        if "Mimikatz" in output:
                            status = "FAIL"
                            description = f"Mimikatz ran successfully (AV Failed). Log: {log_file_name}"
                    
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
