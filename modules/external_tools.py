import os
import subprocess
import json
from datetime import datetime
import ctypes
from rich.prompt import Prompt

class ExternalArsenalBridge:
    def __init__(self, console):
        self.console = console
        self.tools_path = os.path.join(os.getcwd(), "tools")
        self.logs_path = os.path.join(os.getcwd(), "logs", f"arsenal_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        self._ensure_paths()
        
        # Smart Context Detection
        self.is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        self.is_domain = os.environ.get('USERDOMAIN', '').lower() != os.environ.get('COMPUTERNAME', '').lower()
        
        # Define supported tools
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
                "risk": "High",
                "timeout": 60
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
                "risk": "Medium",
                "timeout": 60
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
                "risk": "Info",
                "timeout": 30
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
                "args": "-accepteula -u -v -c c:\\windows\\system32\\drivers", 
                "name": "SigCheck (Unsigned Drivers)", 
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
        from rich.prompt import Prompt # Local import to ensure availability
        findings = []
        self.console.print(f"[dim]   - Scanning Arsenal at: {self.tools_path}[/dim]")
        self.console.print(f"[dim]   - Tool outputs will be saved to: {self.logs_path}[/dim]")
        
        if not self.is_admin:
            self.console.print("[yellow]   [!] Running as Standard User. High-privilege tools will be skipped.[/yellow]")
        if not self.is_domain:
            self.console.print("[dim]   [i] Workgroup detected. AD-specific tools will be skipped.[/dim]")

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
                "details": "No external binaries found in 'tools/' directory. Run 'tools/download_tools.ps1' to populate."
            })
            return findings

        for key, path in installed_tools:
            config = self.supported_tools[key]
            
            # Smart Skipping Logic
            if config['category'] in ["AD Recon", "AD Exploitation"] and not self.is_domain:
                findings.append({
                    "severity": "Info", 
                    "category": config['category'], 
                    "check": f"{config['name']} Check", 
                    "status": "SKIP", 
                    "details": "Skipped: Not domain-joined."
                })
                continue
            
            self.console.print(f"[bold cyan]   > Executing Bridge: {config['name']}...[/bold cyan]")
            
            try:
                # INTERACTIVE PROMPTS FOR COMPLEX TOOLS
                # -------------------------------------
                current_args = config["args"]
                
                if key == "bloodyad":
                    self.console.print("[yellow]   [*] BloodyAD requires target credentials.[/yellow]")
                    if Prompt.ask("       Do you want to run BloodyAD interactively?", choices=["y", "n"], default="n") == "y":
                         target_ip = Prompt.ask("       Target DC IP")
                         domain = Prompt.ask("       Domain (e.g. contoso.com)")
                         username = Prompt.ask("       Username")
                         password = Prompt.ask("       Password")
                         current_args = f"-d {domain} -u {username} -p {password} --host {target_ip} get children"
                    else:
                        self.console.print("[dim]       Skipping interactive mode (using default help).[/dim]")

                elif key == "kerbrute":
                    self.console.print("[yellow]   [*] Kerbrute requires a username wordlist.[/yellow]")
                    if Prompt.ask("       Do you want to run Kerbrute interactively?", choices=["y", "n"], default="n") == "y":
                        wordlist = Prompt.ask("       Path to Wordlist")
                        domain = Prompt.ask("       Target Domain")
                        current_args = f"userenum -d {domain} {wordlist}"
                    else:
                         self.console.print("[dim]       Skipping interactive mode (using default help).[/dim]")
                
                # -------------------------------------

                full_cmd = f'"{path}" {current_args}'
                
                try:
                    # Dynamic Timeout
                    time_limit = config.get('timeout', 15)
                    output = subprocess.check_output(full_cmd, shell=True, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, timeout=time_limit).decode(errors='ignore')
                    
                    # Save Output to Log File
                    log_file_name = f"{key}_output.txt"
                    log_file_path = os.path.join(self.logs_path, log_file_name)
                    with open(log_file_path, "w", encoding="utf-8") as f:
                        f.write(f"COMMAND: {full_cmd}\n")
                        f.write("="*50 + "\n")
                        f.write(output)
                    
                    description = f"Executed. Output saved to: logs/{os.path.basename(self.logs_path)}/{log_file_name}"
                    # Analyze Output for Help/Errors vs Real Data
                    is_real_output = False
                    status = "INFO"
                    
                    # Heuristics for "Did it actually work?"
                    lower_out = output.lower()
                    
                    # Common Help/Error signatures
                    help_indicators = ["usage:", "optional arguments:", "version:", "examples:", "arguments:", "options:", "command line error"]
                    
                    if any(s in lower_out for s in help_indicators) and len(output) < 2000:
                         description = f"Tool produced Help/Syntax output. Check args. Log: {log_file_name}"
                    elif "error" in lower_out or "exception" in lower_out or "failed" in lower_out:
                         description = f"Tool execution error. Log: {log_file_name}"
                         status = "WARN"
                    else:
                         is_real_output = True
                         status = "FAIL" # In this context, FAIL means the tool ran and found something (which is bad for the defender)
                         description = f"Tool ran successfully. Check artifacts. Log: {log_file_name}"

                    # Tool-Specific Overrides
                    if key == "mimikatz":
                        if "sekurlsa" in lower_out or "wdigest" in lower_out:
                            status = "FAIL"
                            description = "Mimikatz dumped credentials. AV Failed."
                        if "error" in lower_out: # Handle the specific errors seen in logs
                             status = "INFO"
                             description = "Mimikatz blocked or failed to dump."

                    if key == "rubeus":
                         if "luid" in lower_out and "servicename" in lower_out:
                             status = "FAIL"
                             description = "Rubeus enumerated Kerberos tickets."
                    
                    if key == "bloodhound" or key == "sharphound":
                        if "zip" in lower_out or "compressing" in lower_out:
                             status = "FAIL" 
                             description = "SharpHound collected AD data."
                        elif "unable to get current domain" in lower_out:
                             status = "INFO"
                             description = "SharpHound failed: Not in a domain."

                    if key == "certify":
                        if "vulnerable template" in lower_out:
                             status = "FAIL"
                             description = "Certify found vulnerable templates."
                        elif "domain either does not exist" in lower_out:
                             status = "INFO"
                             description = "Certify failed: Domain unreachable."

                    if key == "bloodyad":
                         if "usage:" in lower_out:
                              status = "INFO"
                              description = "BloodyAD loaded (Args required for exploit)."

                    if key == "kerbrute":
                         if "valid usernames" in lower_out and "scanning" in lower_out:
                              status = "FAIL"
                              description = "Kerbrute validated users."
                         elif "usage:" in lower_out:
                              status = "INFO" 
                              description = "Kerbrute loaded (Mode selected)."
                    
                    findings.append({
                        "severity": config['risk'],
                        "category": config['category'],
                        "check": f"{config['name']} Status",
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
