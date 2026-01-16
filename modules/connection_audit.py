import subprocess
import re

class ConnectionAuditor:
    def __init__(self, console, wmi_client=None):
        self.console = console
        self.wmi_client = wmi_client

    def run_audit(self):
        findings = []
        self.console.print("[dim]   - Analyzing Active TCP/UDP Connections...[/dim]")
        findings.extend(self.analyze_netstat())
        
        self.console.print("[dim]   - Dumping DNS Resolver Cache (History)...[/dim]")
        findings.extend(self.analyze_dns_cache())
        return findings

    def analyze_netstat(self):
        findings = []
        try:
            # Get connections with PID
            output = subprocess.check_output("netstat -ano", shell=True).decode(errors='ignore')
            lines = output.split('\n')
            
            # Known Bad Ports (RATs/Trojans)
            suspicious_ports = {
                4444: "Metasploit", 1337: "Warez/Trojan", 6667: "IRC Botnet", 
                31337: "BackOrifice", 8888: "Alt-HTTP", 4443: "Alt-HTTPS"
            }
            
            for line in lines:
                if "ESTABLISHED" in line or "LISTEN" in line:
                    parts = line.split()
                    if len(parts) >= 5:
                        proto = parts[0]
                        local = parts[1]
                        foreign = parts[2]
                        state = parts[3]
                        pid = parts[4]
                        
                        # Resolve PID to Name if WMI available
                        process_name = f"PID: {pid}"
                        process_path = "Unknown"
                        
                        if self.wmi_client and pid.isdigit():
                            try:
                                procs = self.wmi_client.Win32_Process(ProcessId=int(pid))
                                if procs:
                                    process_name = procs[0].Name
                                    process_path = procs[0].ExecutablePath
                            except: pass
                            
                        # Check Foreign Port
                        port = 0
                        if ":" in foreign:
                            try:
                                port = int(foreign.split(":")[-1])
                            except: pass
                            
                        # Logic 1: Suspicious Port
                        if port in suspicious_ports:
                            findings.append({
                                "severity": "High",
                                "check": f"Suspicious Port ({port})",
                                "status": "WARN",
                                "details": f"Process '{process_name}' connected to {foreign} (Risk: {suspicious_ports[port]})"
                            })

                        # Logic 2: Public IP Connections from suspicious processes
                        # e.g. powershell.exe connecting out
                        if "powershell" in process_name.lower() or "cmd" in process_name.lower():
                            # Ignore 127.0.0.1 or 0.0.0.0 or [::]
                            if not foreign.startswith("127.") and not foreign.startswith("0.") and not foreign.startswith("[::"):
                                 findings.append({
                                    "severity": "Critical",
                                    "check": "Shell Connection",
                                    "status": "FAIL",
                                    "details": f"Shell '{process_name}' established connection to {foreign}! Potential C2."
                                })

        except Exception as e:
            pass
        return findings

    def analyze_dns_cache(self):
        """
        Parses ipconfig /displaydns to see what domains have been resolved recently.
        """
        findings = []
        try:
            output = subprocess.check_output("ipconfig /displaydns", shell=True).decode(errors='ignore')
            
            # Regex to find Record Name
            # "    Record Name . . . . . : google.com"
            domains = re.findall(r"Record Name\s+\.\s+\.\s+\.\s+\.\s+\.\s+:\s+([^\r\n]+)", output)
            
            # Simple Reputation Check (Static)
            suspicious_tlds = [".xyz", ".top", ".ru", ".cn", ".onion"]
            suspicious_keywords = ["pwn", "hack", "exploit", "ngrok", "tunnel", "tor-entry"]
            
            for domain in domains:
                domain = domain.strip().lower()
                
                risk_sev = "Info"
                risk_stat = "INFO"
                match = False
                
                for tld in suspicious_tlds:
                    if domain.endswith(tld):
                        risk_sev = "Medium"
                        risk_stat = "WARN"
                        match = True
                
                for deg in suspicious_keywords:
                    if deg in domain:
                        risk_sev = "High"
                        risk_stat = "WARN"
                        match = True
                        
                if match:
                    findings.append({
                        "severity": risk_sev,
                        "check": "Suspicious DNS Record",
                        "status": risk_stat,
                        "details": f"Domain found in DNS Cache: {domain}"
                    })
                    
        except: pass
        return findings
