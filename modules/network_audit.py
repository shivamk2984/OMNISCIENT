import socket
import subprocess
import re
from rich.console import Console

class NetworkAuditor:
    def __init__(self, console):
        self.console = console

    def run_network_audit(self):
        findings = []
        findings.extend(self.check_open_ports())
        findings.extend(self.check_dns_settings())
        findings.extend(self.check_hosts_file())
        return findings

    def check_open_ports(self):
        """
        Scans for common high-risk listening ports on localhost.
        """
        findings = []
        risky_ports = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            443: "HTTPS",
            445: "SMB",
            3389: "RDP",
            5900: "VNC",
            8080: "HTTP-Alt"
        }
        
        self.console.print("[dim]Scanning common local ports...[/dim]")
        
        for port, service in risky_ports.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex(('127.0.0.1', port))
                sock.close()
                
                if result == 0:
                    severity = "High" if port in [21, 23, 445] else "Info"
                    description = f"Port {port} ({service}) is LISTENING on localhost."
                    
                    if port == 445:
                        description += " Ensure SMB signing is enabled and not exposed to internet."
                    
                    findings.append({
                        "severity": severity,
                        "check": f"Open Port {port}",
                        "status": "WARN",
                        "details": description
                    })
            except Exception:
                pass
                
        return findings

    def check_dns_settings(self):
        findings = []
        try:
            output = subprocess.check_output("ipconfig /all", shell=True).decode(errors='ignore')
            if "8.8.8.8" in output or "1.1.1.1" in output:
                findings.append({
                    "severity": "Info",
                    "check": "DNS Configuration",
                    "status": "PASS",
                    "details": "Using known public DNS resolvers."
                })
        except:
            pass
        return findings

    def check_hosts_file(self):
        findings = []
        hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
        try:
            with open(hosts_path, 'r') as f:
                content = f.read()
                lines = [l.strip() for l in content.split('\n') if l.strip() and not l.strip().startswith('#')]
                
                if len(lines) > 2:
                    findings.append({
                        "severity": "Medium",
                        "check": "Hosts File Hijack",
                        "status": "WARN",
                        "details": f"Hosts file contains {len(lines)} custom entries. Check for redirection attacks."
                    })
                else:
                    findings.append({
                        "severity": "Info",
                        "check": "Hosts File",
                        "status": "PASS",
                        "details": "Hosts file looks clean (standard entries only)."
                    })
        except FileNotFoundError:
             findings.append({
                "severity": "Low",
                "check": "Hosts File",
                "status": "WARN",
                "details": "Could not find hosts file to audit."
            })
        except Exception as e:
             findings.append({
                "severity": "Error",
                "check": "Hosts File",
                "status": "ERROR",
                "details": str(e)
            })
            
        return findings
