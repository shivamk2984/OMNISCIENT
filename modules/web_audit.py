import requests
import urllib3
from rich.panel import Panel
from rich.table import Table

# Disable SSL warnings for self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class WebAppAuditor:
    def __init__(self, console):
        self.console = console
        self.headers_to_check = [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options"
        ]
        self.sensitive_paths = [
            "/admin", "/login", "/config", "/.env", "/backup", "/users.db", 
            "/sitelist.xml", "/web.config", "/dashboard", "/api"
        ]

    def run_audit(self):
        from rich.prompt import Prompt
        
        self.console.print(Panel("[bold cyan]WEB APPLICATION VULNERABILITY SCANNER[/bold cyan]\nChecks for: Headers, Sensitive Files, Directory Listing, Server Info", style="cyan"))
        
        target = Prompt.ask("\n[bold]Target URL[/bold] (e.g. http://127.0.0.1)", default="http://localhost")
        if not target.startswith("http"):
            target = "http://" + target
            
        findings = []
        self.console.print(f"\n[dim][*] Probing {target}...[/dim]")
        
        try:
            # 1. Base Request & Headers
            try:
                r = requests.get(target, verify=False, timeout=5)
                status_code = r.status_code
            except requests.exceptions.ConnectionError:
                 self.console.print("[bold red][!] Connection Failed. Is the server up?[/bold red]")
                 return []
            
            # Server Banner
            server_header = r.headers.get("Server", "Unknown")
            if server_header != "Unknown":
                 findings.append({"severity": "Info", "check": "Server Banner", "status": "WARN", "details": f"Server disclosure: {server_header}"})
            
            # Missing Headers
            for h in self.headers_to_check:
                if h not in r.headers:
                    findings.append({
                        "severity": "Low", 
                        "check": "Missing Security Header", 
                        "status": "FAIL", 
                        "details": f"Missing: {h}"
                    })

            # Directory Listing Check (Heuristic)
            if "Index of /" in r.text or "Directory Iterator" in r.text:
                 findings.append({
                     "severity": "Medium",
                     "check": "Directory Listing",
                     "status": "FAIL",
                     "details": "Directory listing appears enabled on root."
                 })

            # 2. Sensitive Path Fuzzing
            with self.console.status("[bold green]Fuzzing paths...[/bold green]"):
                for path in self.sensitive_paths:
                    url = target.rstrip("/") + path
                    try:
                        res = requests.get(url, verify=False, timeout=3)
                        if res.status_code == 200:
                            findings.append({
                                "severity": "High",
                                "check": "Sensitive Endpoint",
                                "status": "FAIL", 
                                "details": f"Exposed: {path} (HTTP 200)"
                            })
                        elif res.status_code == 403:
                             findings.append({
                                "severity": "Info",
                                "check": "Restricted Endpoint",
                                "status": "INFO", 
                                "details": f"Found but Forbidden: {path} (HTTP 403)"
                            })
                    except: pass
                    
        except Exception as e:
            self.console.print(f"[red]Error during web scan: {e}[/red]")

        # Print Results
        if findings:
            table = Table(title=f"Web Audit Results: {target}", show_header=True)
            table.add_column("Severity", style="bold")
            table.add_column("Check")
            table.add_column("Status")
            table.add_column("Details")
            
            for f in findings:
                style = "red" if f['severity'] in ["High", "Critical"] else "yellow" if f['severity'] == "Medium" else "white"
                table.add_row(f['severity'], f['check'], f['status'], f['details'], style=style)
            
            self.console.print(table)
        else:
             self.console.print("[green]System appears clean on basic checks.[/green]")

        return findings
