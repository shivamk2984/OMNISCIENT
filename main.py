from rich.console import Console
from rich.prompt import Prompt
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
import sys
import subprocess
import webbrowser
from rich.markup import escape
import time
import os
import random
import ctypes

# Import Modules
from modules.recon import SystemRecon
from modules.config_audit import ConfigAudit
from modules.advanced_audit import AdvancedAuditor
from modules.network_audit import NetworkAuditor
from modules.user_audit import UserAuditor
from modules.reporting import ReportGenerator
from modules.persistence_audit import PersistenceAuditor
from modules.browser_audit import BrowserAuditor
from modules.sensitive_audit import SensitiveDataAuditor
from modules.event_log_audit import EventLogAuditor
from modules.connection_audit import ConnectionAuditor
from modules.sensitive_audit import SensitiveDataAuditor
from modules.external_tools import ExternalArsenalBridge
from modules.web_audit import WebAppAuditor

class OmniscientMenu:
    def check_admin_rights(self):
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        except:
            is_admin = False

        if not is_admin:
            self.console.print(Panel("[bold yellow]Running as Standard User. Elevating privileges...[/bold yellow]", border_style="yellow"))
            # Auto-Escalate immediately (Triggers Windows UAC)
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
            sys.exit()

    def __init__(self):
        self.console = Console()
        self.check_admin_rights() # Strict check on startup
        self.recon = SystemRecon(self.console)
        self.wmi_client = self.recon.wmi_client
        
        self.net_auditor = NetworkAuditor(self.console)
        self.user_auditor = UserAuditor(self.wmi_client)
        self.reporter = ReportGenerator()
        self.persist_auditor = PersistenceAuditor(self.console, self.wmi_client)
        self.adv_auditor = AdvancedAuditor(self.wmi_client)
        self.browser_auditor = BrowserAuditor(self.console)
        self.forensics_auditor = SensitiveDataAuditor(self.console)
        self.conn_auditor = ConnectionAuditor(self.console, self.wmi_client)
        self.event_auditor = EventLogAuditor(self.console)
        self.usb_auditor = UsbForensics(self.console)
        self.web_auditor = WebAppAuditor(self.console)
        self.arsenal_auditor = ExternalArsenalBridge(self.console)
        
        self.last_system_info = self.recon.get_system_info() 
        self.all_findings = []

    def display_banner(self):
        # High-Tech / Brutalist / Cyberpunk ASCII Art
        banners = [
            r"""
 ██████╗ ███╗   ███╗███╗   ██╗██╗███████╗ ██████╗██╗███████╗███╗   ██╗████████╗
██╔═══██╗████╗ ████║████╗  ██║██║██╔════╝██╔════╝██║██╔════╝████╗  ██║╚══██╔══╝
██║   ██║██╔████╔██║██╔██╗ ██║██║███████╗██║     ██║█████╗  ██╔██╗ ██║   ██║   
██║   ██║██║╚██╔╝██║██║╚██╗██║██║╚════██║██║     ██║██╔══╝  ██║╚██╗██║   ██║   
╚██████╔╝██║ ╚═╝ ██║██║ ╚████║██║███████║╚██████╗██║███████╗██║ ╚████║   ██║   
 ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═══╝╚═╝╚══════╝ ╚═════╝╚═╝╚══════╝╚═╝  ╚═══╝   ╚═╝   
                                    [ v1.0 ]
            """,
            r"""
   ____  __  __ _   _ _____  _____  _____ _____ ______ _   _ _______ 
  / __ \|  \/  | \ | |_   _|/ ____|/ ____|_   _|  ____| \ | |__   __|
 | |  | | \  / |  \| | | | | (___ | |      | | | |__  |  \| |  | |   
 | |  | | |\/| | . ` | | |  \___ \| |      | | |  __| | . ` |  | |   
 | |__| | |  | | |\  |_| |_ ____) | |____ _| |_| |____| |\  |  | |   
  \____/|_|  |_|_| \_|_____|_____/ \_____|_____|______|_| \_|  |_|   
                                                                     
                                                                     
            """,
            r"""
                     / \
                   /  |  \
                 /    |    \
               /______|______\
              |       |       |
              |   O M N I     |
              | S C I E N T   |
              |_______|_______|
                 |    |    |
                 |    |    |
            """,
            r"""
       ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄ 
      ▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌
      ▐░█▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀▀▀ 
      ▐░▌       ▐░▌▐░▌       ▐░▌▐░▌          
      ▐░█▄▄▄▄▄▄▄█░▌▐░▌       ▐░▌▐░█▄▄▄▄▄▄▄▄▄ 
      ▐░░░░░░░░░░░▌▐░▌       ▐░▌▐░░░░░░░░░░░▌
      ▐░█▀▀▀▀▀▀▀█░▌▐░▌       ▐░▌▐░█▀▀▀▀▀▀▀▀▀ 
      ▐░▌       ▐░▌▐░▌       ▐░▌▐░▌          
      ▐░▌       ▐░▌▐░█▄▄▄▄▄▄▄█░▌▐░█▄▄▄▄▄▄▄▄▄ 
      ▐░▌       ▐░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌
       ▀         ▀  ▀▀▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀▀▀▀ 
             OMNISCIENT SYSTEMS
            """,
            r"""
        .       .
         \     /
          \   /
           \ /   OMNISCIENT
            O    
           / \
          /   \
         /     \
            """,
            r"""
      _________________
     |                 |
     |   OMNISCIENT    |
     |_________________|
          \  |  /
           \ | /
            \|/
             O
            """,
            r"""
                                                          
                                                          
                           :::                            
                        .....:::                          
                    ........:..  ----                     
                .........        -----===                 
             ........      .::-     -=-======             
         .... ...   ........:::------   =====+++          
         . ..    ..........   :-----=====   =+++          
       : . .  .........  :..:::-  ----=====  +++ +        
    :........... ....  ......::---- --== ====+++ ++++     
      ...-....   ... .....  .  ..--- -===  ==++= ++       
      ......    ...- :...    . ..---  ===    +++ ++       
      ......    ...- :...       ----  ===    +++ ++       
      ...-...:  -... .....     ----- -===   ++++ ++       
    :......:.... .... .....:--:---- --==  ===+++ ++++     
       . . .  ....:.... :...::::-  ---=====+ =++ ++       
         . ..   ..........     ------====   ++++          
         .... ...  .........:::-------  =====+++          
            .........   :.:.:::--    -=======             
                ........         -----====                
                   ......  : ::-------                    
                          :::::::-                        
                           :::-                           
            """
        ]
        
        quotes_list = [
            ("The quieter you become, the more you are able to hear.", "Kali Linux / Ram Dass"),
            ("Amateurs hack systems, professionals hack people.", "Bruce Schneier"),
            ("There is only one way to be safe: visible and aware.", "Omniscient Protocol"),
            ("Data is the new oil. And like oil, it burns.", "Unknown"),
            ("Trust, but verify. Then verify again.", "Security Mantra"),
            ("The system sees all. Hides nothing.", "Omniscient Core"),
            ("If you think technology can solve your security problems, then you don't understand the problems.", "Bruce Schneier"),
            ("Passwords are like underwear: you must change them often.", "Chris Pirillo"),
            ("Arguing that you don't care about privacy because you have nothing to hide is no different than saying you don't care about free speech because you have nothing to say.", "Edward Snowden"),
            ("We are all just ghosts in the machine.", "Cyberpunk Adage"),
            ("Visibility is absolute. Shadows are a myth.", "Omniscient"),
            ("Security is always excessive until it's not enough.", "Robbie Sinclair"),
            ("Your systems are only as secure as your most curious user.", "Omniscient"),
            ("I am the signal in the noise.", "Omniscient"),
            ("It takes 20 years to build a reputation and few minutes of cyber-incident to ruin it.", "Stephane Nappo")
        ]

        selected_banner = random.choice(banners)
        quote_text, quote_author = random.choice(quotes_list)
        
        # Display
        self.console.print(Panel(
            Text(selected_banner, style="bold white") + 
            Text("\n          [ by codeinecasket ]", style="dim white", justify="center") +
            Text(f"\n\n\"{quote_text}\"", style="italic white", justify="center") +
            Text(f"\n— {quote_author}", style="dim white", justify="right"),
            title="[bold white]OMNISCIENT v1.0[/bold white]", 
            border_style="white",
            expand=False,
            padding=(1, 2)
        ))

    def main_loop(self):
        while True:
            # self.console.clear() # Removed to keep history visible
            self.display_banner()
            self.console.print("\n[bold]Surveillance Sectors:[/bold]")
            self.console.print("1. [white]System Reconnaissance[/white]")
            self.console.print("2. [white]Configuration Hardening[/white]")
            self.console.print("3. [white]Advanced Threat Detection[/white]")
            self.console.print("4. [white]Network Analysis[/white]")
            self.console.print("5. [white]Identity & Access[/white]")
            self.console.print("6. [white]Deep Persistence[/white]")
            self.console.print("7. [white]Digital Forensics[/white]")
            self.console.print("8. [white]External Tool Bridge[/white]")
            self.console.print("9. [bold white]Help / Manual[/bold white]")
            self.console.print("[dim]──────────────────────────────────────────────────────────[/dim]")
            self.console.print("[bold]Deep Insight:[/bold]")
            self.console.print("10. [white]Event Log Hunter[/white]")
            self.console.print("11. [white]Live Connection Map[/white]")
            self.console.print("12. [white]Physical Device Trace (USB)[/white]")
            self.console.print("14. [white]Web App Scanner[/white]")
            self.console.print("[dim]──────────────────────────────────────────────────────────[/dim]")
            self.console.print("13. [bold reverse]INITIATE TOTAL AUDIT[/bold reverse]")
            self.console.print("99. [bold green]Update Tool (Git)[/bold green]")
            self.console.print("0. Exit")
            
            choice = Prompt.ask("\n[bold white]Input Command[/bold white]", choices=["1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "99", "0"])
            
            module_map = {
                '1': ("Recon", self.run_recon, "System"),
                '2': ("Config", self.run_basic_audit, "Hardening"),
                '3': ("Advanced Threat", self.run_advanced_audit, "Advanced Threat"),
                '4': ("Network", self.run_network_audit, "Network"),
                '5': ("Identity", self.run_user_audit, "Identity"),
                '6': ("Persistence", self.run_persistence_audit, "Persistence"),
                '7': ("Forensics", self.run_forensics_audit, "Forensics"),
                '8': ("External Bridge", self.arsenal_auditor.run_audit, "Arsenal"),
                '10': ("Deep Event Logs", self.event_auditor.run_audit, "Logs"),
                '11': ("Connection Map", self.conn_auditor.run_audit, "Network"),
                '12': ("USB Forensics", self.usb_auditor.run_audit, "Physical"),
                '14': ("Web Scanner", self.web_auditor.run_audit, "Web"),
            }

            if choice == '13':
                self.run_full_audit_with_report()
            elif choice == '99':
                self.run_updater()
            elif choice == '9':
                self.display_help()
            elif choice == '0':
                sys.exit()
            elif choice in module_map:
                name, func, category = module_map[choice]
                self.run_visual_module_with_report_prompt(name, func, category)
            
            Prompt.ask("\n[dim]Press Enter to continue...[/dim]")

    def run_updater(self):
        self.console.rule("[bold green]SELF-UPDATE SEQUENCE[/bold green]")
        self.console.print("[dim]Accessing remote repository...[/dim]")
        
        # Add local MinGit to PATH if it exists (from install_deps.ps1)
        local_git = os.path.join(os.getcwd(), "bin", "cmd")
        if os.path.exists(local_git):
            os.environ["PATH"] = local_git + os.pathsep + os.environ["PATH"]

        try:
            # Check if git is installed
            subprocess.run(["git", "--version"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            # Auto-Heal: Initialize Git if missing
            if not os.path.exists(os.path.join(os.getcwd(), ".git")):
                self.console.print("[yellow]   [*] Initializing fresh Git repository linkage...[/yellow]")
                subprocess.run(["git", "init"], check=True, stdout=subprocess.DEVNULL)
                subprocess.run(["git", "remote", "add", "origin", "https://github.com/shivamk2984/OMNISCIENT.git"], check=True, stdout=subprocess.DEVNULL)
                self.console.print("[yellow]   [*] Fetching latest code...[/yellow]")
                subprocess.run(["git", "fetch"], check=True, stdout=subprocess.DEVNULL)
                subprocess.run(["git", "reset", "--hard", "origin/main"], check=True, stdout=subprocess.DEVNULL)
                self.console.print("[green]   [+] Repository linked successfully.[/green]")

            # Pull changes
            result = subprocess.run(["git", "pull"], capture_output=True, text=True)
            
            if result.returncode == 0:
                self.console.print(f"[green]✔ Update Successful:[/green]\n{result.stdout}")
                self.console.print("[bold yellow]! Please restart the tool to apply changes.[/bold yellow]")
            else:
                self.console.print(f"[red]! Update Failed:[/red]\n{result.stderr}")
                
        except FileNotFoundError:
            self.console.print("[bold red]! Git (Portable or System) not found.[/bold red]")
            self.console.print("[yellow][*] Portable Git is included in our 'install_deps.ps1' script.[/yellow]")
            
            if Prompt.ask("    Run dependency installer now to get Git?", choices=["y", "n"], default="y") == "y":
                try:
                    self.console.print("[dim]Launching installer...[/dim]")
                    subprocess.run(["powershell", "-ExecutionPolicy", "Bypass", "-File", "install_deps.ps1"], check=True)
                    self.console.print("[green]✔ Installer finished. Please try 'Update' again.[/green]")
                except Exception as e:
                     self.console.print(f"[red]! Failed to launch installer: {e}[/red]")
            else:
                 self.console.print("Please run 'install_deps.ps1' manually.")
        except Exception as e:
            self.console.print(f"[bold red]! Error during update: {e}[/bold red]")

    def display_help(self):
        self.console.rule("[bold white]OMNISCIENT MANUAL[/bold white]")
        help_text = """
[bold white]1. System Reconnaissance[/bold white]
[dim]Description:[/dim] Gathers core OS metrics, build version, installed hotfixes (security patches), and architecture info.
[dim]Example:[/dim] Use first to check if the target is an outdated Windows build (e.g., Win 7/Server 2008) missing critical KBs.

[bold white]2. Configuration Hardening[/bold white]
[dim]Description:[/dim] Audits built-in security features. Checks UAC status, Firewall profiles (Domain/Private/Public), and Unquoted Service Paths.
[dim]Example:[/dim] Detects if UAC is disabled (Level 0) or if the Firewall is off for Public networks.

[bold white]3. Advanced Threat Detection[/bold white]
[dim]Description:[/dim] Scans running processes and services for anomalies. Looks for unsigned binaries in system folders and known malware names.
[dim]Example:[/dim] Identifying a process named `svchost.exe` running from `C:\\Temp\\` (legitimate path is `System32`).

[bold white]4. Network Analysis[/bold white]
[dim]Description:[/dim] Performs a local port scan (127.0.0.1) and audits DNS/Hosts file.
[dim]Example:[/dim] Flags Port 445 (SMB) or 3389 (RDP) if exposed on a Public interface. Detects weird entries in `etc/hosts`.

[bold white]5. Identity & Access[/bold white]
[dim]Description:[/dim] Enumerates local users, groups, and privilege levels. Specifically looks for new administrators or Guest accounts.
[dim]Example:[/dim] Finds a hidden user "Admin2" added to the local Administrators group yesterday.

[bold white]6. Deep Persistence[/bold white]
[dim]Description:[/dim] Hunts for mechanisms attackers use to survive reboots. Scans Run Keys, Startup Folders, and Scheduled Tasks.
[dim]Example:[/dim] Locating a malicious script `updater.vbs` hidden in the detailed Scheduled Tasks list.

[bold white]7. Digital Forensics[/bold white]
[dim]Description:[/dim] Extract browser artifacts (history/downloads) and searches for sensitive files (pem/ppk/config) on disk.
[dim]Example:[/dim] Recovering a downloaded malware file path from Chrome history or finding an AWS key in `C:\\Users\\...`.

[bold white]8. External Tool Bridge[/bold white]
[dim]Description:[/dim] A wrapper to execute your own Red Team binaries safely. Checks if they run or get blocked by AV.
[dim]Action:[/dim] Drop `mimikatz.exe` or `seatbelt.exe` into the `tools/` folder.
[dim]Example:[/dim] Running Mimikatz to test if Credential Guard can be bypassed.

[bold white]10. Event Log Hunter[/bold white]
[dim]Description:[/dim] Deep dive into Windows Event Logs (Security/System/PowerShell). Hunts for IOCs like Log Clearing (1102) or Obfuscated PowerShell (4104).
[dim]Example:[/dim] Finding evidence of an attacker clearing logs to cover tracks or running `EncodedCommand` PowerShell.

[bold white]11. Live Connection Map[/bold white]
[dim]Description:[/dim] Maps active TCP/UDP connections to specific Process IDs (PIDs) and names. Checks against known risky ports.
[dim]Example:[/dim] Seeing `powershell.exe` establishing an outbound connection to a foreign IP on port 4444.

[bold white]12. Physical Device Trace (USB)[/bold white]
[dim]Description:[/dim] Forensic scan of Registry keys (`USBSTOR`) to list every USB device ever connected.
[dim]Example:[/dim] Identifying a "Rubber Ducky" or a specific flash drive used to exfiltrate data on a specific date.

[bold white]13. INITIATE TOTAL AUDIT[/bold white]
[dim]Description:[/dim] Runs ALL of the above modules sequentially and generates a comprehensive HTML artifact.
[dim]Use Case:[/dim] Run this for a complete system baseline or post-incident triage.
"""
        self.console.print(Panel(help_text, border_style="dim white", title="[bold]Detailed Operational Guide[/bold]", expand=False))

    def run_visual_module_with_report_prompt(self, name, func, category):
        self.console.rule(f"[bold]{name}")
        findings = func()
        if not isinstance(findings, list): findings = []
        for f in findings:
            if 'category' not in f: f['category'] = category
        self.print_findings(findings)
        
        if Prompt.ask("\n[bold white]Generate Report Artifact?[/bold white]", choices=["y", "n"], default="n") == "y":
            self.console.print("[dim]Compiling Artifact...[/dim]")
            html_path = self.reporter.generate_html(self.last_system_info, findings, report_name=name)
            self.console.print(f"[white]✔ Artifact Ready:[/white] {html_path}")
            try: os.startfile(html_path)
            except: pass

    # Wrappers
    def run_recon(self):
        info = self.recon.get_system_info()
        self.last_system_info = info 
        table = Table(title="System Attributes", expand=True, style="white")
        table.add_column("Property", style="bold white")
        table.add_column("Value", style="dim white")
        for k, v in info.items():
            table.add_row(str(k), escape(str(v)))
        self.console.print(table)
        hotfixes = self.recon.get_hotfixes()
        self.console.print(f"\n[bold]Installed Hotfixes:[/bold] {len(hotfixes)}")
        for h in hotfixes[:5]:
            self.console.print(f" - {h['HotFixID']} ({h['Description']})")
        return []

    def run_basic_audit(self): return ConfigAudit(self.console, self.wmi_client).audit_all()
    def run_advanced_audit(self): return self.adv_auditor.run_all_checks()
    def run_network_audit(self): return self.net_auditor.run_network_audit()
    def run_user_audit(self): return self.user_auditor.run_audit()
    def run_persistence_audit(self): return self.persist_auditor.run_audit()
    
    def run_forensics_audit(self):
        f = self.browser_auditor.run_audit()
        f.extend(self.sensitive_auditor.run_audit())
        return f

    def run_full_audit_with_report(self):
        self.console.rule("[bold red]OMNISCIENT: TOTAL AUDIT[/bold red]")
        self.all_findings = []
        
        self.run_recon() # Refresh Cache
        
        analyzers = [
            ("Hardening", self.run_basic_audit, "Hardening"),
            ("Advanced Threat", self.run_advanced_audit, "Advanced Threat"),
            ("Network", self.run_network_audit, "Network"),
            ("Identity", self.run_user_audit, "Identity"),
            ("Persistence", self.run_persistence_audit, "Persistence"),
            ("Forensics", self.run_forensics_audit, "Forensics"),
            ("Event Logs", self.event_auditor.run_audit, "Logs"),
            ("Connection Map", self.conn_auditor.run_audit, "Network"),
            ("USB Forensics", self.usb_auditor.run_audit, "Physical"),
            ("Arsenal Bridge", self.arsenal_auditor.run_audit, "Arsenal")
        ]
        
        for name, func, cat in analyzers:
            self.console.print(f"\n[bold cyan]>> ANALYZING SECTOR: {name.upper()}[/bold cyan]")
            try:
                res = func()
                if res and isinstance(res, list):
                    for r in res: r['category'] = cat
                    self.all_findings.extend(res)
                    # Show immediate results for this sector
                    self.print_findings(res, title=f"Local Findings: {name}")
                else:
                    self.console.print(f"[dim]No signals detected in {name}[/dim]")
            except Exception as e:
                self.console.print(f"[bold red]!! Error in {name}: {e}[/bold red]")
        
        self.console.rule("[bold white]AUDIT COMPLETE: GENERATING ARTIFACT[/bold white]")
        html_path = self.reporter.generate_html(self.last_system_info, self.all_findings, report_name="Total_Audit")
        
        self.console.print(f"[bold green]✔ Artifact Ready:[/bold green] {html_path}")
        try: os.startfile(html_path) 
        except: pass

    def print_findings(self, findings, title="Sector Findings"):
        if not findings:
            self.console.print("[dim white]No signals detected.[/dim white]")
            return

        table = Table(title=title, expand=True, style="grey30", border_style="grey30")
        table.add_column("LVL", style="bold", width=8, justify="center")
        table.add_column("SCOPE", style="cyan dim", width=12)
        table.add_column("CHECK", style="white")
        table.add_column("STATUS", style="dim")
        table.add_column("DATA", style="grey70")
        
        severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        findings.sort(key=lambda x: severity_order.get(x.get('severity', 'Info'), 99))

        for f in findings:
            sev = str(f.get('severity', 'Info'))
            # Vibrant Color Coding
            if sev == "Critical":
                sev_style = "bold red on black"
                sev_label = "CRIT"
            elif sev == "High":
                sev_style = "bold orange3"
                sev_label = "HIGH"
            elif sev == "Medium":
                sev_style = "yellow"
                sev_label = "MED"
            elif sev == "Low":
                sev_style = "blue"
                sev_label = "LOW"
            else:
                sev_style = "dim white"
                sev_label = "INFO"
            
            table.add_row(
                Text(sev_label, style=sev_style),
                Text(f.get('category', 'General')[:10].upper()),
                str(f.get('check', 'N/A')),
                str(f.get('status', 'N/A')),
                str(f.get('details', '')) # No truncation
            )
        self.console.print(table)

if __name__ == "__main__":
    menu = OmniscientMenu()
    menu.main_loop()
