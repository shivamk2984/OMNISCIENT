import win32evtlog
import subprocess
import re

class EventLogAuditor:
    def __init__(self, console):
        self.console = console

    def run_audit(self):
        findings = []
        
        self.console.print("[dim]   - Deep Scan: Security Event Log (IOCs)...[/dim]")
        findings.extend(self.scan_security_log())
        
        self.console.print("[dim]   - Deep Scan: System Log (Services & Drivers)...[/dim]")
        findings.extend(self.scan_system_log())
        
        self.console.print("[dim]   - Deep Scan: PowerShell Operational (Script Block Logging)...[/dim]")
        findings.extend(self.scan_powershell_logs())
        
        self.console.print("[dim]   - Deep Scan: RDP & Local Session Manager...[/dim]")
        findings.extend(self.scan_rdp_logs())
        
        return findings

    def scan_security_log(self):
        findings = []
        log_type = 'Security'
        # Expanded Event ID List
        critical_events = {
            1102: {"risk": "Critical", "msg": "Audit Log Cleared! Evidence destruction."},
            4720: {"risk": "High", "msg": "User Account Created."},
            4726: {"risk": "Medium", "msg": "User Account Deleted."},
            4732: {"risk": "High", "msg": "User Added to Local Admin Group."},
            4728: {"risk": "High", "msg": "User Added to Global Security Group."},
            4799: {"risk": "Medium", "msg": "Security-Enabled Local Group Membership Enumerated (Recon)."},
            4688: {"risk": "Low", "msg": "New Process Created (Verbose)."}, # Only if Command Line auditing is on
            4625: {"risk": "Medium", "msg": "Failed Logon (Potential Brute Force)."}
        }
        
        try:
            hand = win32evtlog.OpenEventLog(None, log_type)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            total_read = 0
            
            while True:
                events = win32evtlog.ReadEventLog(hand, flags, 0)
                if not events: break
                
                for event in events:
                    if event.EventID in critical_events:
                        info = critical_events[event.EventID]
                        
                        # Filter out noise (e.g. system accounts enumerating groups)
                        if event.EventID == 4799 and "Window Manager" in str(event.StringInserts):
                            continue

                        findings.append({
                            "severity": info['risk'],
                            "check": f"Security Log: {event.EventID}",
                            "status": "WARN",
                            "details": f"{info['msg']} [{event.TimeGenerated}]"
                        })
                
                total_read += len(events)
                if total_read > 3000: break # Scan last 3000 events
            win32evtlog.CloseEventLog(hand)
        except: pass
        return findings

    def scan_system_log(self):
        findings = []
        try:
            hand = win32evtlog.OpenEventLog(None, 'System')
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            total = 0
            while True:
                events = win32evtlog.ReadEventLog(hand, flags, 0)
                if not events: break
                for event in events:
                    # 7045 = New Service Installed
                    if event.EventID == 7045:
                        data = event.StringInserts
                        svc_name = data[0] if data else "Unknown"
                        img = data[1] if len(data)>1 else "Unknown"
                        user = data[2] if len(data)>2 else "Unknown"
                        
                        # Filter out benign system services if needed, but 7045 is rare enough to log all
                        findings.append({
                            "severity": "High",
                            "check": "Service Install (7045)",
                            "status": "WARN",
                            "details": f"Service Installed: {svc_name} | Path: {img} | User: {user} [{event.TimeGenerated}]"
                        })
                    
                    # 7036 = Service entered stopped/running state (Noise? Maybe useful for identifying shutdowns of AV)
                    if event.EventID == 7036:
                        data = event.StringInserts
                        if data and ("Windows Defender" in data[0] or "Antivirus" in data[0]) and "stopped" in data:
                             findings.append({
                                "severity": "High",
                                "check": "AV Service Stopped",
                                "status": "FAIL",
                                "details": f"Security Service Stopped: {data[0]} [{event.TimeGenerated}]"
                            })

                total += len(events)
                if total > 2000: break
            win32evtlog.CloseEventLog(hand)
        except: pass
        return findings

    def scan_powershell_logs(self):
        """
        Uses PowerShell to query Microsoft-Windows-PowerShell/Operational for malicious script blocks.
        """
        findings = []
        # Event 4104: Script Block Logging
        # We look for keywords like "EncodedCommand", "Invoke-Expression", "DownloadString"
        cmd = r'Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 200 | Where-Object {$_.Id -eq 4104} | Select-Object -ExpandProperty Message'
        
        try:
            output = subprocess.check_output(["powershell", "-Command", cmd], stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW).decode(errors='ignore')
            
            suspicious_terms = ["EncodedCommand", "FromBase64String", "iex", "Invoke-Expression", "Net.WebClient", "DownloadString", "Bypass"]
            
            for line in output.split('\n'):
                line = line.strip()
                if not line: continue
                
                for term in suspicious_terms:
                    if term.lower() in line.lower():
                        findings.append({
                            "severity": "Critical",
                            "check": "PowerShell ScriptBlock",
                            "status": "FAIL",
                            "details": f"Suspicious PowerShell Content Found: '{term}'. Sample: {line[:50]}..."
                        })
                        break # One hit per block is enough
        except:
            # Log might be empty or disabled
            pass
        return findings

    def scan_rdp_logs(self):
        """
        Checks TerminalServices-LocalSessionManager for remote logins.
        """
        findings = []
        # Event 21: remote logon
        cmd = r'Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" -MaxEvents 100 | Where-Object {$_.Id -eq 21} | Format-List TimeCreated,Message'
        
        try:
            output = subprocess.check_output(["powershell", "-Command", cmd], stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW).decode(errors='ignore')
            
            if "Source Network Address" in output:
                # Basic parsing needed, output is in list format
                # We'll just flag that RDP activity exists regardless of IP for now, 
                # or try to extract IP.
                findings.append({
                    "severity": "Medium",
                    "check": "RDP Activity",
                    "status": "WARN",
                    "details": "Recent RDP Logons detected in TerminalServices Log. verify Source IPs manually."
                })
        except: pass
        return findings
