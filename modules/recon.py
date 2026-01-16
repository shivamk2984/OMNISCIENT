import platform
import subprocess
import os
import socket
from datetime import datetime
try:
    import wmi
except ImportError:
    wmi = None

from rich.markup import escape

class SystemRecon:
    def __init__(self, console):
        self.console = console
        self.wmi_client = wmi.WMI() if wmi else None

    def _parse_wmi_time(self, wmi_time):
        if not wmi_time: return "Unknown"
        try:
            dt_str = wmi_time.split('.')[0]
            dt = datetime.strptime(dt_str, "%Y%m%d%H%M%S")
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except:
            return wmi_time

    def get_system_info(self):
        self.console.print("Gathering detailed system metrics...")
        info = {}
        
        # Basic Platform Info
        info['Hostname'] = platform.node()
        info['OS'] = platform.system()
        info['Architecture'] = platform.machine()
        
        if self.wmi_client:
            try:
                # Operating System
                os_info = self.wmi_client.Win32_OperatingSystem()[0]
                info['OS Name'] = os_info.Caption
                info['OS Version'] = os_info.Version
                info['Build Number'] = os_info.BuildNumber
                info['Registered User'] = os_info.RegisteredUser or "N/A"
                info['Organization'] = os_info.Organization or "N/A"
                info['Serial Number'] = os_info.SerialNumber
                info['Install Date'] = self._parse_wmi_time(os_info.InstallDate)
                info['Last Boot'] = self._parse_wmi_time(os_info.LastBootUpTime)
                
                # Hardware
                cs_info = self.wmi_client.Win32_ComputerSystem()[0]
                info['Manufacturer'] = cs_info.Manufacturer
                info['Model'] = cs_info.Model
                info['System Type'] = cs_info.SystemType
                info['Domain'] = cs_info.Domain
                try:
                    ram_gb = round(int(cs_info.TotalPhysicalMemory) / (1024**3), 2)
                    info['Total RAM'] = f"{ram_gb} GB"
                except:
                    info['Total RAM'] = "Unknown"
                
                # BIOS
                bios_info = self.wmi_client.Win32_BIOS()[0]
                info['BIOS Version'] = bios_info.Version
                
                # Processor
                cpu_info = self.wmi_client.Win32_Processor()[0]
                info['Processor'] = cpu_info.Name.strip()

                # Network
                ip_addr = "Unknown"
                mac_addr = "Unknown"
                for nic in self.wmi_client.Win32_NetworkAdapterConfiguration(IPEnabled=True):
                    if nic.IPAddress:
                        ip_addr = nic.IPAddress[0]
                        mac_addr = nic.MACAddress
                        break
                info['IP Address'] = ip_addr
                info['MAC Address'] = mac_addr

            except Exception as e:
                self.console.print(f"[red]Error fetching WMI data: {escape(str(e))}[/red]")
                info['Processor'] = platform.processor()
        else:
             info['Processor'] = platform.processor()
             info['OS Version'] = platform.version()

        return info

    def get_hotfixes(self):
        """
        Retrieves installed hotfixes using WMI or systeminfo command fallback.
        """
        hotfixes = []
        if self.wmi_client:
            try:
                for patch in self.wmi_client.Win32_QuickFixEngineering():
                    # Check for None attributes
                    desc = patch.Description or "Unknown"
                    hotfixes.append({
                        'HotFixID': patch.HotFixID,
                        'InstalledOn': patch.InstalledOn,
                        'Description': desc
                    })
            except Exception as e:
                self.console.print(f"[red]WMI Hotfix scan failed: {escape(str(e))}[/red]")
        
        # Fallback if WMI failed or returned nothing (some minimal environments)
        if not hotfixes:
            self.console.print("[yellow]Attempting fallback hotfix scan via systeminfo...[/yellow]")
            try:
                # This is a bit heavy, strictly fallback
                output = subprocess.check_output("systeminfo", shell=True).decode(errors='ignore')
                for line in output.split('\n'):
                    if "KB" in line:
                        # rigorous parsing needed here, simplistic check
                        parts = line.split()
                        for part in parts:
                            if part.startswith("KB") and part[2:].isdigit():
                                hotfixes.append({'HotFixID': part})
            except Exception as e:
                 self.console.print(f"[red]Fallback scan failed: {escape(str(e))}[/red]")
                 
        return hotfixes
