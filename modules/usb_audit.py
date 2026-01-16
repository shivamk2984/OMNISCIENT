import winreg
import re

class UsbForensics:
    def __init__(self, console):
        self.console = console

    def run_audit(self):
        findings = []
        self.console.print("[dim]   - Auditing USBSTOR Registry Hive...[/dim]")
        findings.extend(self.check_usb_stor())
        
        self.console.print("[dim]   - Correlating Mounted Devices...[/dim]")
        findings.extend(self.check_mounted_devices())
        return findings

    def check_usb_stor(self):
        findings = []
        # Key: SYSTEM\CurrentControlSet\Enum\USBSTOR
        # Structure: Vendor_Prod_Rev -> SerialNumber -> Properties
        try:
            base_path = r"SYSTEM\CurrentControlSet\Enum\USBSTOR"
            base_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base_path, 0, winreg.KEY_READ)
            subkey_count = winreg.QueryInfoKey(base_key)[0]
            
            for i in range(subkey_count):
                device_id = winreg.EnumKey(base_key, i)
                # Now open device_id key
                dev_key_path = f"{base_path}\\{device_id}"
                dev_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, dev_key_path, 0, winreg.KEY_READ)
                
                # Enumerate serial numbers (instances)
                serial_count = winreg.QueryInfoKey(dev_key)[0]
                for j in range(serial_count):
                    serial = winreg.EnumKey(dev_key, j)
                    
                    # Get FriendlyName if possible
                    friendly_name = "Unknown Device"
                    try:
                        instance_path = f"{dev_key_path}\\{serial}"
                        inst_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, instance_path, 0, winreg.KEY_READ)
                        friendly_name, _ = winreg.QueryValueEx(inst_key, "FriendlyName")
                        winreg.CloseKey(inst_key)
                    except: pass
                    
                    findings.append({
                         "severity": "Info", # Info unless we find a rubber ducky signature
                         "check": "USB Usage History",
                         "status": "INFO",
                         "details": f"Device: {friendly_name} | ID: {device_id} | Serial: {serial}"
                    })
                    
                    # Heuristic for malicious USBs (Rubber Ducky, Bash Bunny often have specific VID/PID or names)
                    if "ducky" in friendly_name.lower() or "badusb" in friendly_name.lower():
                         findings.append({
                             "severity": "Critical",
                             "check": "Malicious USB Detection",
                             "status": "FAIL",
                             "details": f"Potential Attack Hardware detected: {friendly_name}"
                        })

                winreg.CloseKey(dev_key)
            winreg.CloseKey(base_key)
        except Exception:
            pass
        return findings

    def check_mounted_devices(self):
        findings = []
        # HKLM\SYSTEM\MountedDevices
        # Maps DOS devices (E:, F:) to Volume GUIDs
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\MountedDevices", 0, winreg.KEY_READ)
            info = winreg.QueryInfoKey(key)
            count = info[1] # Value count
            
            usb_mounts = 0
            for i in range(count):
                name, data, _ = winreg.EnumValue(key, i)
                if "\\DosDevices\\" in name:
                    # Data is binary, contains checks for USB prefix usually
                    # 5c 00 3f 00 ( \ ? ) ...
                    try:
                        decoded = data.decode('utf-16le', errors='ignore')
                        if "USBSTOR" in decoded or "RemovableMedia" in decoded:
                            usb_mounts += 1
                    except: pass
            
            if usb_mounts > 0:
                 findings.append({
                     "severity": "Info",
                     "check": "USB Mount Count",
                     "status": "INFO",
                     "details": f"Found {usb_mounts} drive letter mappings associated with Removable Media in history."
                })
            winreg.CloseKey(key)
        except: pass
        return findings
