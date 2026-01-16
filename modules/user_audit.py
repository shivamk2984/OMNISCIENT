import subprocess

class UserAuditor:
    def __init__(self, wmi_client):
        self.wmi_client = wmi_client

    def run_audit(self):
        findings = []
        findings.extend(self.audit_users())
        findings.extend(self.check_admin_group())
        return findings

    def audit_users(self):
        findings = []
        if not self.wmi_client:
            return findings

        try:
            # Win32_UserAccount
            users = self.wmi_client.Win32_UserAccount(LocalAccount=True)
            for user in users:
                # Check for Password Required
                if not user.PasswordRequired:
                     findings.append({
                        "severity": "Critical",
                        "check": f"User Account: {user.Name}",
                        "status": "FAIL",
                        "details": "Password is NOT required for this account."
                    })
                
                # Check for Password Expires (PasswordChangeable=False often implies specific service accounts that don't expire, but worth checking expiration flags if available)
                # WMI UserAccount doesn't expose 'PasswordExpires' easily without AD ADSI, but valid simple check is Disabled status
                
                if user.Name == "Guest":
                    if not user.Disabled:
                         findings.append({
                            "severity": "High",
                            "check": "Guest Account",
                            "status": "FAIL",
                            "details": "Guest account is ENABLED. Standard security practice is to disable."
                        })
                    else:
                        findings.append({
                            "severity": "Info",
                            "check": "Guest Account",
                            "status": "PASS",
                            "details": "Guest account is disabled."
                        })
                        
                # Check for Administrator account rename (Security through obscurity, but CIS recommendation)
                if user.SID.endswith("-500") and user.Name == "Administrator":
                     findings.append({
                        "severity": "Low",
                        "check": "Admin Account Name",
                        "status": "WARN",
                        "details": "Built-in Administrator account is named 'Administrator'. Renaming is a hardening best practice."
                    })

        except Exception as e:
            findings.append({"severity": "Error", "check": "User Audit", "status": "ERROR", "details": str(e)})
            
        return findings

    def check_admin_group(self):
        findings = []
        try:
            # Use net localgroup because WMI group mapping is complex/slow
            output = subprocess.check_output("net localgroup Administrators", shell=True).decode(errors='ignore')
            lines = output.split('\n')
            
            # Parse members (usually start after "-----------------")
            members = []
            parsing = False
            for line in lines:
                if "-------" in line:
                    parsing = True
                    continue
                if parsing and line.strip() and "The command completed" not in line:
                    members.append(line.strip())
            
            if len(members) > 3:
                 findings.append({
                        "severity": "Medium",
                        "check": "Admin Group Count",
                        "status": "WARN",
                        "details": f"There are {len(members)} users in the Administrators group. Review for least privilege."
                    })
            
            findings.append({
                "severity": "Info",
                "check": "Admin Group Membership",
                "status": "INFO",
                "details": f"Admins: {', '.join(members)}"
            })

        except Exception as e:
             findings.append({"severity": "Error", "check": "Admin Group Check", "status": "ERROR", "details": str(e)})
        
        return findings
