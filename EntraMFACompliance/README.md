# MS 365 Entra ID MFA Compliance Tool

> Automated compliance monitoring for MS 365 Entra ID to meet SOC 2, ISO 27001, and NIST requirements.

## Overview

This PowerShell tool automates the weekly monitoring of:
- User account status (Active, Inactive, Disabled)
- MFA authentication method configuration
- MFA drift detection (changes from baseline)
- Compliance reporting for audit trails

**Designed for**: Small business IT technicians managing <50 users per client
**Skill Level**: Novice-friendly with extensive inline comments
**License Required**: Azure AD Premium P2

---

## Features

✅ **User Status Classification**
- Active: Successful sign-in within 20 days
- Inactive: No sign-in for 21+ days (stale account flagging)
- Disabled: Account explicitly disabled

✅ **MFA Drift Detection**
- Tracks all authentication methods (Authenticator app, Phone, Email, FIDO2, Windows Hello, etc.)
- Detects changes in default method, method count, or method types
- Classifies drift severity: Critical, High, Medium, Low, None
- Creates baseline on first run for future comparisons

✅ **Compliance Reporting**
- CSV reports with executive summary
- Tracks all required user fields (UPN, department, licenses, sign-in dates)
- Flags compliance violations (NoMFA, StaleAccount)
- Automatic retention management (60 days default)

✅ **Automation Ready**
- Designed for Windows Task Scheduler
- Supports WhatIf testing mode
- Comprehensive logging for troubleshooting
- Auto-cleanup of old files

---

## Prerequisites

### 1. PowerShell 7.0+
Check your version:
```powershell
$PSVersionTable.PSVersion
```

Install PowerShell 7 if needed:
- Download from: https://github.com/PowerShell/PowerShell/releases

### 2. Microsoft Graph PowerShell Modules
Install required modules:
```powershell
Install-Module -Name Microsoft.Graph.Authentication -Scope CurrentUser
Install-Module -Name Microsoft.Graph.Users -Scope CurrentUser
Install-Module -Name Microsoft.Graph.Identity.SignIns -Scope CurrentUser
```

### 3. Azure AD App Registration
You need an Azure AD App Registration with the following API permissions:

**Required Permissions** (Application type):
- `User.Read.All`
- `UserAuthenticationMethod.Read.All`
- `AuditLog.Read.All`
- `Directory.Read.All`

**See the [Setup Guide](SETUP_GUIDE.md) for detailed app registration walkthrough.**

### 4. Azure AD Premium P2 License
The script requires Azure AD Premium P2 for:
- `signInActivity` data (last sign-in dates)
- MFA authentication method reporting

---

## Quick Start

### Step 1: Download and Extract
1. Download the entire `EntraMFACompliance` folder
2. Place it in a secure location (e.g., `C:\Scripts\EntraMFACompliance\`)

### Step 2: Configure Azure App Registration
Follow the [SETUP_GUIDE.md](SETUP_GUIDE.md) to create and configure your Azure AD App Registration.

You'll need:
- **Tenant ID** (from Azure Portal > Azure Active Directory > Properties)
- **Client ID** (from App Registration > Overview)
- **Client Secret** (from App Registration > Certificates & secrets)

### Step 3: Test the Script
Run the script manually to test:

```powershell
cd C:\Scripts\EntraMFACompliance

.\Invoke-EntraMFACompliance.ps1 `
    -TenantId "YOUR-TENANT-ID" `
    -ClientId "YOUR-CLIENT-ID"
```

You'll be prompted for the **Client Secret** securely.

**First Run Behavior:**
- No previous baseline exists, so one will be created
- All non-compliant users will be flagged
- Baseline is saved for next week's drift detection

### Step 4: Review Output
After successful execution, check:

📁 **`./reports/EntraMFA_Report_YYYY-MM-DD.csv`**
- Contains all user data and compliance status
- Includes summary header with statistics

📁 **`./baselines/EntraMFA_Baseline_YYYY-MM-DD.json`**
- Snapshot of current MFA state for drift comparison

📁 **`./logs/EntraCompliance_YYYY-MM-DD_HHMMSS.log`**
- Detailed execution log for troubleshooting

---

## Running Weekly (Automated)

### Option 1: Windows Task Scheduler

1. **Create a new scheduled task:**
   - Open Task Scheduler (`taskschd.msc`)
   - Action > Create Task

2. **General Tab:**
   - Name: `Entra MFA Compliance Scan`
   - Description: Weekly MFA drift detection and compliance reporting
   - Security Options: ☑ Run whether user is logged on or not
   - Security Options: ☑ Run with highest privileges

3. **Triggers Tab:**
   - New > Weekly
   - Start: Monday at 6:00 AM
   - Recur every: 1 week

4. **Actions Tab:**
   - Action: Start a program
   - Program/script: `pwsh.exe`
   - Arguments:
     ```
     -ExecutionPolicy Bypass -File "C:\Scripts\EntraMFACompliance\Invoke-EntraMFACompliance.ps1" -TenantId "YOUR-TENANT-ID" -ClientId "YOUR-CLIENT-ID"
     ```

5. **Conditions Tab:**
   - ☐ Start the task only if the computer is on AC power (uncheck for laptops)

6. **Settings Tab:**
   - ☑ Allow task to be run on demand
   - ☑ If task fails, restart every: 10 minutes (3 attempts)

**Note:** The task will prompt for the client secret. For fully unattended execution, see **Advanced: Storing Secrets** below.

---

## Understanding the Report

### CSV Report Structure

```csv
# MS 365 Entra ID MFA Compliance Report
# Generated: 2025-10-07 06:00:00
# Total Users: 42
# Active Users: 35
# Inactive Users: 5
# Disabled Users: 2
# Users with MFA Drift: 3
# Critical Findings: 1
# High Findings: 2
#
UserPrincipalName,DisplayName,Department,Status,AccountEnabled,...
```

### Key Columns

| Column | Description |
|--------|-------------|
| `Status` | Active / Inactive / Disabled |
| `DaysSinceLastSignIn` | Days since last successful sign-in |
| `MFA_DefaultMethod` | Current default MFA method |
| `MFA_MethodCount` | Number of registered MFA methods |
| `MFA_Methods` | Comma-separated list of method types |
| `MFA_DriftStatus` | Critical / High / Medium / Low / None |
| `MFA_DriftDetails` | Description of what changed |
| `ComplianceFlags` | NoMFA, StaleAccount, etc. |

### Drift Severity Levels

| Severity | Meaning | Example |
|----------|---------|---------|
| **Critical** | MFA completely removed | User had 2 methods, now has 0 |
| **High** | Methods dropped below minimum (2) or default changed from Authenticator | Default changed from MicrosoftAuthenticator to Phone |
| **Medium** | Methods changed but not critical | Added Email method, removed Phone |
| **Low** | Improvements detected | Methods increased from 2 to 3 |
| **None** | No drift or compliant state | No changes detected |

---

## Testing & Validation

### Test Mode (WhatIf)
Run without saving files:
```powershell
.\Invoke-EntraMFACompliance.ps1 -TenantId "xxx" -ClientId "yyy" -WhatIf
```

### Create Test Baseline
Use the helper script to generate a sample baseline for testing:
```powershell
.\New-TestBaseline.ps1 -OutputPath "./baselines/EntraMFA_Baseline_2025-10-01.json"
```

Then run the compliance scan to detect drift against the test baseline.

---

## Troubleshooting

### Error: "Required module not installed"
**Solution:** Install missing modules:
```powershell
Install-Module -Name Microsoft.Graph.Authentication -Scope CurrentUser
Install-Module -Name Microsoft.Graph.Users -Scope CurrentUser
Install-Module -Name Microsoft.Graph.Identity.SignIns -Scope CurrentUser
```

### Error: "Failed to connect to Graph API"
**Possible Causes:**
1. **Invalid Tenant ID or Client ID** - Verify GUIDs are correct
2. **Incorrect Client Secret** - Regenerate in Azure Portal
3. **Missing API Permissions** - Grant admin consent in Azure Portal
4. **Firewall blocking graph.microsoft.com** - Check network connectivity

**Test connectivity:**
```powershell
Test-NetConnection -ComputerName graph.microsoft.com -Port 443
```

### Error: "Insufficient privileges to complete the operation"
**Solution:** App Registration needs admin consent for API permissions:
1. Azure Portal > App Registrations > Your App
2. API Permissions tab
3. Click "Grant admin consent for [Tenant]"

### Warning: "signInActivity" data not available
**Cause:** Azure AD Premium P1/P2 required for sign-in activity data
**Solution:** Verify your license includes Azure AD Premium

### Baseline file corrupted or missing
**First Run:** Normal - baseline will be created
**Subsequent Runs:** Previous baseline not found - script will create new baseline

---

## Advanced Configuration

### Customizing Thresholds
Edit the script variables (lines 80-85):
```powershell
$script:ActiveUserDays = 20          # Change to 30 for longer active window
$script:InactiveDays = 21            # Change to 31 to match
$script:MinimumMFAMethods = 2        # Change to 3 for stricter compliance
$script:PreferredDefaultMethod = "microsoftAuthenticator"
```

### Storing Secrets (Unattended Execution)
For fully automated scheduled tasks, you have options:

**Option 1: Windows Credential Manager (Recommended for novices)**
```powershell
# Store secret once
$clientSecret = Read-Host -AsSecureString -Prompt "Enter Client Secret"
$credential = New-Object System.Management.Automation.PSCredential("ClientSecret", $clientSecret)
$credential.Password | ConvertFrom-SecureString | Set-Content ".\secret.txt"

# Modify script to load from file (not recommended for production)
```

**Option 2: Azure Key Vault (Recommended for production)**
- Store client secret in Azure Key Vault
- Grant Managed Identity access to retrieve secret
- Modify script to fetch secret from Key Vault

**Option 3: Certificate-based Authentication (Most secure)**
- Use certificate instead of client secret
- No secret storage required
- Modify script to use `Connect-MgGraph -CertificateThumbprint`

---

## Multi-Tenant Support (Future)

Current design: Single tenant per execution

To run for multiple clients:
1. Create separate config files per tenant (e.g., `config-client1.json`, `config-client2.json`)
2. Schedule separate tasks for each client tenant
3. Use different output folders per client

**Future Enhancement:** Loop through array of tenants in single execution

---

## Compliance Mapping

This tool supports audit requirements for:

| Framework | Control | Requirement | How This Tool Helps |
|-----------|---------|-------------|---------------------|
| **SOC 2** | CC6.1 | Logical access controls including MFA | Reports users without MFA, tracks MFA drift |
| **ISO 27001** | A.9.4.2 | Secure log-on procedures | Identifies stale accounts, monitors MFA compliance |
| **NIST 800-53** | IA-2(1) | Multi-factor authentication | Detects MFA removal, enforces minimum 2 methods |

**Audit Evidence:**
- Weekly CSV reports serve as compliance evidence
- Baselines demonstrate continuous monitoring
- Logs provide audit trail of scans

---

## File Retention

By default, files older than **60 days** are automatically deleted:
- Baselines: `./baselines/EntraMFA_Baseline_*.json`
- Reports: `./reports/EntraMFA_Report_*.csv`
- Logs: `./logs/EntraCompliance_*.log`

To change retention period, edit line 84:
```powershell
$script:BaselineRetentionDays = 90   # Keep for 90 days
```

---

## Security Best Practices

🔒 **Never commit secrets to version control**
- Add `config.json` to `.gitignore`
- Use `config.EXAMPLE.json` as template

🔒 **Restrict access to script folder**
- Only authorized personnel should access the folder
- Use NTFS permissions to restrict access

🔒 **Rotate client secrets regularly**
- Regenerate secrets every 90 days
- Update scheduled tasks with new secrets

🔒 **Monitor for unauthorized changes**
- Review logs for unexpected activity
- Alert on critical drift findings

🔒 **Use Managed Identity when possible**
- If running in Azure (e.g., Azure Automation), use Managed Identity instead of client secrets

---

## Support & Resources

📖 **Microsoft Graph API Documentation**
https://learn.microsoft.com/en-us/graph/api/resources/users

📖 **Azure AD App Registration Guide**
See [SETUP_GUIDE.md](SETUP_GUIDE.md)

📖 **WITCHCRAFT Specification**
See [Entra_MFA_Compliance_Witchcraft_Spec.txt](../Entra_MFA_Compliance_Witchcraft_Spec.txt)

🐛 **Issues & Feedback**
Contact: services@bansheecybersecurity.com

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2025-10-07 | Initial release with baseline drift detection |

---

## License

Copyright © 2025 Banshee Cybersecurity
Designed for small business compliance automation (<50 users per tenant)

---

## Credits

**Framework:** WITCHCRAFT Prompt Specification
**Compliance Standards:** SOC 2, ISO 27001, NIST 800-53
**Built with:** Microsoft Graph PowerShell SDK
