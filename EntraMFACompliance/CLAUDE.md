# CLAUDE.md - Project Context & Maintenance Guide

> **Purpose**: Maintain context for AI assistants working on this project
> **Last Updated**: 2025-10-07
> **Project**: MS 365 Entra ID MFA Compliance Tool

---

## 🎯 Project Overview

### **What This Solution Does**
Automated compliance monitoring tool for MS 365 Entra ID that:
- Scans user accounts for status (Active/Inactive/Disabled)
- Tracks MFA authentication methods across all users
- Detects MFA configuration drift from baseline
- Generates weekly compliance reports for SOC 2, ISO 27001, NIST audits
- Flags stale accounts and missing MFA for remediation

### **Who Uses This**
- **Primary**: Compliance analysts at Banshee Cybersecurity
- **Secondary**: Small business IT technicians managing <50 users per client
- **Skill Level**: Novice PowerShell users (extensive inline comments required)

### **Compliance Frameworks Supported**
- SOC 2 (CC6.1: Logical access controls)
- ISO 27001 (A.9.4.2: Secure log-on procedures)
- NIST 800-53 (IA-2(1): Multi-factor authentication)

---

## 📐 Architecture & Design Decisions

### **Framework Used: WITCHCRAFT**
This project was built using the WITCHCRAFT prompt specification framework:
- **W**hy: Problem statement and business value
- **I**nfrastructure: Tech stack and dependencies
- **T**asks: Detailed requirements
- **C**haracter: User personas and skill levels
- **H**arness: Execution and scheduling

See: `../Entra_MFA_Compliance_Witchcraft_Spec.txt` for full specification

### **Key Design Decisions**

| Decision | Rationale | Alternative Considered |
|----------|-----------|------------------------|
| **No email notifications** | User requested removal of email requirement | SMTP delivery to services@bansheecybersecurity.com |
| **Client secret prompting** | Secure runtime input for novice users | Stored encrypted secret, Azure Key Vault |
| **No failed login tracking** | P2 license limitation - audit logs require deep query | Full audit log analysis (performance impact) |
| **Local file storage** | Simple for small businesses (<50 users) | Database backend, SharePoint, Azure Blob |
| **Single-tenant execution** | Designed for expansion to multi-tenant | Multi-tenant loop in single execution |
| **CSV reports** | Universal format, Excel-compatible | HTML reports, JSON exports, Excel .xlsx |

### **Status Classification Logic**
```
IF accountEnabled = FALSE → "Disabled"
ELSE IF lastSuccessfulSignIn ≤ 20 days → "Active"
ELSE IF lastSuccessfulSignIn ≥ 21 days → "Inactive"
ELSE (no sign-in data) → "Inactive"
```

### **MFA Drift Severity Levels**

| Severity | Condition | Example |
|----------|-----------|---------|
| **Critical** | MFA completely removed | Had 2 methods → now 0 |
| **High** | Methods < 2 OR default changed from Authenticator | Default: Authenticator → Phone |
| **Medium** | Methods changed but not critical | Added Email, removed Phone |
| **Low** | Improvements detected | Methods: 2 → 3 |
| **None** | No drift or first-run compliant | No changes detected |

---

## 🛠️ Technical Stack

### **Platform Requirements**
- PowerShell 7.0+ (cross-platform)
- Windows 10/11 or Windows Server 2019+
- Azure AD Premium P2 license
- Internet connectivity to `graph.microsoft.com`

### **PowerShell Modules**
```powershell
Microsoft.Graph.Authentication         # Graph API connection
Microsoft.Graph.Users                  # User data retrieval
Microsoft.Graph.Identity.SignIns       # Sign-in activity & MFA methods
```

### **Azure AD App Registration**
**Required API Permissions** (Application type):
- `User.Read.All` - Read all user profiles
- `UserAuthenticationMethod.Read.All` - Read MFA methods
- `AuditLog.Read.All` - Read sign-in activity
- `Directory.Read.All` - Read directory data (licenses)

**Admin consent required** for all permissions.

---

## 📂 Project Structure

```
EntraMFACompliance/
├── Invoke-EntraMFACompliance.ps1   # Main script (1000+ lines)
├── New-TestBaseline.ps1             # Test baseline generator
├── config.EXAMPLE.json              # Configuration template
├── README.md                        # User documentation
├── SETUP_GUIDE.md                   # Azure AD setup guide
├── CLAUDE.md                        # This file
├── .gitignore                       # Protects secrets
├── baselines/                       # JSON snapshots (git-ignored)
│   └── .gitkeep
├── reports/                         # CSV reports (git-ignored)
│   └── .gitkeep
└── logs/                            # Execution logs (git-ignored)
    └── .gitkeep
```

---

## 🔄 Data Flow

### **Execution Workflow**
```
1. Initialize → Create folders, check prerequisites
2. Authenticate → Connect to Graph API with client secret
3. Load Baseline → Find previous baseline JSON (if exists)
4. Collect Users → Get all users with sign-in activity
5. Process Users → For each user:
   a. Get MFA methods (all types)
   b. Classify status (Active/Inactive/Disabled)
   c. Compare to baseline (detect drift)
   d. Build report record
6. Generate Report → Save CSV with summary header
7. Save Baseline → Store current state as JSON
8. Cleanup → Delete files >60 days old
9. Disconnect → Logout from Graph API
```

### **First Run Behavior**
- No previous baseline exists
- Creates initial baseline from current state
- Flags non-compliant users:
  - Critical: No MFA methods
  - High: <2 MFA methods
  - Medium: Default method not MicrosoftAuthenticator

### **Subsequent Runs**
- Loads previous baseline
- Compares current state to baseline
- Detects changes in:
  - Method count
  - Default method
  - Method types (added/removed)

---

## 📊 Output Files

### **CSV Report** (`reports/EntraMFA_Report_YYYY-MM-DD.csv`)

**Header Section** (commented):
```csv
# MS 365 Entra ID MFA Compliance Report
# Generated: 2025-10-07 06:00:00
# Total Users: 42
# Active Users: 35
# Inactive Users: 5
# ...
```

**Columns** (18 total):
- UserPrincipalName, DisplayName, Department
- Status, AccountEnabled, CreatedDateTime
- LastSignInDateTime, LastSuccessfulSignInDateTime, DaysSinceLastSignIn
- LicenseSKUs
- MFA_DefaultMethod, MFA_MethodCount, MFA_Methods
- MFA_DriftStatus, MFA_DriftDetails
- ComplianceFlags

### **Baseline JSON** (`baselines/EntraMFA_Baseline_YYYY-MM-DD.json`)

**Structure**:
```json
{
  "Metadata": {
    "GeneratedDate": "2025-10-07 06:00:00",
    "ScriptVersion": "1.0.0",
    "UserCount": 42
  },
  "Users": [
    {
      "UserPrincipalName": "user@domain.com",
      "MFA_DefaultMethod": "MicrosoftAuthenticator",
      "MFA_MethodCount": 2,
      "MFA_Methods": "MicrosoftAuthenticator, Phone",
      ...
    }
  ]
}
```

### **Log File** (`logs/EntraCompliance_YYYY-MM-DD_HHMMSS.log`)

**Format**:
```
[2025-10-07 06:00:00] [INFO] Starting Entra MFA Compliance Scan
[2025-10-07 06:00:05] [DEBUG] Querying Graph API for users...
[2025-10-07 06:00:10] [WARNING] No previous baseline found
[2025-10-07 06:01:30] [INFO] Report saved: reports/...
```

---

## 🔧 Configuration & Customization

### **Key Variables** (lines 80-85 in main script)

```powershell
$script:ActiveUserDays = 20          # Active threshold
$script:InactiveDays = 21            # Inactive threshold
$script:BaselineRetentionDays = 60   # File retention
$script:MinimumMFAMethods = 2        # Compliance minimum
$script:PreferredDefaultMethod = "microsoftAuthenticator"
```

### **MFA Method Types Tracked**

| Graph API Type | Friendly Name |
|----------------|---------------|
| `#microsoft.graph.microsoftAuthenticatorAuthenticationMethod` | MicrosoftAuthenticator |
| `#microsoft.graph.phoneAuthenticationMethod` | Phone |
| `#microsoft.graph.emailAuthenticationMethod` | Email |
| `#microsoft.graph.fido2AuthenticationMethod` | FIDO2 |
| `#microsoft.graph.windowsHelloForBusinessAuthenticationMethod` | WindowsHello |
| `#microsoft.graph.softwareOathAuthenticationMethod` | SoftwareOath |
| `#microsoft.graph.temporaryAccessPassAuthenticationMethod` | TemporaryAccessPass |

---

## 🧪 Testing

### **Test Baseline Generator**
```powershell
.\New-TestBaseline.ps1 -UserCount 10
```

Creates sample baseline with:
- 90% enabled accounts
- Mix of Active/Inactive/Disabled status
- Randomized MFA configurations (0-4 methods)
- Realistic departments and licenses

### **Test Scenarios to Validate**

| Scenario | Setup | Expected Result |
|----------|-------|-----------------|
| First run | No baseline exists | Creates baseline, flags non-compliant users |
| No drift | Run twice with same data | MFA_DriftStatus = "None" |
| MFA removed | Edit baseline to have 2 methods, real user has 0 | Critical drift |
| Default changed | Baseline: Authenticator, real: Phone | High drift |
| Method added | Baseline: 2 methods, real: 3 methods | Low drift (improvement) |
| New user | User in current scan not in baseline | No drift error |
| Deleted user | User in baseline not in current scan | Ignored gracefully |
| Invalid credentials | Wrong client secret | Clear error message |

---

## 🚨 Known Limitations

### **Azure AD P2 License Limitations**
- `signInActivity` requires Azure AD Premium (P1/P2) ✓ Available
- **Failed login counts** require deeper audit log queries
  - Decision: Removed from scope (performance impact)
  - Future: Could add as optional feature with `-IncludeAuditLogs` parameter

### **Performance Considerations**
- Designed for <50 users (small businesses)
- For 100+ users: Batch Graph API calls (pagination)
- For 500+ users: Consider database backend instead of JSON files

### **Multi-Tenant Support**
- Current: Single tenant per execution
- Future: Loop through array of tenants in config.json
- Workaround: Run multiple scheduled tasks with different configs

### **Authentication**
- Client secret prompting at runtime (not ideal for fully unattended)
- Future options:
  - Certificate-based auth (no secret storage)
  - Azure Key Vault integration
  - Windows Credential Manager

---

## 🔐 Security Considerations

### **Secrets Management**
- Client secret is **prompted at runtime** (not stored)
- `.gitignore` prevents accidental commit of config.json
- `config.EXAMPLE.json` provided as safe template

### **API Permissions**
- All permissions are **Application** type (not Delegated)
- Requires **admin consent** (Global Admin or Application Admin)
- Least privilege: Only reads data, no write permissions

### **File Storage**
- Baselines/reports contain **sensitive user data**
- Stored locally in script folder
- Recommend NTFS permissions to restrict access
- Auto-cleanup after 60 days (configurable)

---

## 🔄 Maintenance & Updates

### **Client Secret Rotation**
**Recommended**: Every 90 days

**Process**:
1. Azure Portal → App Registrations → Entra MFA Compliance Tool
2. Certificates & secrets → New client secret
3. Copy new secret value
4. Update scheduled task/documentation
5. Delete old secret after validating new one works

### **Module Updates**
```powershell
# Check for updates
Get-InstalledModule Microsoft.Graph.* |
  ForEach-Object { Find-Module $_.Name }

# Update modules
Update-Module Microsoft.Graph.Authentication
Update-Module Microsoft.Graph.Users
Update-Module Microsoft.Graph.Identity.SignIns
```

### **Script Version History**

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2025-10-07 | Initial release with baseline drift detection |

---

## 🐛 Common Issues & Solutions

### **Issue: "Required module not installed"**
**Solution**: Install Graph modules
```powershell
Install-Module -Name Microsoft.Graph.Authentication -Scope CurrentUser
Install-Module -Name Microsoft.Graph.Users -Scope CurrentUser
Install-Module -Name Microsoft.Graph.Identity.SignIns -Scope CurrentUser
```

### **Issue: "Failed to connect to Graph API"**
**Causes**:
1. Invalid Tenant/Client ID (verify GUIDs)
2. Wrong client secret (regenerate)
3. Missing admin consent (grant in Azure Portal)
4. Firewall blocking graph.microsoft.com

### **Issue: "signInActivity is null for all users"**
**Cause**: Azure AD Premium P1/P2 required
**Solution**: Verify license includes Azure AD Premium

### **Issue: Baseline file corrupted**
**Recovery**:
1. Delete corrupted baseline
2. Run script to create fresh baseline
3. Or use `New-TestBaseline.ps1` to generate sample

---

## 📈 Future Enhancements

### **Planned Features** (Not Yet Implemented)
- [ ] Multi-tenant support (loop through array of tenants)
- [ ] HTML report option (in addition to CSV)
- [ ] Email notifications (restore SMTP delivery)
- [ ] Failed login tracking (optional `-IncludeAuditLogs` flag)
- [ ] Remediation scripts (auto-disable stale accounts, send MFA enrollment emails)
- [ ] Dashboard/compliance score calculation
- [ ] Azure Key Vault integration for secrets
- [ ] Certificate-based authentication option
- [ ] Excel .xlsx export (with formatting)

### **Extensibility Points**
- Custom compliance rules can be added to `Compare-MFAState` function
- Additional user properties can be added to `Get-EntraUsers` query
- Report columns can be extended in `New-ComplianceReport` function
- Thresholds can be externalized to config.json

---

## 📞 Support & Contact

**Created By**: Banshee Cybersecurity
**Contact**: services@bansheecybersecurity.com
**Documentation**: See README.md and SETUP_GUIDE.md

---

## 🧠 AI Assistant Notes

### **When Making Changes to This Project**

1. **Preserve Inline Comments**
   - Novice users rely on extensive comments
   - Every 5-10 lines should have explanation
   - Function headers must include description, parameters, returns

2. **Maintain WITCHCRAFT Compliance**
   - All changes should align with `Entra_MFA_Compliance_Witchcraft_Spec.txt`
   - Update spec if requirements change
   - Validate against CRAFT criteria after changes

3. **Testing Requirements**
   - Test with `New-TestBaseline.ps1` before live tenant
   - Validate CSV output format (Excel compatibility)
   - Check log file for errors/warnings
   - Verify drift detection with manually edited baseline

4. **Security First**
   - Never hardcode secrets
   - Never commit sensitive data
   - Always use SecureString for passwords
   - Clear sensitive variables after use

5. **Backward Compatibility**
   - Baseline JSON format changes require migration script
   - CSV column changes may break downstream tools
   - Version number in baseline metadata for compatibility checks

### **Key Functions to Understand**

| Function | Purpose | Lines |
|----------|---------|-------|
| `Invoke-ComplianceScan` | Main execution workflow | 600+ |
| `Get-EntraUsers` | Retrieve all users from Graph API | 260-290 |
| `Get-UserMFAMethods` | Get MFA methods for a user | 295-350 |
| `Compare-MFAState` | Detect MFA drift | 400-500 |
| `Get-UserStatus` | Classify user as Active/Inactive/Disabled | 360-390 |
| `New-ComplianceReport` | Generate CSV report | 520-570 |
| `Save-Baseline` | Store current state as JSON | 575-600 |

---

**End of CLAUDE.md** - Context file for AI assistants working on Entra MFA Compliance Tool
