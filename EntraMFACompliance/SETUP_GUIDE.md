# Azure AD App Registration Setup Guide

This guide walks you through creating and configuring an Azure AD App Registration for the Entra MFA Compliance Tool.

---

## Prerequisites

- **Azure AD Premium P2** license
- **Global Administrator** or **Application Administrator** role in Azure AD
- Access to the **Azure Portal** (https://portal.azure.com)

---

## Step 1: Create App Registration

1. **Sign in to Azure Portal**
   - Navigate to https://portal.azure.com
   - Sign in with your admin account

2. **Open Azure Active Directory**
   - In the left menu, click **Azure Active Directory**
   - (Or search for "Azure Active Directory" in the top search bar)

3. **Navigate to App Registrations**
   - In the left menu under **Manage**, click **App registrations**
   - Click **+ New registration**

4. **Register the Application**
   - **Name:** `Entra MFA Compliance Tool`
   - **Supported account types:**
     - Select **Accounts in this organizational directory only (Single tenant)**
   - **Redirect URI:** Leave blank (not needed for this script)
   - Click **Register**

5. **Copy Important Values**

   After registration, you'll see the **Overview** page. Copy these values:

   | Field | Location | Example | Notes |
   |-------|----------|---------|-------|
   | **Application (client) ID** | Overview page | `12345678-1234-1234-1234-123456789abc` | Save this as your `ClientId` |
   | **Directory (tenant) ID** | Overview page | `87654321-4321-4321-4321-abcdef123456` | Save this as your `TenantId` |

   **Store these values securely** - you'll need them to run the script.

---

## Step 2: Create Client Secret

1. **Navigate to Certificates & secrets**
   - In the left menu, click **Certificates & secrets**
   - Click **+ New client secret**

2. **Add a Client Secret**
   - **Description:** `Entra MFA Compliance Script`
   - **Expires:**
     - Recommended: **90 days** (for security)
     - Alternative: **180 days** or **Custom**
   - Click **Add**

3. **Copy the Secret Value**

   ⚠️ **IMPORTANT:** The secret value is only shown ONCE!

   - **Secret Value:** Click the copy icon to copy the entire value
   - **Store securely** - you cannot retrieve this later
   - If you lose it, you'll need to create a new secret

   **Example:**
   ```
   Secret Value: AbC123~dEf456.GhI789_JkL012
   ```

---

## Step 3: Configure API Permissions

The app needs specific Microsoft Graph API permissions to read user and MFA data.

1. **Navigate to API Permissions**
   - In the left menu, click **API permissions**
   - You'll see **Microsoft Graph > User.Read** (delegated) already present

2. **Add Required Permissions**

   For each permission below, follow these steps:

   **Click:** `+ Add a permission`
   → Select **Microsoft Graph**
   → Select **Application permissions** (NOT Delegated)
   → Search for and select the permission
   → Click **Add permissions**

   **Required Permissions:**

   | Permission Name | Type | Purpose |
   |-----------------|------|---------|
   | `User.Read.All` | Application | Read all user profiles |
   | `UserAuthenticationMethod.Read.All` | Application | Read all users' MFA methods |
   | `AuditLog.Read.All` | Application | Read sign-in activity data |
   | `Directory.Read.All` | Application | Read directory data (licenses, etc.) |

3. **Grant Admin Consent**

   ⚠️ **Critical Step:** Application permissions require admin consent.

   - After adding all 4 permissions, click the button:

     **✔️ Grant admin consent for [Your Tenant Name]**

   - Click **Yes** to confirm

   - Verify all permissions show **Granted for [Tenant]** in green

   **Expected Result:**

   | API / Permission name | Type | Admin consent required | Status |
   |-----------------------|------|------------------------|--------|
   | Microsoft Graph / User.Read.All | Application | Yes | ✅ Granted for... |
   | Microsoft Graph / UserAuthenticationMethod.Read.All | Application | Yes | ✅ Granted for... |
   | Microsoft Graph / AuditLog.Read.All | Application | Yes | ✅ Granted for... |
   | Microsoft Graph / Directory.Read.All | Application | Yes | ✅ Granted for... |

---

## Step 4: Verify Configuration

1. **Review App Overview**
   - Navigate back to **Overview** page
   - Confirm:
     - Application type: **Web app / API**
     - Supported account types: **Single tenant**

2. **Test the Configuration**

   You can test the app registration before running the full script:

   ```powershell
   # Install Microsoft Graph module if not already installed
   Install-Module -Name Microsoft.Graph.Authentication -Scope CurrentUser

   # Connect using your app registration
   $tenantId = "YOUR-TENANT-ID"
   $clientId = "YOUR-CLIENT-ID"
   $clientSecret = Read-Host -AsSecureString -Prompt "Enter Client Secret"

   # Convert SecureString to plain text
   $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($clientSecret)
   $plainSecret = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

   # Create credential
   $securePassword = ConvertTo-SecureString $plainSecret -AsPlainText -Force
   $credential = New-Object System.Management.Automation.PSCredential($clientId, $securePassword)

   # Connect
   Connect-MgGraph -TenantId $tenantId -ClientSecretCredential $credential

   # Test: Get users
   Get-MgUser -Top 5 | Select-Object DisplayName, UserPrincipalName

   # Disconnect
   Disconnect-MgGraph
   ```

   **Expected Output:** List of 5 users from your tenant

---

## Step 5: Security Best Practices

### 🔒 Protect Your Client Secret

- **Never** commit client secrets to Git or version control
- **Never** share secrets via email or chat
- **Store** secrets in a password manager (e.g., 1Password, LastPass, BitWarden)
- **Rotate** secrets every 90 days

### 🔒 Monitor App Activity

- Navigate to **Enterprise applications** in Azure AD
- Find your app: **Entra MFA Compliance Tool**
- Review **Sign-in logs** periodically to detect unauthorized use

### 🔒 Use Certificate Authentication (Advanced)

For production environments, consider using certificate-based authentication instead of client secrets:

1. **Create a self-signed certificate:**
   ```powershell
   $cert = New-SelfSignedCertificate -Subject "CN=EntraMFACompliance" `
       -CertStoreLocation "Cert:\CurrentUser\My" `
       -KeySpec KeyExchange `
       -NotAfter (Get-Date).AddYears(2)
   ```

2. **Export certificate (without private key):**
   ```powershell
   Export-Certificate -Cert $cert -FilePath "EntraMFACompliance.cer"
   ```

3. **Upload to Azure AD:**
   - App Registration > **Certificates & secrets**
   - **Certificates** tab > **Upload certificate**
   - Upload the `.cer` file

4. **Modify script to use certificate:**
   ```powershell
   Connect-MgGraph -TenantId $tenantId -ClientId $clientId -CertificateThumbprint $cert.Thumbprint
   ```

---

## Step 6: Document Your Setup

Create a secure record of your configuration:

```
Tenant Name: [Your Organization]
Tenant ID: [Your Tenant GUID]
Client ID: [Your Client GUID]
Client Secret: [Stored in: Password Manager / Azure Key Vault]
Secret Expiration: [Date]
Created By: [Your Name]
Created Date: [Date]
Next Secret Rotation: [Date + 90 days]
```

Store this in your organization's secure documentation system.

---

## Troubleshooting

### Error: "Need admin approval"

**Cause:** Application permissions require admin consent

**Solution:**
1. Go to **API permissions** in your app registration
2. Click **Grant admin consent for [Tenant]**
3. Confirm by clicking **Yes**

### Error: "Invalid client secret"

**Cause:** Secret expired or incorrect

**Solution:**
1. Go to **Certificates & secrets**
2. Check if secret is expired
3. Create a new client secret
4. Update the script with new secret

### Error: "Application not found in directory"

**Cause:** Incorrect Tenant ID or Client ID

**Solution:**
1. Verify you're in the correct Azure AD tenant
2. Double-check the Application (client) ID from **Overview** page
3. Ensure you copied the entire GUID (36 characters with dashes)

### Error: "Insufficient privileges to complete the operation"

**Cause:** Missing API permissions or admin consent

**Solution:**
1. Verify all 4 required permissions are added
2. Ensure permissions are **Application** type (not Delegated)
3. Click **Grant admin consent** again
4. Wait 5 minutes for permissions to propagate

---

## Next Steps

✅ App Registration created
✅ Client secret generated and stored securely
✅ API permissions configured and consented
✅ Configuration tested

**You're ready to run the compliance script!**

Proceed to the main [README.md](README.md) for script execution instructions.

---

## Additional Resources

📖 **Microsoft Docs: Register an application**
https://learn.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app

📖 **Microsoft Graph API permissions reference**
https://learn.microsoft.com/en-us/graph/permissions-reference

📖 **Best practices for app registrations**
https://learn.microsoft.com/en-us/azure/active-directory/develop/security-best-practices-for-app-registration

---

**Support:** services@bansheecybersecurity.com
