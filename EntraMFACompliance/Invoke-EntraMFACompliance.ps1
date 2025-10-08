<#
.SYNOPSIS
    MS 365 Entra ID User Status & MFA Drift Compliance Tool

.DESCRIPTION
    Automated compliance monitoring for MS 365 Entra ID to meet SOC 2, ISO 27001,
    and NIST requirements. This script:
    - Collects user status and sign-in activity
    - Tracks MFA authentication methods
    - Detects MFA configuration drift from baseline
    - Generates weekly compliance reports
    - Identifies stale/inactive accounts

.PARAMETER TenantId
    The Azure AD Tenant ID (GUID format)

.PARAMETER ClientId
    The App Registration Client ID (GUID format)

.PARAMETER WhatIf
    Run in test mode without saving baseline or reports

.PARAMETER Force
    Skip confirmation prompts

.EXAMPLE
    .\Invoke-EntraMFACompliance.ps1 -TenantId "xxxx-xxxx" -ClientId "yyyy-yyyy"
    Runs the compliance scan and prompts for client secret

.NOTES
    Version:        1.0
    Author:         Banshee Cybersecurity
    Creation Date:  2025-10-07
    Framework:      WITCHCRAFT Specification
    Compliance:     SOC 2, ISO 27001, NIST 800-53
    License:        P2 Azure AD Premium Required
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $false, HelpMessage = "Azure AD Tenant ID")]
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string]$TenantId,

    [Parameter(Mandatory = $false, HelpMessage = "App Registration Client ID")]
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string]$ClientId,

    [Parameter(Mandatory = $false, HelpMessage = "Run in test mode without saving")]
    [switch]$WhatIf,

    [Parameter(Mandatory = $false, HelpMessage = "Skip confirmation prompts")]
    [switch]$Force
)

#Requires -Version 7.0

################################################################################
# SCRIPT CONFIGURATION & GLOBAL VARIABLES
################################################################################

# Script version for tracking changes
$script:ScriptVersion = "1.0.0"

# Get the script's root directory
$script:ScriptRoot = $PSScriptRoot
if (-not $script:ScriptRoot) {
    $script:ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
}

# Define folder structure
$script:BaselineFolder = Join-Path $script:ScriptRoot "baselines"
$script:ReportFolder = Join-Path $script:ScriptRoot "reports"
$script:LogFolder = Join-Path $script:ScriptRoot "logs"

# Define current run timestamp
$script:RunDateTime = Get-Date
$script:RunDateString = $script:RunDateTime.ToString("yyyy-MM-dd")
$script:RunDateTimeString = $script:RunDateTime.ToString("yyyy-MM-dd_HHmmss")

# Define file paths for this run
$script:LogFile = Join-Path $script:LogFolder "EntraCompliance_$($script:RunDateTimeString).log"
$script:BaselineFile = Join-Path $script:BaselineFolder "EntraMFA_Baseline_$($script:RunDateString).json"
$script:ReportFile = Join-Path $script:ReportFolder "EntraMFA_Report_$($script:RunDateString).csv"

# Compliance thresholds (configurable)
$script:ActiveUserDays = 20          # Users active within this many days
$script:InactiveDays = 21            # Users inactive beyond this threshold
$script:BaselineRetentionDays = 60   # How long to keep old baselines/reports/logs
$script:MinimumMFAMethods = 2        # Expected minimum MFA methods per user
$script:PreferredDefaultMethod = "microsoftAuthenticator"  # Preferred default MFA method

# Initialize counters for summary
$script:Stats = @{
    TotalUsers = 0
    ActiveUsers = 0
    InactiveUsers = 0
    DisabledUsers = 0
    UsersWithMFADrift = 0
    CriticalFindings = 0
    HighFindings = 0
    MediumFindings = 0
    LowFindings = 0
}

################################################################################
# LOGGING FUNCTIONS
################################################################################

<#
.SYNOPSIS
    Writes a log entry with timestamp and level
#>
function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [ValidateSet('INFO', 'WARNING', 'ERROR', 'DEBUG')]
        [string]$Level = 'INFO'
    )

    # Create timestamp
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    # Format log entry
    $logEntry = "[$timestamp] [$Level] $Message"

    # Write to log file
    try {
        Add-Content -Path $script:LogFile -Value $logEntry -ErrorAction Stop
    }
    catch {
        Write-Warning "Failed to write to log file: $_"
    }

    # Also write to console with color coding
    switch ($Level) {
        'ERROR'   { Write-Host $logEntry -ForegroundColor Red }
        'WARNING' { Write-Host $logEntry -ForegroundColor Yellow }
        'DEBUG'   { Write-Verbose $logEntry }
        default   { Write-Host $logEntry -ForegroundColor Gray }
    }
}

################################################################################
# ENVIRONMENT SETUP FUNCTIONS
################################################################################

<#
.SYNOPSIS
    Creates required folder structure if it doesn't exist
#>
function Initialize-FolderStructure {
    [CmdletBinding()]
    param()

    Write-Log "Initializing folder structure..." -Level INFO

    # Create folders if they don't exist
    $folders = @($script:BaselineFolder, $script:ReportFolder, $script:LogFolder)

    foreach ($folder in $folders) {
        if (-not (Test-Path $folder)) {
            try {
                New-Item -Path $folder -ItemType Directory -Force | Out-Null
                Write-Log "Created folder: $folder" -Level INFO
            }
            catch {
                Write-Log "Failed to create folder $folder : $_" -Level ERROR
                throw
            }
        }
        else {
            Write-Log "Folder exists: $folder" -Level DEBUG
        }
    }
}

<#
.SYNOPSIS
    Validates PowerShell version and required modules
#>
function Test-Prerequisites {
    [CmdletBinding()]
    param()

    Write-Log "Checking prerequisites..." -Level INFO

    # Check PowerShell version
    $psVersion = $PSVersionTable.PSVersion
    Write-Log "PowerShell Version: $psVersion" -Level INFO

    if ($psVersion.Major -lt 7) {
        Write-Log "PowerShell 7.0 or higher required. Current: $psVersion" -Level ERROR
        throw "Unsupported PowerShell version"
    }

    # Required modules
    $requiredModules = @(
        'Microsoft.Graph.Authentication',
        'Microsoft.Graph.Users',
        'Microsoft.Graph.Identity.SignIns'
    )

    # Check each module
    foreach ($module in $requiredModules) {
        Write-Log "Checking for module: $module" -Level DEBUG

        $installedModule = Get-Module -ListAvailable -Name $module

        if (-not $installedModule) {
            Write-Log "Required module missing: $module" -Level ERROR
            Write-Host "`nMissing module: $module" -ForegroundColor Red
            Write-Host "Install with: Install-Module -Name $module -Scope CurrentUser" -ForegroundColor Yellow
            throw "Required module not installed: $module"
        }
        else {
            Write-Log "Module found: $module (Version: $($installedModule.Version))" -Level INFO
        }
    }

    Write-Log "All prerequisites met" -Level INFO
}

<#
.SYNOPSIS
    Cleans up old baseline, report, and log files beyond retention period
#>
function Remove-OldFiles {
    [CmdletBinding()]
    param()

    Write-Log "Cleaning up files older than $script:BaselineRetentionDays days..." -Level INFO

    $cutoffDate = (Get-Date).AddDays(-$script:BaselineRetentionDays)

    # Clean each folder
    $folders = @(
        @{Path = $script:BaselineFolder; Pattern = "EntraMFA_Baseline_*.json"},
        @{Path = $script:ReportFolder; Pattern = "EntraMFA_Report_*.csv"},
        @{Path = $script:LogFolder; Pattern = "EntraCompliance_*.log"}
    )

    foreach ($folder in $folders) {
        $oldFiles = Get-ChildItem -Path $folder.Path -Filter $folder.Pattern -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -lt $cutoffDate }

        foreach ($file in $oldFiles) {
            try {
                Remove-Item $file.FullName -Force
                Write-Log "Deleted old file: $($file.Name)" -Level INFO
            }
            catch {
                Write-Log "Failed to delete $($file.Name): $_" -Level WARNING
            }
        }
    }
}

################################################################################
# AUTHENTICATION FUNCTIONS
################################################################################

<#
.SYNOPSIS
    Connects to Microsoft Graph API with app-based authentication
#>
function Connect-GraphAPI {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantId,

        [Parameter(Mandatory = $true)]
        [string]$ClientId,

        [Parameter(Mandatory = $true)]
        [SecureString]$ClientSecret
    )

    Write-Log "Connecting to Microsoft Graph API..." -Level INFO
    Write-Log "Tenant ID: $TenantId" -Level DEBUG
    Write-Log "Client ID: $ClientId" -Level DEBUG

    try {
        # Convert SecureString to plain text for Graph API
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ClientSecret)
        $plainSecret = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

        # Create credential object
        $securePassword = ConvertTo-SecureString $plainSecret -AsPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential($ClientId, $securePassword)

        # Connect to Graph with required scopes
        Connect-MgGraph -TenantId $TenantId -ClientSecretCredential $credential -NoWelcome -ErrorAction Stop

        # Clear sensitive data from memory
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
        Remove-Variable plainSecret -ErrorAction SilentlyContinue

        Write-Log "Successfully connected to Microsoft Graph API" -Level INFO

        # Verify connection by getting context
        $context = Get-MgContext
        Write-Log "Connected as: $($context.AppName) | Scopes: $($context.Scopes -join ', ')" -Level INFO

        return $true
    }
    catch {
        Write-Log "Failed to connect to Graph API: $_" -Level ERROR
        throw
    }
}

<#
.SYNOPSIS
    Tests Graph API connectivity by making a simple call
#>
function Test-GraphConnection {
    [CmdletBinding()]
    param()

    Write-Log "Testing Graph API connectivity..." -Level INFO

    try {
        # Try to get the organization details (lightweight call)
        $org = Get-MgOrganization -ErrorAction Stop | Select-Object -First 1
        Write-Log "Successfully connected to tenant: $($org.DisplayName)" -Level INFO
        return $true
    }
    catch {
        Write-Log "Graph API connectivity test failed: $_" -Level ERROR
        return $false
    }
}

################################################################################
# DATA COLLECTION FUNCTIONS
################################################################################

<#
.SYNOPSIS
    Retrieves all users with required properties
#>
function Get-EntraUsers {
    [CmdletBinding()]
    param()

    Write-Log "Retrieving all Entra ID users..." -Level INFO

    try {
        # Define properties to retrieve
        $properties = @(
            'Id',
            'UserPrincipalName',
            'DisplayName',
            'AccountEnabled',
            'Department',
            'CreatedDateTime',
            'SignInActivity',
            'AssignedLicenses',
            'UserType'
        )

        # Get all users (excluding guests)
        Write-Log "Querying Graph API for users..." -Level DEBUG

        $users = Get-MgUser -All `
            -Property $properties `
            -Filter "userType eq 'Member'" `
            -ErrorAction Stop

        Write-Log "Retrieved $($users.Count) users" -Level INFO

        return $users
    }
    catch {
        Write-Log "Failed to retrieve users: $_" -Level ERROR
        throw
    }
}

<#
.SYNOPSIS
    Retrieves MFA authentication methods for a specific user
#>
function Get-UserMFAMethods {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserId
    )

    Write-Log "Retrieving MFA methods for user: $UserId" -Level DEBUG

    try {
        # Get all authentication methods for the user
        $methods = Get-MgUserAuthenticationMethod -UserId $UserId -ErrorAction Stop

        # Parse method details
        $mfaDetails = @{
            Methods = @()
            MethodCount = 0
            DefaultMethod = "None"
            MethodTypes = @()
        }

        foreach ($method in $methods) {
            # Extract method type from the OData type
            $methodType = $method.AdditionalProperties.'@odata.type' -replace '#microsoft.graph.', ''

            # Map common method types to friendly names
            $friendlyName = switch -Wildcard ($methodType) {
                '*microsoftAuthenticator*' { 'MicrosoftAuthenticator' }
                '*phone*' { 'Phone' }
                '*email*' { 'Email' }
                '*fido2*' { 'FIDO2' }
                '*windowsHello*' { 'WindowsHello' }
                '*softwareOath*' { 'SoftwareOath' }
                '*temporaryAccessPass*' { 'TemporaryAccessPass' }
                default { $methodType }
            }

            $mfaDetails.Methods += @{
                Type = $friendlyName
                Id = $method.Id
                Details = $method.AdditionalProperties
            }

            $mfaDetails.MethodTypes += $friendlyName
        }

        $mfaDetails.MethodCount = $mfaDetails.Methods.Count

        # Determine default method (prefer Microsoft Authenticator if available)
        if ($mfaDetails.MethodTypes -contains 'MicrosoftAuthenticator') {
            $mfaDetails.DefaultMethod = 'MicrosoftAuthenticator'
        }
        elseif ($mfaDetails.MethodCount -gt 0) {
            $mfaDetails.DefaultMethod = $mfaDetails.MethodTypes[0]
        }

        return $mfaDetails
    }
    catch {
        Write-Log "Failed to retrieve MFA methods for user $UserId : $_" -Level WARNING

        # Return empty structure on error (user may not have MFA configured)
        return @{
            Methods = @()
            MethodCount = 0
            DefaultMethod = "None"
            MethodTypes = @()
        }
    }
}

<#
.SYNOPSIS
    Classifies user status based on sign-in activity
#>
function Get-UserStatus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [bool]$AccountEnabled,

        [Parameter(Mandatory = $false)]
        [datetime]$LastSignInDateTime,

        [Parameter(Mandatory = $false)]
        [datetime]$LastSuccessfulSignInDateTime
    )

    # If account is disabled, mark as Disabled
    if (-not $AccountEnabled) {
        return "Disabled"
    }

    # Calculate days since last successful sign-in
    if ($LastSuccessfulSignInDateTime) {
        $daysSinceSignIn = (Get-Date) - $LastSuccessfulSignInDateTime
        $daysCount = $daysSinceSignIn.Days

        # Active: signed in within last 20 days
        if ($daysCount -le $script:ActiveUserDays) {
            return "Active"
        }
        # Inactive: no sign-in for 21+ days
        else {
            return "Inactive"
        }
    }
    else {
        # No sign-in data available - consider inactive
        return "Inactive"
    }
}

################################################################################
# BASELINE & DRIFT DETECTION FUNCTIONS
################################################################################

<#
.SYNOPSIS
    Loads the previous baseline file if it exists
#>
function Get-PreviousBaseline {
    [CmdletBinding()]
    param()

    Write-Log "Checking for previous baseline..." -Level INFO

    # Find the most recent baseline file (excluding today's)
    $baselineFiles = Get-ChildItem -Path $script:BaselineFolder -Filter "EntraMFA_Baseline_*.json" -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -ne (Split-Path $script:BaselineFile -Leaf) } |
        Sort-Object LastWriteTime -Descending

    if ($baselineFiles.Count -eq 0) {
        Write-Log "No previous baseline found - this is the first run" -Level WARNING
        return $null
    }

    $latestBaseline = $baselineFiles[0]
    Write-Log "Found previous baseline: $($latestBaseline.Name)" -Level INFO

    try {
        $baselineData = Get-Content $latestBaseline.FullName -Raw | ConvertFrom-Json
        Write-Log "Successfully loaded baseline with $($baselineData.Users.Count) users" -Level INFO
        return $baselineData
    }
    catch {
        Write-Log "Failed to load baseline file: $_" -Level ERROR
        return $null
    }
}

<#
.SYNOPSIS
    Detects MFA drift by comparing current state to baseline
#>
function Compare-MFAState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$CurrentMFA,

        [Parameter(Mandatory = $false)]
        [object]$BaselineUser
    )

    # If no baseline exists, check against compliance expectations
    if (-not $BaselineUser) {
        $drift = @{
            Status = "None"
            Severity = "None"
            Details = @()
        }

        # Check if user has MFA enabled
        if ($CurrentMFA.MethodCount -eq 0) {
            $drift.Status = "Critical"
            $drift.Severity = "Critical"
            $drift.Details += "No MFA methods configured"
        }
        # Check if user has minimum required methods
        elseif ($CurrentMFA.MethodCount -lt $script:MinimumMFAMethods) {
            $drift.Status = "High"
            $drift.Severity = "High"
            $drift.Details += "Only $($CurrentMFA.MethodCount) MFA method(s) - minimum $script:MinimumMFAMethods expected"
        }
        # Check if default method is Microsoft Authenticator
        elseif ($CurrentMFA.DefaultMethod -ne 'MicrosoftAuthenticator') {
            $drift.Status = "Medium"
            $drift.Severity = "Medium"
            $drift.Details += "Default method is $($CurrentMFA.DefaultMethod) - Microsoft Authenticator preferred"
        }
        else {
            $drift.Status = "Compliant"
            $drift.Severity = "None"
            $drift.Details += "MFA configuration meets baseline expectations"
        }

        return $drift
    }

    # Compare against previous baseline
    $drift = @{
        Status = "None"
        Severity = "None"
        Details = @()
    }

    # Get baseline MFA state
    $baselineMethods = $BaselineUser.MFA_MethodCount
    $baselineDefault = $BaselineUser.MFA_DefaultMethod
    $baselineTypes = $BaselineUser.MFA_Methods -split ', '

    # Check for critical changes: MFA completely removed
    if ($baselineMethods -gt 0 -and $CurrentMFA.MethodCount -eq 0) {
        $drift.Status = "Critical"
        $drift.Severity = "Critical"
        $drift.Details += "MFA completely disabled (was $baselineMethods methods)"
    }
    # Check for high severity: method count decreased below minimum
    elseif ($CurrentMFA.MethodCount -lt $baselineMethods -and $CurrentMFA.MethodCount -lt $script:MinimumMFAMethods) {
        $drift.Status = "High"
        $drift.Severity = "High"
        $drift.Details += "MFA methods decreased from $baselineMethods to $($CurrentMFA.MethodCount)"
    }
    # Check for high severity: default method changed from Microsoft Authenticator
    elseif ($baselineDefault -eq 'MicrosoftAuthenticator' -and $CurrentMFA.DefaultMethod -ne 'MicrosoftAuthenticator') {
        $drift.Status = "High"
        $drift.Severity = "High"
        $drift.Details += "Default method changed from $baselineDefault to $($CurrentMFA.DefaultMethod)"
    }
    # Check for medium severity: methods changed but not critical
    elseif (Compare-Object $baselineTypes $CurrentMFA.MethodTypes) {
        $drift.Status = "Medium"
        $drift.Severity = "Medium"

        # Identify added/removed methods
        $added = $CurrentMFA.MethodTypes | Where-Object { $_ -notin $baselineTypes }
        $removed = $baselineTypes | Where-Object { $_ -notin $CurrentMFA.MethodTypes }

        if ($added) {
            $drift.Details += "Added methods: $($added -join ', ')"
        }
        if ($removed) {
            $drift.Details += "Removed methods: $($removed -join ', ')"
        }
    }
    # Check for low severity: improvements
    elseif ($CurrentMFA.MethodCount -gt $baselineMethods) {
        $drift.Status = "Low"
        $drift.Severity = "Low"
        $drift.Details += "MFA methods increased from $baselineMethods to $($CurrentMFA.MethodCount) (improvement)"
    }

    # If no changes detected
    if ($drift.Details.Count -eq 0) {
        $drift.Status = "None"
        $drift.Severity = "None"
        $drift.Details += "No MFA drift detected"
    }

    return $drift
}

################################################################################
# REPORT GENERATION FUNCTIONS
################################################################################

<#
.SYNOPSIS
    Generates the compliance report CSV
#>
function New-ComplianceReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$UserData
    )

    Write-Log "Generating compliance report..." -Level INFO

    try {
        # Create report header with summary
        $reportHeader = @"
# MS 365 Entra ID MFA Compliance Report
# Generated: $($script:RunDateTime.ToString("yyyy-MM-dd HH:mm:ss"))
# Script Version: $script:ScriptVersion
# Total Users: $($script:Stats.TotalUsers)
# Active Users: $($script:Stats.ActiveUsers)
# Inactive Users: $($script:Stats.InactiveUsers)
# Disabled Users: $($script:Stats.DisabledUsers)
# Users with MFA Drift: $($script:Stats.UsersWithMFADrift)
# Critical Findings: $($script:Stats.CriticalFindings)
# High Findings: $($script:Stats.HighFindings)
# Medium Findings: $($script:Stats.MediumFindings)
# Low Findings: $($script:Stats.LowFindings)
#
"@

        # Write header to file
        Set-Content -Path $script:ReportFile -Value $reportHeader -Force

        # Export user data to CSV (append to existing file)
        $UserData | Export-Csv -Path $script:ReportFile -NoTypeInformation -Append -Force

        Write-Log "Report saved: $script:ReportFile" -Level INFO

        return $true
    }
    catch {
        Write-Log "Failed to generate report: $_" -Level ERROR
        throw
    }
}

<#
.SYNOPSIS
    Saves the current state as a baseline for next run
#>
function Save-Baseline {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$UserData
    )

    Write-Log "Saving baseline for future drift detection..." -Level INFO

    try {
        # Create baseline object
        $baseline = @{
            Metadata = @{
                GeneratedDate = $script:RunDateTime.ToString("yyyy-MM-dd HH:mm:ss")
                ScriptVersion = $script:ScriptVersion
                UserCount = $UserData.Count
            }
            Users = $UserData
        }

        # Convert to JSON and save
        $baseline | ConvertTo-Json -Depth 10 | Set-Content -Path $script:BaselineFile -Force

        Write-Log "Baseline saved: $script:BaselineFile" -Level INFO

        return $true
    }
    catch {
        Write-Log "Failed to save baseline: $_" -Level ERROR
        throw
    }
}

################################################################################
# MAIN EXECUTION FUNCTION
################################################################################

<#
.SYNOPSIS
    Main execution workflow
#>
function Invoke-ComplianceScan {
    [CmdletBinding()]
    param()

    Write-Log "======================================" -Level INFO
    Write-Log "Starting Entra MFA Compliance Scan" -Level INFO
    Write-Log "======================================" -Level INFO

    try {
        # Step 1: Initialize environment
        Initialize-FolderStructure
        Test-Prerequisites
        Remove-OldFiles

        # Step 2: Authenticate to Graph API
        if (-not $script:TenantId -or -not $script:ClientId) {
            Write-Log "Tenant ID or Client ID not provided" -Level ERROR
            throw "Missing required parameters"
        }

        # Prompt for client secret securely
        Write-Host "`nEnter Client Secret for App Registration:" -ForegroundColor Cyan
        $clientSecret = Read-Host -AsSecureString

        Connect-GraphAPI -TenantId $script:TenantId -ClientId $script:ClientId -ClientSecret $clientSecret

        if (-not (Test-GraphConnection)) {
            throw "Graph API connection test failed"
        }

        # Step 3: Load previous baseline (if exists)
        $previousBaseline = Get-PreviousBaseline
        $isFirstRun = ($null -eq $previousBaseline)

        if ($isFirstRun) {
            Write-Host "`n⚠️  FIRST RUN DETECTED - No previous baseline found" -ForegroundColor Yellow
            Write-Host "This run will establish the baseline for future drift detection.`n" -ForegroundColor Yellow
        }

        # Step 4: Retrieve all users
        $users = Get-EntraUsers
        $script:Stats.TotalUsers = $users.Count

        Write-Host "`nProcessing $($users.Count) users..." -ForegroundColor Cyan

        # Step 5: Process each user
        $reportData = @()
        $progressCount = 0

        foreach ($user in $users) {
            $progressCount++
            Write-Progress -Activity "Scanning Users" -Status "Processing $($user.UserPrincipalName)" -PercentComplete (($progressCount / $users.Count) * 100)

            Write-Log "Processing user: $($user.UserPrincipalName)" -Level DEBUG

            # Get sign-in dates
            $lastSignIn = $null
            $lastSuccessfulSignIn = $null

            if ($user.SignInActivity) {
                $lastSignIn = $user.SignInActivity.LastSignInDateTime
                $lastSuccessfulSignIn = $user.SignInActivity.LastSuccessfulSignInDateTime
            }

            # Calculate days since last sign-in
            $daysSinceSignIn = "Never"
            if ($lastSuccessfulSignIn) {
                $daysSinceSignIn = ((Get-Date) - $lastSuccessfulSignIn).Days
            }

            # Get user status
            $status = Get-UserStatus -AccountEnabled $user.AccountEnabled -LastSuccessfulSignInDateTime $lastSuccessfulSignIn

            # Update counters
            switch ($status) {
                "Active" { $script:Stats.ActiveUsers++ }
                "Inactive" { $script:Stats.InactiveUsers++ }
                "Disabled" { $script:Stats.DisabledUsers++ }
            }

            # Get MFA methods
            $mfaMethods = Get-UserMFAMethods -UserId $user.Id

            # Find baseline user if exists
            $baselineUser = $null
            if (-not $isFirstRun) {
                $baselineUser = $previousBaseline.Users | Where-Object { $_.UserPrincipalName -eq $user.UserPrincipalName }
            }

            # Detect MFA drift
            $drift = Compare-MFAState -CurrentMFA $mfaMethods -BaselineUser $baselineUser

            # Update drift counters
            if ($drift.Severity -ne "None") {
                $script:Stats.UsersWithMFADrift++

                switch ($drift.Severity) {
                    "Critical" { $script:Stats.CriticalFindings++ }
                    "High" { $script:Stats.HighFindings++ }
                    "Medium" { $script:Stats.MediumFindings++ }
                    "Low" { $script:Stats.LowFindings++ }
                }
            }

            # Get license SKUs
            $licenses = ($user.AssignedLicenses | ForEach-Object { $_.SkuId }) -join ', '
            if ([string]::IsNullOrWhiteSpace($licenses)) {
                $licenses = "None"
            }

            # Build compliance flags
            $complianceFlags = @()
            if ($mfaMethods.MethodCount -eq 0) {
                $complianceFlags += "NoMFA"
            }
            if ($status -eq "Inactive") {
                $complianceFlags += "StaleAccount"
            }

            # Create report record
            $reportRecord = [PSCustomObject]@{
                UserPrincipalName = $user.UserPrincipalName
                DisplayName = $user.DisplayName
                Department = $user.Department
                Status = $status
                AccountEnabled = $user.AccountEnabled
                CreatedDateTime = $user.CreatedDateTime
                LastSignInDateTime = $lastSignIn
                LastSuccessfulSignInDateTime = $lastSuccessfulSignIn
                DaysSinceLastSignIn = $daysSinceSignIn
                LicenseSKUs = $licenses
                MFA_DefaultMethod = $mfaMethods.DefaultMethod
                MFA_MethodCount = $mfaMethods.MethodCount
                MFA_Methods = ($mfaMethods.MethodTypes -join ', ')
                MFA_DriftStatus = $drift.Severity
                MFA_DriftDetails = ($drift.Details -join ' | ')
                ComplianceFlags = ($complianceFlags -join ', ')
            }

            $reportData += $reportRecord
        }

        Write-Progress -Activity "Scanning Users" -Completed

        # Step 6: Generate report
        if (-not $WhatIf) {
            New-ComplianceReport -UserData $reportData
            Save-Baseline -UserData $reportData
        }
        else {
            Write-Host "`n⚠️  WhatIf mode - skipping file save" -ForegroundColor Yellow
        }

        # Step 7: Display summary
        Write-Host "`n======================================" -ForegroundColor Green
        Write-Host "COMPLIANCE SCAN COMPLETE" -ForegroundColor Green
        Write-Host "======================================" -ForegroundColor Green
        Write-Host "Total Users:           $($script:Stats.TotalUsers)"
        Write-Host "Active Users:          $($script:Stats.ActiveUsers)" -ForegroundColor Green
        Write-Host "Inactive Users:        $($script:Stats.InactiveUsers)" -ForegroundColor Yellow
        Write-Host "Disabled Users:        $($script:Stats.DisabledUsers)" -ForegroundColor Gray
        Write-Host ""
        Write-Host "MFA Drift Detected:    $($script:Stats.UsersWithMFADrift)"
        Write-Host "  Critical Findings:   $($script:Stats.CriticalFindings)" -ForegroundColor Red
        Write-Host "  High Findings:       $($script:Stats.HighFindings)" -ForegroundColor DarkRed
        Write-Host "  Medium Findings:     $($script:Stats.MediumFindings)" -ForegroundColor Yellow
        Write-Host "  Low Findings:        $($script:Stats.LowFindings)" -ForegroundColor Cyan
        Write-Host ""

        if (-not $WhatIf) {
            Write-Host "Report saved to:       $script:ReportFile" -ForegroundColor Cyan
            Write-Host "Baseline saved to:     $script:BaselineFile" -ForegroundColor Cyan
        }

        Write-Host "Log file:              $script:LogFile" -ForegroundColor Cyan
        Write-Host "======================================`n" -ForegroundColor Green

        Write-Log "Compliance scan completed successfully" -Level INFO

    }
    catch {
        Write-Log "Compliance scan failed: $_" -Level ERROR
        Write-Host "`n❌ SCAN FAILED: $_" -ForegroundColor Red
        throw
    }
    finally {
        # Disconnect from Graph API
        try {
            Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
            Write-Log "Disconnected from Graph API" -Level INFO
        }
        catch {
            # Ignore disconnect errors
        }
    }
}

################################################################################
# SCRIPT ENTRY POINT
################################################################################

# Store parameters in script scope for functions to access
$script:TenantId = $TenantId
$script:ClientId = $ClientId

# Execute main function
Invoke-ComplianceScan
