<#
.SYNOPSIS
    Creates a test baseline file for MFA drift detection testing

.DESCRIPTION
    This helper script generates a sample baseline JSON file that can be used
    to test the MFA drift detection functionality of Invoke-EntraMFACompliance.ps1

    You can manually modify the generated baseline to simulate different drift scenarios:
    - Remove MFA methods to test Critical drift detection
    - Change default method to test High drift detection
    - Add/remove methods to test Medium drift detection

.PARAMETER OutputPath
    The path where the test baseline JSON file should be saved
    Default: ./baselines/EntraMFA_Baseline_TEST.json

.PARAMETER UserCount
    Number of sample users to generate in the baseline
    Default: 10

.EXAMPLE
    .\New-TestBaseline.ps1
    Creates a test baseline with 10 sample users in the default location

.EXAMPLE
    .\New-TestBaseline.ps1 -OutputPath "./baselines/EntraMFA_Baseline_2025-10-01.json" -UserCount 5
    Creates a test baseline with 5 users at a specific date

.NOTES
    Version:        1.0
    Author:         Banshee Cybersecurity
    Creation Date:  2025-10-07
    Purpose:        Testing MFA drift detection functionality
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "./baselines/EntraMFA_Baseline_TEST.json",

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 100)]
    [int]$UserCount = 10
)

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Creating Test Baseline" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Ensure baselines folder exists
$baselineFolder = Split-Path $OutputPath -Parent
if (-not (Test-Path $baselineFolder)) {
    New-Item -Path $baselineFolder -ItemType Directory -Force | Out-Null
    Write-Host "✓ Created folder: $baselineFolder" -ForegroundColor Green
}

# Sample data arrays for realistic test users
$departments = @("IT", "Finance", "HR", "Marketing", "Sales", "Operations", "Legal", "Executive")
$firstNames = @("John", "Sarah", "Michael", "Emily", "David", "Jennifer", "Robert", "Lisa", "James", "Mary")
$lastNames = @("Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis", "Rodriguez", "Martinez")
$mfaMethods = @("MicrosoftAuthenticator", "Phone", "Email", "FIDO2", "WindowsHello", "SoftwareOath")
$licenseSKUs = @("O365_BUSINESS_PREMIUM", "ENTERPRISEPACK", "SPE_E3", "SPE_E5")

# Generate sample users
$testUsers = @()

for ($i = 1; $i -le $UserCount; $i++) {
    # Generate random user data
    $firstName = $firstNames | Get-Random
    $lastName = $lastNames | Get-Random
    $department = $departments | Get-Random
    $upn = "$($firstName.ToLower()).$($lastName.ToLower())@contoso.com"

    # Randomize account status
    $accountEnabled = ($i -le ($UserCount * 0.9))  # 90% enabled

    # Randomize activity (mix of active, inactive, disabled)
    $daysAgo = Get-Random -Minimum 1 -Maximum 60
    $lastSignIn = (Get-Date).AddDays(-$daysAgo).ToString("yyyy-MM-ddTHH:mm:ssZ")

    # Determine status based on days
    $status = if (-not $accountEnabled) {
        "Disabled"
    }
    elseif ($daysAgo -le 20) {
        "Active"
    }
    else {
        "Inactive"
    }

    # Randomize MFA configuration
    $methodCount = Get-Random -Minimum 0 -Maximum 4
    $userMethods = @()

    if ($methodCount -gt 0) {
        # Always include MicrosoftAuthenticator as first method for most users
        if ((Get-Random -Minimum 1 -Maximum 100) -gt 20) {
            $userMethods += "MicrosoftAuthenticator"
        }

        # Add additional random methods
        while ($userMethods.Count -lt $methodCount) {
            $method = $mfaMethods | Get-Random
            if ($method -notin $userMethods) {
                $userMethods += $method
            }
        }
    }

    # Default method
    $defaultMethod = if ($userMethods.Count -gt 0) {
        $userMethods[0]
    }
    else {
        "None"
    }

    # Random licenses
    $licenseCount = Get-Random -Minimum 0 -Maximum 3
    $userLicenses = @()
    for ($l = 0; $l -lt $licenseCount; $l++) {
        $license = $licenseSKUs | Get-Random
        if ($license -notin $userLicenses) {
            $userLicenses += $license
        }
    }

    # Determine compliance flags
    $complianceFlags = @()
    if ($methodCount -eq 0) {
        $complianceFlags += "NoMFA"
    }
    if ($status -eq "Inactive") {
        $complianceFlags += "StaleAccount"
    }

    # Create user object
    $testUser = [PSCustomObject]@{
        UserPrincipalName = $upn
        DisplayName = "$firstName $lastName"
        Department = $department
        Status = $status
        AccountEnabled = $accountEnabled
        CreatedDateTime = (Get-Date).AddDays(-365).ToString("yyyy-MM-ddTHH:mm:ssZ")
        LastSignInDateTime = $lastSignIn
        LastSuccessfulSignInDateTime = $lastSignIn
        DaysSinceLastSignIn = $daysAgo
        LicenseSKUs = ($userLicenses -join ', ')
        MFA_DefaultMethod = $defaultMethod
        MFA_MethodCount = $methodCount
        MFA_Methods = ($userMethods -join ', ')
        MFA_DriftStatus = "None"
        MFA_DriftDetails = "Baseline - no drift comparison"
        ComplianceFlags = ($complianceFlags -join ', ')
    }

    $testUsers += $testUser

    Write-Host "  Generated user $i/$UserCount : $upn ($status, $methodCount MFA methods)" -ForegroundColor Gray
}

# Create baseline structure
$baseline = @{
    Metadata = @{
        GeneratedDate = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        ScriptVersion = "1.0.0-TEST"
        UserCount = $testUsers.Count
        IsTestData = $true
    }
    Users = $testUsers
}

# Save to JSON
try {
    $baseline | ConvertTo-Json -Depth 10 | Set-Content -Path $OutputPath -Force

    Write-Host "`n✓ Test baseline created successfully!" -ForegroundColor Green
    Write-Host "  Location: $OutputPath" -ForegroundColor Cyan
    Write-Host "  Users: $UserCount" -ForegroundColor Cyan

    # Display statistics
    $activeCount = ($testUsers | Where-Object { $_.Status -eq "Active" }).Count
    $inactiveCount = ($testUsers | Where-Object { $_.Status -eq "Inactive" }).Count
    $disabledCount = ($testUsers | Where-Object { $_.Status -eq "Disabled" }).Count
    $noMFACount = ($testUsers | Where-Object { $_.MFA_MethodCount -eq 0 }).Count

    Write-Host "`n  Statistics:" -ForegroundColor Yellow
    Write-Host "    Active Users:    $activeCount" -ForegroundColor Green
    Write-Host "    Inactive Users:  $inactiveCount" -ForegroundColor Yellow
    Write-Host "    Disabled Users:  $disabledCount" -ForegroundColor Gray
    Write-Host "    No MFA:          $noMFACount" -ForegroundColor Red

    Write-Host "`n📝 TESTING TIP:" -ForegroundColor Magenta
    Write-Host "  1. Edit the JSON file to simulate drift scenarios:" -ForegroundColor White
    Write-Host "     - Remove MFA methods to test Critical drift" -ForegroundColor White
    Write-Host "     - Change MFA_DefaultMethod to test High drift" -ForegroundColor White
    Write-Host "     - Add/remove methods to test Medium drift" -ForegroundColor White
    Write-Host "`n  2. Run the compliance script to detect your changes:" -ForegroundColor White
    Write-Host "     .\Invoke-EntraMFACompliance.ps1 -TenantId xxx -ClientId yyy`n" -ForegroundColor Cyan
}
catch {
    Write-Host "`n❌ Failed to create test baseline: $_" -ForegroundColor Red
    exit 1
}

Write-Host "========================================`n" -ForegroundColor Cyan
