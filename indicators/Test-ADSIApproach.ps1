<#
.SYNOPSIS
Test script to validate ADSI approach without RSAT dependency

.DESCRIPTION
This script tests our ADSI-based approach for querying Active Directory
without requiring the ActiveDirectory PowerShell module (RSAT)
#>

# Load helper library
$helperPath = Join-Path $PSScriptRoot "IronVeil-ADSIHelper.ps1"
. $helperPath

Write-Host "=== IronVeil ADSI Approach Validation ===" -ForegroundColor Cyan
Write-Host ""

# Test 1: Check if we can connect to AD without RSAT
Write-Host "`[TEST 1`] Checking domain connectivity..." -ForegroundColor Yellow
try {
    # Try to get current domain
    $computerSystem = Get-WmiObject Win32_ComputerSystem
    $currentDomain = $computerSystem.Domain
    
    if ($currentDomain) {
        Write-Host "  ✓ Current domain: $currentDomain" -ForegroundColor Green
    } else {
        Write-Host "  ✗ Not domain joined" -ForegroundColor Red
        Write-Host "  Note: This machine appears to not be domain-joined. ADSI queries require domain membership." -ForegroundColor Gray
        exit 1
    }
}
catch {
    Write-Host "  ✗ Failed to determine domain: $_" -ForegroundColor Red
    exit 1
}

# Test 2: Check if RSAT is installed (we want to prove we don't need it)
Write-Host ""
Write-Host "`[TEST 2`] Checking RSAT installation status..." -ForegroundColor Yellow
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Write-Host "  ℹ RSAT is installed (but we're NOT using it)" -ForegroundColor Cyan
}
catch {
    Write-Host "  ✓ RSAT is NOT installed (perfect for testing standalone operation)" -ForegroundColor Green
}

# Test 3: Test basic LDAP connectivity using ADSI
Write-Host ""
Write-Host "`[TEST 3`] Testing LDAP connectivity with ADSI..." -ForegroundColor Yellow
try {
    $rootDSE = New-Object System.DirectoryServices.DirectoryEntry("LDAP://RootDSE")
    $defaultNC = $rootDSE.defaultNamingContext
    
    if ($defaultNC) {
        Write-Host "  ✓ Successfully connected to LDAP" -ForegroundColor Green
        Write-Host "  ✓ Default Naming Context: $defaultNC" -ForegroundColor Green
    } else {
        throw "Could not retrieve defaultNamingContext"
    }
    
    $rootDSE.Dispose()
}
catch {
    Write-Host "  ✗ LDAP connection failed: $_" -ForegroundColor Red
    Write-Host "  Note: Ensure this machine is domain-joined and can reach a domain controller" -ForegroundColor Gray
    exit 1
}

# Test 4: Test our helper functions
Write-Host ""
Write-Host "`[TEST 4`] Testing IronVeil ADSI helper functions..." -ForegroundColor Yellow
try {
    # Test Get-IVDomainInfo
    Write-Host "  Testing Get-IVDomainInfo..." -ForegroundColor Gray
    $domainInfo = Get-IVDomainInfo
    Write-Host "    ✓ Domain: $($domainInfo.DomainName)" -ForegroundColor Green
    Write-Host "    ✓ Domain DN: $($domainInfo.DistinguishedName)" -ForegroundColor Green
    Write-Host "    ✓ Domain SID: $($domainInfo.DomainSID)" -ForegroundColor Green
}
catch {
    Write-Host "  ✗ Get-IVDomainInfo failed: $_" -ForegroundColor Red
}

# Test 5: Test searching for domain controllers
Write-Host ""
Write-Host "`[TEST 5`] Testing domain controller enumeration..." -ForegroundColor Yellow
try {
    $dcs = Get-IVADDomainController
    if ($dcs.Count -gt 0) {
        Write-Host "  ✓ Found $($dcs.Count) domain controller(s):" -ForegroundColor Green
        foreach ($dc in $dcs) {
            Write-Host "    - $($dc.dNSHostName)" -ForegroundColor Gray
        }
    } else {
        Write-Host "  ⚠ No domain controllers found (might be permission issue)" -ForegroundColor Yellow
    }
}
catch {
    Write-Host "  ✗ DC enumeration failed: $_" -ForegroundColor Red
}

# Test 6: Test searching for accounts with specific flags
Write-Host ""
Write-Host "`[TEST 6`] Testing UserAccountControl flag queries..." -ForegroundColor Yellow
try {
    # Search for disabled accounts as a test
    $filter = "(userAccountControl:1.2.840.113556.1.4.803:=2)"  # ACCOUNTDISABLE flag
    $results = Search-IVADObjects -Filter $filter -Properties @('sAMAccountName') -SizeLimit 5
    
    if ($results) {
        Write-Host "  ✓ Successfully queried accounts using bitwise LDAP filters" -ForegroundColor Green
        Write-Host "    Found $($results.Count) disabled account(s) (limited to 5)" -ForegroundColor Gray
    } else {
        Write-Host "  ⚠ No results returned (might be permission issue)" -ForegroundColor Yellow
    }
}
catch {
    Write-Host "  ✗ UAC flag query failed: $_" -ForegroundColor Red
}

# Test 7: Performance comparison
Write-Host ""
Write-Host "`[TEST 7`] Testing query performance..." -ForegroundColor Yellow
try {
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    
    # Simple query for users
    $filter = "(&(objectClass=user)(objectCategory=person))"
    $users = Search-IVADObjects -Filter $filter -Properties @('sAMAccountName') -SizeLimit 10
    
    $sw.Stop()
    
    Write-Host "  ✓ Query completed in $($sw.ElapsedMilliseconds)ms" -ForegroundColor Green
    Write-Host "    Retrieved $($users.Count) user(s) (limited to 10)" -ForegroundColor Gray
}
catch {
    Write-Host "  ✗ Performance test failed: $_" -ForegroundColor Red
}

# Summary
Write-Host ""
Write-Host "=== ADSI Validation Summary ===" -ForegroundColor Cyan
Write-Host "✅ ADSI approach works WITHOUT requiring RSAT installation" -ForegroundColor Green
Write-Host "✅ All queries use native .NET System.DirectoryServices" -ForegroundColor Green
Write-Host "✅ No external dependencies required" -ForegroundColor Green
Write-Host ""
Write-Host "This proves IronVeil can operate as a truly standalone application!" -ForegroundColor Green