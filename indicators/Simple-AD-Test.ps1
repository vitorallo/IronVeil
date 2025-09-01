<#
.SYNOPSIS
Simple AD connection test for debugging
#>

$ErrorActionPreference = "Stop"

Write-Host "=== Simple AD Connection Test ===" -ForegroundColor Cyan

# Test domain membership
try {
    $computerSystem = Get-WmiObject Win32_ComputerSystem
    $currentDomain = $computerSystem.Domain
    
    if ($currentDomain -and $currentDomain -ne $env:COMPUTERNAME) {
        Write-Host "Domain: $currentDomain" -ForegroundColor Green
        $isDomainJoined = $true
    } else {
        Write-Host "Not domain joined" -ForegroundColor Yellow
        $isDomainJoined = $false
    }
} catch {
    Write-Host "Error checking domain: $_" -ForegroundColor Red
    $isDomainJoined = $false
}

# Test RSAT
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Write-Host "ActiveDirectory module available" -ForegroundColor Green
    $hasADModule = $true
} catch {
    Write-Host "ActiveDirectory module not available" -ForegroundColor Yellow
    $hasADModule = $false
}

# Test ADSI
if ($isDomainJoined) {
    try {
        $rootDSE = New-Object System.DirectoryServices.DirectoryEntry("LDAP://RootDSE")
        $defaultNC = $rootDSE.defaultNamingContext.Value
        
        if ($defaultNC) {
            Write-Host "LDAP working - DN: $defaultNC" -ForegroundColor Green
            $adsiWorking = $true
        } else {
            Write-Host "LDAP not working" -ForegroundColor Red
            $adsiWorking = $false
        }
        
        $rootDSE.Dispose()
    } catch {
        Write-Host "LDAP error: $_" -ForegroundColor Red
        $adsiWorking = $false
    }
} else {
    Write-Host "Skipping ADSI test - not domain joined" -ForegroundColor Yellow
    $adsiWorking = $false
}

# Load helper
try {
    $helperPath = Join-Path $PSScriptRoot "IronVeil-ADSIHelper.ps1"
    if (Test-Path $helperPath) {
        . $helperPath
        Write-Host "Helper library loaded" -ForegroundColor Green
        $helperLoaded = $true
    } else {
        Write-Host "Helper library not found" -ForegroundColor Red
        $helperLoaded = $false
    }
} catch {
    Write-Host "Helper error: $_" -ForegroundColor Red
    $helperLoaded = $false
}

Write-Host ""
Write-Host "=== Results ===" -ForegroundColor Cyan
Write-Host "Domain Joined: $isDomainJoined"
Write-Host "RSAT Available: $hasADModule"
Write-Host "ADSI Working: $adsiWorking"
Write-Host "Helper Loaded: $helperLoaded"

if ($adsiWorking -and $helperLoaded) {
    Write-Host ""
    Write-Host "Ready for AD rule development!" -ForegroundColor Green
}