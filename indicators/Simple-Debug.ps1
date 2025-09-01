<#
.SYNOPSIS
Simple debugging environment for AD rules
#>

param(
    [string]$RuleName = ""
)

$ErrorActionPreference = "Stop"

Write-Host "=== Simple AD Rule Debugger ===" -ForegroundColor Cyan

# Load helper library
$helperPath = Join-Path $PSScriptRoot "IronVeil-ADSIHelper.ps1"
if (Test-Path $helperPath) {
    . $helperPath
    Write-Host "Helper library loaded" -ForegroundColor Green
} else {
    Write-Host "Helper library not found" -ForegroundColor Red
    exit 1
}

# Get domain info
try {
    $domainInfo = Get-IVDomainInfo
    Write-Host "Domain: $($domainInfo.DomainName)" -ForegroundColor Green
} catch {
    Write-Host "Failed to get domain info: $_" -ForegroundColor Red
    exit 1
}

# Test specific rule if provided
if ($RuleName) {
    $rulePath = Join-Path $PSScriptRoot "$RuleName.ps1"
    if (Test-Path $rulePath) {
        Write-Host ""
        Write-Host "Testing rule: $RuleName" -ForegroundColor Yellow
        
        try {
            $startTime = Get-Date
            $result = & $rulePath
            $duration = (Get-Date) - $startTime
            
            Write-Host "Rule executed successfully in $($duration.TotalMilliseconds)ms" -ForegroundColor Green
            
            if ($result) {
                Write-Host ""
                Write-Host "Result:" -ForegroundColor Cyan
                $result | Format-List | Out-String | Write-Host
            } else {
                Write-Host "No result returned" -ForegroundColor Yellow
            }
            
        } catch {
            Write-Host "Rule failed: $_" -ForegroundColor Red
            Write-Host "Error details: $($_.Exception.Message)" -ForegroundColor Red
        }
    } else {
        Write-Host "Rule not found: $rulePath" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "Environment ready for manual testing" -ForegroundColor Green