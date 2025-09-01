<#
.SYNOPSIS
Verifies that IronVeil is 100% RSAT-free by checking all security rules
#>

Write-Host "`n=== IronVeil RSAT-Free Verification ===" -ForegroundColor Cyan
Write-Host "Checking all security rules for ActiveDirectory module dependencies...`n" -ForegroundColor Yellow

$rulesPath = $PSScriptRoot
$totalRules = 0
$rsatDependentRules = @()
$adsiRules = @()

# Get all security rule files (AD-T*, EID-T*, AZ-T*)
$ruleFiles = Get-ChildItem -Path $rulesPath -Filter "*.ps1" | 
    Where-Object { $_.Name -match "^(AD|EID|AZ)-T[0-9]+-[0-9]+\.ps1$" }

foreach ($file in $ruleFiles) {
    $totalRules++
    $content = Get-Content $file.FullName -Raw
    
    # Check for ActiveDirectory module
    if ($content -match "Import-Module\s+ActiveDirectory") {
        $rsatDependentRules += $file.Name
        Write-Host "❌ $($file.Name)" -ForegroundColor Red -NoNewline
        Write-Host " - Still uses ActiveDirectory module" -ForegroundColor Yellow
    }
    # Check for ADSI Helper usage
    elseif ($content -match "IronVeil-ADSIHelper\.ps1") {
        $adsiRules += $file.Name
        Write-Host "✅ $($file.Name)" -ForegroundColor Green -NoNewline
        Write-Host " - Uses ADSI (RSAT-free)" -ForegroundColor Gray
    }
    # Rule doesn't use AD at all (likely Entra-only)
    else {
        Write-Host "✅ $($file.Name)" -ForegroundColor Green -NoNewline
        Write-Host " - No AD dependency" -ForegroundColor Gray
    }
}

Write-Host "`n=== Summary ===" -ForegroundColor Cyan
Write-Host "Total Security Rules: $totalRules" -ForegroundColor White
Write-Host "ADSI-based Rules: $($adsiRules.Count)" -ForegroundColor Green
Write-Host "RSAT-dependent Rules: $($rsatDependentRules.Count)" -ForegroundColor $(if ($rsatDependentRules.Count -eq 0) { "Green" } else { "Red" })

if ($rsatDependentRules.Count -eq 0) {
    Write-Host "`n🎉 SUCCESS! IronVeil is 100% RSAT-FREE! 🎉" -ForegroundColor Green
    Write-Host "All Active Directory operations now use pure ADSI implementation." -ForegroundColor Green
    Write-Host "No Remote Server Administration Tools required!" -ForegroundColor Green
} else {
    Write-Host "`nThe following rules still need conversion:" -ForegroundColor Red
    $rsatDependentRules | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
}

# Additional checks
Write-Host "`n=== Additional Verification ===" -ForegroundColor Cyan

# Check if helper library exists
if (Test-Path (Join-Path $rulesPath "IronVeil-ADSIHelper.ps1")) {
    Write-Host "✅ IronVeil-ADSIHelper.ps1 exists" -ForegroundColor Green
} else {
    Write-Host "❌ IronVeil-ADSIHelper.ps1 not found!" -ForegroundColor Red
}

# Check test tools
$testFiles = @("Simple-AD-Test.ps1", "Simple-Debug.ps1")
$testFilesWithRSAT = @()

foreach ($testFile in $testFiles) {
    $testPath = Join-Path $rulesPath $testFile
    if (Test-Path $testPath) {
        $content = Get-Content $testPath -Raw
        if ($content -match "Import-Module\s+ActiveDirectory") {
            $testFilesWithRSAT += $testFile
        }
    }
}

if ($testFilesWithRSAT.Count -gt 0) {
    Write-Host "`nNote: The following test/debug files still reference ActiveDirectory module:" -ForegroundColor Yellow
    Write-Host "(This is OK - they are for testing/comparison purposes only)" -ForegroundColor Gray
    $testFilesWithRSAT | ForEach-Object { Write-Host "  - $_" -ForegroundColor Gray }
}

Write-Host "`n=== Verification Complete ===" -ForegroundColor Cyan