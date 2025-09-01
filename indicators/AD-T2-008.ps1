<#
.SYNOPSIS
Detects if the KRBTGT account password has not been rotated regularly

.METADATA
{
  "id": "AD-T2-008",
  "name": "Old KRBTGT Password",
  "description": "The KRBTGT account's password should be rotated regularly to prevent Golden Ticket attacks. An old KRBTGT password allows attackers with previously compromised hashes to forge authentication tickets indefinitely.",
  "category": "PersistenceAndBackdoor",
  "severity": "High",
  "weight": 8,
  "impact": 9,
  "frameworks": ["MITRE", "NIST"],
  "targets": ["ActiveDirectory"]
}
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$DomainName = $env:USERDNSDOMAIN
)

try {
    $startTime = Get-Date
    $findings = @()
    
    # Import IronVeil ADSI Helper
    . "$PSScriptRoot\IronVeil-ADSIHelper.ps1"
    
    if (-not $DomainName) {
        throw "Domain name could not be determined"
    }
    
    # Get domain information
    $domainInfo = Get-IVDomainInfo -DomainName $DomainName
    $domainDN = $domainInfo.DistinguishedName
    
    # Define password age thresholds (in days)
    $criticalThreshold = 365 * 2  # 2 years - critical risk
    $highThreshold = 365          # 1 year - high risk
    $warningThreshold = 180       # 6 months - warning
    $recommendedRotation = 180    # Microsoft recommends 180 days
    
    # Get all KRBTGT accounts (including Read-Only Domain Controller KRBTGT accounts)
    $krbtgtAccounts = Get-IVADUser -Filter "(sAMAccountName=krbtgt*)" `
                                   -Properties @('pwdLastSet', 'whenCreated', 'whenChanged', 'userAccountControl',
                                               'lastLogonTimestamp', 'description')
    
    if ($krbtgtAccounts.Count -eq 0) {
        throw "Unable to find KRBTGT account(s) in domain $DomainName"
    }
    
    foreach ($krbtgt in $krbtgtAccounts) {
        $accountName = $krbtgt.sAMAccountName
        $isMainKrbtgt = ($accountName -eq "krbtgt")
        $accountType = if ($isMainKrbtgt) { "Primary KRBTGT" } else { "RODC KRBTGT" }
        
        # Get password age
        $passwordAge = $null
        $passwordLastSetDate = $null
        
        if ($krbtgt.pwdLastSet) {
            # Convert from FileTime to DateTime
            $passwordLastSetDate = [DateTime]::FromFileTime([long]$krbtgt.pwdLastSet)
            $passwordAge = ((Get-Date) - $passwordLastSetDate).Days
        }
        else {
            # If no password last set date, use account creation date as fallback
            if ($krbtgt.whenCreated) {
                $whenCreatedTime = if ($krbtgt.whenCreated -is [DateTime]) { 
                    $krbtgt.whenCreated 
                } else { 
                    [DateTime]::Parse($krbtgt.whenCreated) 
                }
                $passwordLastSetDate = $whenCreatedTime
                $passwordAge = ((Get-Date) - $passwordLastSetDate).Days
            }
        }
        
        if ($passwordAge -eq $null) {
            # Critical finding - cannot determine password age
            $findings += @{
                ObjectName = $accountName
                ObjectType = $accountType
                RiskLevel = "Critical"
                Description = "Cannot determine password age for $accountType account. This is highly unusual and could indicate tampering or corruption."
                Remediation = "1. IMMEDIATELY investigate this account. 2. Consider resetting the KRBTGT password twice (with 24-hour gap). 3. Check domain controller event logs for any modifications to this account. 4. This could indicate a sophisticated attack."
                AffectedAttributes = @("pwdLastSet", "passwordLastSet")
            }
            continue
        }
        
        # Determine risk level based on password age
        $riskLevel = "Low"
        $riskFactors = @()
        
        if ($passwordAge -gt $criticalThreshold) {
            $riskLevel = "Critical"
            $yearsOld = [Math]::Round($passwordAge / 365, 1)
            $riskFactors += "Password is $yearsOld YEARS old!"
            $riskFactors += "Extreme risk of Golden Ticket attacks"
            $riskFactors += "Any historical compromise can still be exploited"
        }
        elseif ($passwordAge -gt $highThreshold) {
            $riskLevel = "High"
            $riskFactors += "Password is over 1 year old"
            $riskFactors += "High risk of Golden Ticket persistence"
        }
        elseif ($passwordAge -gt $warningThreshold) {
            $riskLevel = "Medium"
            $riskFactors += "Password exceeds recommended rotation period"
        }
        
        # Additional checks for the primary KRBTGT account
        if ($isMainKrbtgt) {
            # Check if account is disabled (it should be)
            $uac = [int]$krbtgt.userAccountControl
            $isEnabled = -not ($uac -band 0x2)  # ACCOUNTDISABLE flag
            
            if ($isEnabled) {
                $riskLevel = "Critical"
                $riskFactors += "KRBTGT account is ENABLED - this should NEVER happen!"
            }
            
            # Check for any last logon (KRBTGT should never log on)
            if ($krbtgt.lastLogonTimestamp) {
                $lastLogonTime = [DateTime]::FromFileTime([long]$krbtgt.lastLogonTimestamp)
                $daysSinceLogon = ((Get-Date) - $lastLogonTime).Days
                $riskLevel = "Critical"
                $riskFactors += "KRBTGT has a last logon date ($daysSinceLogon days ago) - highly suspicious!"
            }
        }
        
        # Check domain functional level for additional context
        $domainMode = $domainInfo.DomainMode
        if ($domainMode -and $domainMode -lt "2012R2" -and $passwordAge -gt $highThreshold) {
            $riskFactors += "Legacy domain functional level ($domainMode) increases risk"
        }
        
        if ($passwordAge -gt $warningThreshold) {
            # Build comprehensive description
            $description = "$accountType account password was last set $passwordAge days ago"
            
            if ($passwordLastSetDate) {
                $description += " (on $($passwordLastSetDate.ToString('yyyy-MM-dd')))"
            }
            
            $description += ". "
            
            if ($passwordAge -gt $criticalThreshold) {
                $description += "This is EXTREMELY dangerous and allows Golden Ticket attacks using any historically compromised KRBTGT hash. "
            }
            elseif ($passwordAge -gt $highThreshold) {
                $description += "This significantly increases the risk of Golden Ticket attacks. "
            }
            else {
                $description += "Microsoft recommends rotating KRBTGT password every 180 days. "
            }
            
            if ($riskFactors.Count -gt 0) {
                $description += "Risk factors: $($riskFactors -join '; '). "
            }
            
            # Determine remediation based on age
            $remediation = if ($passwordAge -gt $criticalThreshold) {
                "1. CRITICAL: Reset KRBTGT password IMMEDIATELY using Microsoft's KRBTGT Reset Script. 2. Reset it TWICE with at least 24 hours between resets (to invalidate old tickets). 3. Monitor for Golden Ticket usage (Event ID 4769 with failure codes). 4. Consider this domain potentially compromised. 5. After reset, implement quarterly KRBTGT rotation policy."
            }
            elseif ($passwordAge -gt $highThreshold) {
                "1. HIGH PRIORITY: Schedule KRBTGT password reset within 1 week. 2. Use Microsoft's official KRBTGT Reset Script. 3. Perform two resets 24 hours apart. 4. Monitor domain controller logs for anomalies. 5. Implement regular rotation schedule (every 180 days)."
            }
            else {
                "1. Schedule KRBTGT password rotation. 2. Use Microsoft's KRBTGT Reset Script. 3. Implement automated rotation every 180 days. 4. Document the rotation in change management. 5. Test in non-production first if available."
            }
            
            $findings += @{
                ObjectName = $accountName
                ObjectType = $accountType
                RiskLevel = $riskLevel
                Description = $description
                Remediation = $remediation
                AffectedAttributes = @("pwdLastSet", "passwordAge", "goldenTicketRisk")
            }
        }
    }
    
    # Check for multiple KRBTGT accounts (RODCs)
    $rodcKrbtgtCount = @($krbtgtAccounts | Where-Object { $_.sAMAccountName -ne "krbtgt" }).Count
    if ($rodcKrbtgtCount -gt 0) {
        # This is informational, not necessarily a finding
        $rodcInfo = "Domain has $rodcKrbtgtCount Read-Only Domain Controller KRBTGT account(s). Each RODC has its own KRBTGT account for security isolation."
    }
    
    # Calculate execution time
    $executionTime = ((Get-Date) - $startTime).TotalSeconds
    
    # Determine final score and status
    $score = 100  # Start with perfect score
    $status = "Success"
    $message = "KRBTGT password age assessment completed."
    
    if ($findings.Count -gt 0) {
        $criticalCount = @($findings | Where-Object { $_.RiskLevel -eq "Critical" }).Count
        $highCount = @($findings | Where-Object { $_.RiskLevel -eq "High" }).Count
        $mediumCount = @($findings | Where-Object { $_.RiskLevel -eq "Medium" }).Count
        
        # Get the oldest KRBTGT password age for the message
        $oldestAge = ($findings | ForEach-Object {
            if ($_.Description -match "(\d+) days ago") {
                [int]$Matches[1]
            }
        } | Measure-Object -Maximum).Maximum
        
        if ($criticalCount -gt 0) {
            $score = 0
            $yearsOld = [Math]::Round($oldestAge / 365, 1)
            $message = "CRITICAL: KRBTGT password is $yearsOld YEARS old! Domain is vulnerable to Golden Ticket attacks. Immediate action required!"
        }
        elseif ($highCount -gt 0) {
            $score = 25
            $message = "HIGH RISK: KRBTGT password is $oldestAge days old (over 1 year). Significant Golden Ticket attack risk."
        }
        else {
            $score = 50
            $message = "WARNING: KRBTGT password is $oldestAge days old. Exceeds recommended 180-day rotation period."
        }
        
        if ($rodcKrbtgtCount -gt 0) {
            $message += " Note: $rodcKrbtgtCount RODC KRBTGT account(s) also detected."
        }
    }
    else {
        # Get the actual age even if it's within threshold
        $mainKrbtgt = $krbtgtAccounts | Where-Object { $_.sAMAccountName -eq "krbtgt" } | Select-Object -First 1
        if ($mainKrbtgt -and $mainKrbtgt.pwdLastSet) {
            $currentAge = ((Get-Date) - [DateTime]::FromFileTime([long]$mainKrbtgt.pwdLastSet)).Days
            $message = "Excellent! KRBTGT password is only $currentAge days old, well within the recommended 180-day rotation period."
        }
        else {
            $message = "KRBTGT password age is within acceptable limits."
        }
    }
    
    return @{
        CheckId = "AD-T2-008"
        Timestamp = (Get-Date).ToString("o")
        Status = $status
        Score = $score
        Severity = "High"
        Category = "PersistenceAndBackdoor"
        Findings = $findings
        Message = $message
        AffectedObjects = $findings.Count
        IgnoredObjects = 0
        Metadata = @{
            Domain = $DomainName
            ExecutionTime = [Math]::Round($executionTime, 2)
            KRBTGTAccountsFound = $krbtgtAccounts.Count
            RODCKRBTGTAccounts = $rodcKrbtgtCount
            RecommendedRotationDays = $recommendedRotation
        }
    }
}
catch {
    return @{
        CheckId = "AD-T2-008"
        Timestamp = (Get-Date).ToString("o")
        Status = "Error"
        Score = 0
        Severity = "High"
        Category = "PersistenceAndBackdoor"
        Findings = @()
        Message = "Error executing KRBTGT password age assessment: $_"
        AffectedObjects = 0
        IgnoredObjects = 0
        Metadata = @{
            Domain = $DomainName
            ExecutionTime = 0.0
            ErrorDetails = $_.Exception.Message
        }
    }
}