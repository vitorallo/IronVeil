<#
.SYNOPSIS
Evaluates the domain's password policy settings for security weaknesses

.METADATA
{
  "id": "AD-T3-002",
  "name": "Weak Password Policies",
  "description": "Lack of strong password policies makes accounts susceptible to brute-force attacks and credential compromise",
  "category": "Authentication",
  "severity": "Medium",
  "weight": 6,
  "impact": 6,
  "frameworks": ["MITRE", "NIST"],
  "targets": ["ActiveDirectory"]
}
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$DomainName = $env:USERDNSDOMAIN
)

$startTime = Get-Date

try {
    # Initialize results
    $findings = @()
    $affectedCount = 0
    $ignoredCount = 0
    $score = 100
    
    # Get default domain password policy
    $passwordPolicy = Get-ADDefaultDomainPasswordPolicy -Server $DomainName -ErrorAction Stop
    
    # Check minimum password length
    if ($passwordPolicy.MinPasswordLength -lt 14) {
        $findings += @{
            ObjectName = "Default Domain Password Policy"
            ObjectType = "PasswordPolicy"
            RiskLevel = if ($passwordPolicy.MinPasswordLength -lt 8) { "High" } else { "Medium" }
            Description = "Minimum password length is only $($passwordPolicy.MinPasswordLength) characters (recommended: 14+)"
            Remediation = "Increase minimum password length to at least 14 characters in Default Domain Policy"
            AffectedAttributes = @("MinPasswordLength")
        }
        $affectedCount++
        $score -= if ($passwordPolicy.MinPasswordLength -lt 8) { 25 } else { 15 }
    }
    
    # Check password complexity requirements
    if (-not $passwordPolicy.ComplexityEnabled) {
        $findings += @{
            ObjectName = "Default Domain Password Policy"
            ObjectType = "PasswordPolicy"
            RiskLevel = "High"
            Description = "Password complexity requirements are not enabled"
            Remediation = "Enable password complexity requirements in Default Domain Policy"
            AffectedAttributes = @("ComplexityEnabled")
        }
        $affectedCount++
        $score -= 20
    }
    
    # Check password history
    if ($passwordPolicy.PasswordHistoryCount -lt 24) {
        $findings += @{
            ObjectName = "Default Domain Password Policy"
            ObjectType = "PasswordPolicy"
            RiskLevel = "Medium"
            Description = "Password history is set to $($passwordPolicy.PasswordHistoryCount) passwords (recommended: 24)"
            Remediation = "Increase password history to remember at least 24 passwords"
            AffectedAttributes = @("PasswordHistoryCount")
        }
        $affectedCount++
        $score -= 10
    }
    
    # Check maximum password age
    if ($passwordPolicy.MaxPasswordAge.TotalDays -gt 90 -or $passwordPolicy.MaxPasswordAge.TotalDays -eq 0) {
        $findings += @{
            ObjectName = "Default Domain Password Policy"
            ObjectType = "PasswordPolicy"
            RiskLevel = "Medium"
            Description = "Maximum password age is $($passwordPolicy.MaxPasswordAge.TotalDays) days (recommended: 60-90 days)"
            Remediation = "Set maximum password age to 60-90 days"
            AffectedAttributes = @("MaxPasswordAge")
        }
        $affectedCount++
        $score -= 15
    }
    
    # Check minimum password age
    if ($passwordPolicy.MinPasswordAge.TotalDays -lt 1) {
        $findings += @{
            ObjectName = "Default Domain Password Policy"
            ObjectType = "PasswordPolicy"
            RiskLevel = "Medium"
            Description = "Minimum password age is $($passwordPolicy.MinPasswordAge.TotalDays) days (allows rapid password cycling)"
            Remediation = "Set minimum password age to at least 1 day to prevent password cycling"
            AffectedAttributes = @("MinPasswordAge")
        }
        $affectedCount++
        $score -= 10
    }
    
    # Check account lockout policy
    if ($passwordPolicy.LockoutThreshold -eq 0) {
        $findings += @{
            ObjectName = "Default Domain Password Policy"
            ObjectType = "PasswordPolicy"
            RiskLevel = "High"
            Description = "Account lockout is not configured (unlimited password attempts allowed)"
            Remediation = "Configure account lockout threshold to 3-5 invalid attempts"
            AffectedAttributes = @("LockoutThreshold")
        }
        $affectedCount++
        $score -= 20
    } elseif ($passwordPolicy.LockoutThreshold -gt 10) {
        $findings += @{
            ObjectName = "Default Domain Password Policy"
            ObjectType = "PasswordPolicy"
            RiskLevel = "Medium"
            Description = "Account lockout threshold is too high: $($passwordPolicy.LockoutThreshold) attempts"
            Remediation = "Reduce account lockout threshold to 3-5 invalid attempts"
            AffectedAttributes = @("LockoutThreshold")
        }
        $affectedCount++
        $score -= 10
    }
    
    # Check lockout duration
    if ($passwordPolicy.LockoutDuration -and $passwordPolicy.LockoutDuration.TotalMinutes -lt 15) {
        $findings += @{
            ObjectName = "Default Domain Password Policy"
            ObjectType = "PasswordPolicy"
            RiskLevel = "Medium"
            Description = "Account lockout duration is only $($passwordPolicy.LockoutDuration.TotalMinutes) minutes"
            Remediation = "Increase lockout duration to at least 15-30 minutes"
            AffectedAttributes = @("LockoutDuration")
        }
        $affectedCount++
        $score -= 10
    }
    
    # Check for Fine-Grained Password Policies
    try {
        $fgppList = Get-ADFineGrainedPasswordPolicy -Filter * -Server $DomainName -ErrorAction Stop
        
        foreach ($fgpp in $fgppList) {
            $fgppIssues = @()
            
            if ($fgpp.MinPasswordLength -lt 14) {
                $fgppIssues += "weak password length ($($fgpp.MinPasswordLength) chars)"
            }
            if (-not $fgpp.ComplexityEnabled) {
                $fgppIssues += "complexity disabled"
            }
            if ($fgpp.PasswordHistoryCount -lt 24) {
                $fgppIssues += "insufficient password history ($($fgpp.PasswordHistoryCount))"
            }
            if ($fgpp.LockoutThreshold -eq 0) {
                $fgppIssues += "no account lockout"
            }
            
            if ($fgppIssues.Count -gt 0) {
                $findings += @{
                    ObjectName = $fgpp.Name
                    ObjectType = "FineGrainedPasswordPolicy"
                    RiskLevel = "Medium"
                    Description = "Fine-Grained Password Policy has weaknesses: $($fgppIssues -join ', ')"
                    Remediation = "Review and strengthen Fine-Grained Password Policy settings"
                    AffectedAttributes = @("PasswordSettings")
                }
                $affectedCount++
                $score -= 5
            }
        }
    } catch {
        $ignoredCount++
        Write-Warning "Could not check Fine-Grained Password Policies: $_"
    }
    
    # Check for reversible encryption
    if ($passwordPolicy.ReversibleEncryptionEnabled) {
        $findings += @{
            ObjectName = "Default Domain Password Policy"
            ObjectType = "PasswordPolicy"
            RiskLevel = "Critical"
            Description = "Passwords are stored using reversible encryption"
            Remediation = "Disable reversible encryption immediately - passwords are essentially stored in plaintext"
            AffectedAttributes = @("ReversibleEncryptionEnabled")
        }
        $affectedCount++
        $score -= 30
    }
    
    # Ensure score doesn't go below 0
    $score = [Math]::Max(0, $score)
    
    # Determine overall status
    $status = if ($findings.Count -eq 0) { "Success" } 
              elseif ($score -lt 50) { "Failed" } 
              else { "Warning" }
    
    $message = if ($findings.Count -eq 0) {
        "Password policies meet security best practices"
    } else {
        "Found $($findings.Count) password policy weaknesses affecting domain security"
    }
    
    $executionTime = (Get-Date) - $startTime
    
    return @{
        CheckId = "AD-T3-002"
        Timestamp = (Get-Date).ToString("o")
        Status = $status
        Score = $score
        Severity = "Medium"
        Category = "Authentication"
        Findings = $findings
        Message = $message
        AffectedObjects = $affectedCount
        IgnoredObjects = $ignoredCount
        Metadata = @{
            Domain = $DomainName
            ExecutionTime = $executionTime.TotalSeconds
            FineGrainedPoliciesChecked = $fgppList.Count
        }
    }
    
} catch {
    return @{
        CheckId = "AD-T3-002"
        Timestamp = (Get-Date).ToString("o")
        Status = "Error"
        Score = 0
        Severity = "Medium"
        Category = "Authentication"
        Findings = @()
        Message = "Error checking password policies: $_"
        AffectedObjects = 0
        IgnoredObjects = 0
        Metadata = @{
            Domain = $DomainName
            ExecutionTime = ((Get-Date) - $startTime).TotalSeconds
            Error = $_.Exception.Message
        }
    }
}