<#
.SYNOPSIS
Detects user accounts with Kerberos pre-authentication disabled (AS-REP Roasting vulnerability)

.METADATA
{
  "id": "AD-T2-007",
  "name": "Users with Kerberos Pre-Authentication Disabled",
  "description": "Accounts with Kerberos pre-authentication disabled are vulnerable to AS-REP Roasting attacks, where attackers can request AS-REP responses and crack them offline to obtain passwords without any authentication.",
  "category": "CredentialExposure",
  "severity": "High",
  "weight": 7,
  "impact": 8,
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
    
    # Import required module
    Import-Module ActiveDirectory -ErrorAction SilentlyContinue
    
    if (-not $DomainName) {
        throw "Domain name could not be determined"
    }
    
    # Get domain information
    $domain = Get-ADDomain -Identity $DomainName
    $domainDN = $domain.DistinguishedName
    $domainSID = $domain.DomainSID.Value
    
    # UserAccountControl flag for "Do not require Kerberos preauthentication"
    $DONT_REQ_PREAUTH = 0x400000  # 4194304 in decimal
    
    # Get all users with Kerberos pre-authentication disabled
    # Using LDAP filter with bitwise AND operation
    $vulnerableUsers = Get-ADUser -LDAPFilter "(userAccountControl:1.2.840.113556.1.4.803:=4194304)" `
                                  -Properties userAccountControl, memberOf, adminCount, passwordLastSet, `
                                             lastLogonDate, enabled, whenCreated, whenChanged, `
                                             description, title, department
    
    # Define privileged groups for risk assessment
    $privilegedGroups = @(
        "$domainSID-512",  # Domain Admins
        "$domainSID-519",  # Enterprise Admins
        "$domainSID-518",  # Schema Admins
        "S-1-5-32-544",    # Administrators
        "$domainSID-516",  # Domain Controllers
        "$domainSID-520",  # Group Policy Creator Owners
        "S-1-5-32-548",    # Account Operators
        "S-1-5-32-549",    # Server Operators
        "S-1-5-32-550",    # Print Operators
        "S-1-5-32-551"     # Backup Operators
    )
    
    $totalVulnerable = $vulnerableUsers.Count
    $privilegedVulnerable = 0
    $enabledVulnerable = 0
    
    foreach ($user in $vulnerableUsers) {
        # Determine risk level based on various factors
        $riskLevel = "Medium"  # Base risk
        $riskFactors = @()
        
        # Check if account is enabled
        if ($user.enabled) {
            $enabledVulnerable++
            $riskFactors += "Account is active"
            $riskLevel = "High"
        }
        else {
            $riskFactors += "Account is disabled (reduced risk)"
        }
        
        # Check if user is privileged
        $isPrivileged = $false
        $privilegedGroupNames = @()
        
        # Check adminCount
        if ($user.adminCount -eq 1) {
            $isPrivileged = $true
            $privilegedGroupNames += "AdminSDHolder-Protected"
        }
        
        # Check group memberships
        if ($user.memberOf) {
            foreach ($group in $user.memberOf) {
                try {
                    $groupObj = Get-ADGroup -Identity $group -Properties primaryGroupToken
                    $groupSID = $groupObj.SID.Value
                    
                    if ($groupSID -in $privilegedGroups) {
                        $isPrivileged = $true
                        $privilegedGroupNames += $groupObj.Name
                    }
                    
                    # Also check for sensitive non-default groups
                    if ($groupObj.Name -match "admin|operator|backup|replicat|certif|schema|enterpr|domain con") {
                        if ($privilegedGroupNames -notcontains $groupObj.Name) {
                            $privilegedGroupNames += $groupObj.Name
                        }
                    }
                }
                catch {
                    # Skip if group cannot be resolved
                }
            }
        }
        
        if ($isPrivileged) {
            $privilegedVulnerable++
            $riskLevel = "Critical"
            $riskFactors += "Member of privileged groups: $($privilegedGroupNames[0..2] -join ', ')"
        }
        
        # Check password age
        $passwordInfo = "Unknown"
        if ($user.passwordLastSet) {
            $passwordAge = ((Get-Date) - $user.passwordLastSet).Days
            $passwordInfo = "$passwordAge days old"
            
            if ($passwordAge -gt 365) {
                $riskFactors += "Password not changed for over a year"
                if ($riskLevel -eq "Medium") {
                    $riskLevel = "High"
                }
            }
            elseif ($passwordAge -gt 180) {
                $riskFactors += "Password is $passwordAge days old"
            }
        }
        else {
            $riskFactors += "Password never set or age unknown"
        }
        
        # Check last logon
        $activityInfo = "Unknown"
        if ($user.lastLogonDate) {
            $daysSinceLogon = ((Get-Date) - $user.lastLogonDate).Days
            $activityInfo = "Last logon $daysSinceLogon days ago"
            
            if ($daysSinceLogon -lt 30 -and $user.enabled) {
                $riskFactors += "Recently active account"
                if ($riskLevel -eq "Medium") {
                    $riskLevel = "High"
                }
            }
            elseif ($daysSinceLogon -gt 180) {
                $riskFactors += "Inactive for $daysSinceLogon days"
                if ($riskLevel -eq "High" -and -not $isPrivileged) {
                    $riskLevel = "Medium"
                }
            }
        }
        
        # Check if it appears to be a service account
        $accountType = "User"
        if ($user.SamAccountName -match "^svc|service|sql|app|daemon|batch|task|job" -or
            $user.description -match "service|automated|batch|scheduled|system") {
            $accountType = "Service Account"
            $riskFactors += "Appears to be a service account"
        }
        
        # Check account age
        if ($user.whenCreated) {
            $accountAge = ((Get-Date) - $user.whenCreated).Days
            if ($accountAge -lt 30) {
                $riskFactors += "Recently created account ($accountAge days)"
            }
        }
        
        # Build description
        $description = "User has 'Do not require Kerberos preauthentication' flag set, vulnerable to AS-REP Roasting. "
        $description += "Account type: $accountType. Status: $(if($user.enabled){'Enabled'}else{'Disabled'}). "
        $description += "Password: $passwordInfo. Activity: $activityInfo. "
        $description += "Risk factors: $($riskFactors -join '; ')."
        
        $findings += @{
            ObjectName = $user.SamAccountName
            ObjectType = $accountType
            RiskLevel = $riskLevel
            Description = $description
            Remediation = "1. Enable Kerberos pre-authentication for this account immediately. 2. Reset the account password. 3. Review why pre-authentication was disabled. 4. If this is a service account, consider migrating to gMSA. 5. Monitor for AS-REP roasting attacks (unusual AS-REQ without pre-auth). 6. Implement strong password policy."
            AffectedAttributes = @("userAccountControl", "DONT_REQUIRE_PREAUTH", "passwordLastSet")
        }
    }
    
    # Also check for computer accounts with pre-auth disabled (less common but possible)
    $vulnerableComputers = Get-ADComputer -LDAPFilter "(userAccountControl:1.2.840.113556.1.4.803:=4194304)" `
                                          -Properties userAccountControl, operatingSystem, lastLogonDate, enabled
    
    foreach ($computer in $vulnerableComputers) {
        $findings += @{
            ObjectName = $computer.Name
            ObjectType = "Computer"
            RiskLevel = "High"
            Description = "Computer account has Kerberos pre-authentication disabled. OS: $($computer.operatingSystem). This is highly unusual and could indicate compromise or misconfiguration."
            Remediation = "1. Investigate why this computer has pre-auth disabled. 2. Enable Kerberos pre-authentication. 3. Check if this computer is legitimate. 4. Review recent changes to this computer object. 5. Consider this a potential indicator of compromise."
            AffectedAttributes = @("userAccountControl", "DONT_REQUIRE_PREAUTH")
        }
    }
    
    # Calculate execution time
    $executionTime = ((Get-Date) - $startTime).TotalSeconds
    
    # Determine final score and status
    $score = 100  # Start with perfect score
    $status = "Success"
    $message = "AS-REP Roasting vulnerability assessment completed."
    
    if ($findings.Count -gt 0) {
        $criticalCount = @($findings | Where-Object { $_.RiskLevel -eq "Critical" }).Count
        $highCount = @($findings | Where-Object { $_.RiskLevel -eq "High" }).Count
        $mediumCount = @($findings | Where-Object { $_.RiskLevel -eq "Medium" }).Count
        
        if ($criticalCount -gt 0) {
            $score = 0
            $message = "CRITICAL: Found $criticalCount privileged account(s) vulnerable to AS-REP Roasting! These accounts can be compromised without any authentication."
        }
        elseif ($highCount -gt 0) {
            $score = 25
            $message = "WARNING: Found $highCount active account(s) vulnerable to AS-REP Roasting. $enabledVulnerable of $totalVulnerable vulnerable accounts are enabled."
        }
        else {
            $score = 50
            $message = "Found $mediumCount account(s) with Kerberos pre-authentication disabled. Most are disabled or inactive accounts."
        }
        
        if ($vulnerableComputers.Count -gt 0) {
            $message += " Also found $($vulnerableComputers.Count) computer account(s) with pre-auth disabled - highly unusual!"
            if ($score -gt 25) {
                $score = 25
            }
        }
    }
    else {
        $message = "Excellent! No accounts with Kerberos pre-authentication disabled. AS-REP Roasting attack vector is not present."
    }
    
    return @{
        CheckId = "AD-T2-007"
        Timestamp = (Get-Date).ToString("o")
        Status = $status
        Score = $score
        Severity = "High"
        Category = "CredentialExposure"
        Findings = $findings
        Message = $message
        AffectedObjects = $findings.Count
        IgnoredObjects = 0
        Metadata = @{
            Domain = $DomainName
            ExecutionTime = [Math]::Round($executionTime, 2)
            VulnerableUsers = $vulnerableUsers.Count
            VulnerableComputers = $vulnerableComputers.Count
            PrivilegedVulnerable = $privilegedVulnerable
            EnabledVulnerable = $enabledVulnerable
        }
    }
}
catch {
    return @{
        CheckId = "AD-T2-007"
        Timestamp = (Get-Date).ToString("o")
        Status = "Error"
        Score = 0
        Severity = "High"
        Category = "CredentialExposure"
        Findings = @()
        Message = "Error executing AS-REP Roasting assessment: $_"
        AffectedObjects = 0
        IgnoredObjects = 0
        Metadata = @{
            Domain = $DomainName
            ExecutionTime = 0.0
            ErrorDetails = $_.Exception.Message
        }
    }
}