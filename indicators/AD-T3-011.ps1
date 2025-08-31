<#
.SYNOPSIS
Scans for user accounts that have SPNs registered enabling Kerberoasting attacks

.METADATA
{
  "id": "AD-T3-011",
  "name": "Service Principal Name (SPN) Misconfigurations - General User Accounts",
  "description": "SPNs registered to regular user accounts with weak passwords enable Kerberoasting attacks",
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
    
    # Get all user accounts with SPNs (excluding computer accounts)
    $usersWithSPNs = Get-ADUser -Filter {servicePrincipalName -like "*"} `
        -Properties servicePrincipalName, PasswordLastSet, LastLogonTimestamp, Enabled, memberOf, `
                   PasswordNeverExpires, PasswordNotRequired, AccountExpirationDate, adminCount `
        -Server $DomainName -ErrorAction Stop
    
    foreach ($user in $usersWithSPNs) {
        $riskFactors = @()
        $riskLevel = "Low"
        
        # Check if account is enabled
        if ($user.Enabled) {
            $riskFactors += "account is enabled"
            
            # Check password age
            if ($user.PasswordLastSet) {
                $passwordAge = ((Get-Date) - $user.PasswordLastSet).Days
                if ($passwordAge -gt 365) {
                    $riskFactors += "password is $passwordAge days old"
                    $riskLevel = "Medium"
                } elseif ($passwordAge -gt 730) {
                    $riskFactors += "password is $passwordAge days old (very old)"
                    $riskLevel = "High"
                }
            } else {
                $riskFactors += "password never set"
                $riskLevel = "High"
            }
            
            # Check for password policy exceptions
            if ($user.PasswordNeverExpires) {
                $riskFactors += "password never expires"
                $riskLevel = "Medium"
            }
            
            if ($user.PasswordNotRequired) {
                $riskFactors += "password not required"
                $riskLevel = "High"
            }
            
            # Check if it's a privileged account
            $isPrivileged = $false
            if ($user.adminCount -eq 1) {
                $isPrivileged = $true
                $riskFactors += "privileged account (AdminCount=1)"
                $riskLevel = "High"
            } else {
                # Check group membership
                $privilegedGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins", 
                                     "Administrators", "Account Operators", "Server Operators", 
                                     "Backup Operators", "Print Operators")
                
                foreach ($group in $user.memberOf) {
                    $groupName = ($group -split ",")[0] -replace "CN=", ""
                    if ($groupName -in $privilegedGroups) {
                        $isPrivileged = $true
                        $riskFactors += "member of $groupName"
                        $riskLevel = "High"
                        break
                    }
                }
            }
            
            # Check last logon
            if ($user.LastLogonTimestamp) {
                $lastLogon = [DateTime]::FromFileTime($user.LastLogonTimestamp)
                $daysSinceLogon = ((Get-Date) - $lastLogon).Days
                
                if ($daysSinceLogon -gt 90) {
                    $riskFactors += "inactive for $daysSinceLogon days"
                    if ($riskLevel -eq "Low") {
                        $riskLevel = "Medium"
                    }
                }
            }
            
            # Check number of SPNs
            $spnCount = $user.servicePrincipalName.Count
            if ($spnCount -gt 5) {
                $riskFactors += "has $spnCount SPNs registered"
            }
            
            # Check for high-value SPNs
            $highValueSPNs = @()
            foreach ($spn in $user.servicePrincipalName) {
                if ($spn -match "MSSQL|HTTP|LDAP|HOST|TERMSRV|WSMan|exchangeAB") {
                    $service = ($spn -split "/")[0]
                    if ($service -notin $highValueSPNs) {
                        $highValueSPNs += $service
                    }
                }
            }
            
            if ($highValueSPNs.Count -gt 0) {
                $riskFactors += "high-value services: $($highValueSPNs -join ', ')"
                if ($riskLevel -eq "Low") {
                    $riskLevel = "Medium"
                }
            }
            
            # Create finding
            $spnList = if ($user.servicePrincipalName.Count -le 3) {
                $user.servicePrincipalName -join '; '
            } else {
                "$($user.servicePrincipalName[0..2] -join '; ') ... ($spnCount total)"
            }
            
            $findings += @{
                ObjectName = $user.SamAccountName
                ObjectType = "User"
                RiskLevel = $riskLevel
                Description = "User account with SPNs is vulnerable to Kerberoasting: $($riskFactors -join ', '). SPNs: $spnList"
                Remediation = if ($isPrivileged) {
                    "Move SPNs to dedicated service accounts with strong passwords and minimal privileges"
                } else {
                    "Ensure account has a strong, unique password and consider using Managed Service Accounts (MSA) instead"
                }
                AffectedAttributes = @("servicePrincipalName", "PasswordLastSet")
            }
            $affectedCount++
            
            # Score impact
            if ($riskLevel -eq "High") {
                $score -= 10
            } elseif ($riskLevel -eq "Medium") {
                $score -= 7
            } else {
                $score -= 4
            }
            
        } else {
            # Disabled account with SPNs - lower risk but still notable
            $findings += @{
                ObjectName = $user.SamAccountName
                ObjectType = "User"
                RiskLevel = "Low"
                Description = "Disabled user account has $($user.servicePrincipalName.Count) SPN(s) registered"
                Remediation = "Remove SPNs from disabled accounts or delete accounts if no longer needed"
                AffectedAttributes = @("servicePrincipalName", "Enabled")
            }
            $affectedCount++
            $score -= 2
        }
    }
    
    # Check for duplicate SPNs
    try {
        $allSPNs = @{}
        $duplicateSPNs = @()
        
        # Collect all SPNs from users
        foreach ($user in $usersWithSPNs) {
            foreach ($spn in $user.servicePrincipalName) {
                if ($allSPNs.ContainsKey($spn)) {
                    $allSPNs[$spn] += ", $($user.SamAccountName)"
                } else {
                    $allSPNs[$spn] = $user.SamAccountName
                }
            }
        }
        
        # Also check computer SPNs for duplicates
        $computersWithSPNs = Get-ADComputer -Filter {servicePrincipalName -like "*"} `
            -Properties servicePrincipalName -Server $DomainName -ErrorAction Stop | 
            Select-Object -First 100  # Limit for performance
        
        foreach ($computer in $computersWithSPNs) {
            foreach ($spn in $computer.servicePrincipalName) {
                if ($allSPNs.ContainsKey($spn)) {
                    $allSPNs[$spn] += ", $($computer.Name)$"
                }
            }
        }
        
        # Find duplicates
        foreach ($spn in $allSPNs.Keys) {
            if ($allSPNs[$spn] -match ",") {
                $duplicateSPNs += @{
                    SPN = $spn
                    Accounts = $allSPNs[$spn]
                }
            }
        }
        
        if ($duplicateSPNs.Count -gt 0) {
            foreach ($dup in $duplicateSPNs) {
                $findings += @{
                    ObjectName = $dup.SPN
                    ObjectType = "ServicePrincipalName"
                    RiskLevel = "High"
                    Description = "Duplicate SPN registered to multiple accounts: $($dup.Accounts)"
                    Remediation = "Remove duplicate SPNs - each SPN should be unique in the domain"
                    AffectedAttributes = @("servicePrincipalName")
                }
                $affectedCount++
                $score -= 8
            }
        }
        
    } catch {
        $ignoredCount++
        Write-Warning "Could not check for duplicate SPNs: $_"
    }
    
    # Check for weak encryption types on accounts with SPNs
    foreach ($user in $usersWithSPNs | Select-Object -First 50) {  # Limit for performance
        try {
            $userDetails = Get-ADUser -Identity $user.DistinguishedName `
                -Properties msDS-SupportedEncryptionTypes -Server $DomainName -ErrorAction Stop
            
            $encTypes = $userDetails."msDS-SupportedEncryptionTypes"
            
            if ($encTypes) {
                # Check if only RC4 is enabled (value 4)
                if ($encTypes -eq 4) {
                    $findings += @{
                        ObjectName = $user.SamAccountName
                        ObjectType = "User"
                        RiskLevel = "Medium"
                        Description = "Kerberoastable account supports only RC4 encryption (weak)"
                        Remediation = "Enable AES encryption for this service account"
                        AffectedAttributes = @("msDS-SupportedEncryptionTypes")
                    }
                    $affectedCount++
                    $score -= 5
                }
            }
        } catch {
            # Skip if can't check encryption types
        }
    }
    
    # Ensure score doesn't go below 0
    $score = [Math]::Max(0, $score)
    
    # Determine overall status
    $status = if ($findings.Count -eq 0) { "Success" } 
              elseif ($score -lt 50) { "Failed" } 
              else { "Warning" }
    
    $message = if ($findings.Count -eq 0) {
        "No risky SPN configurations detected on user accounts"
    } else {
        "Found $($usersWithSPNs.Count) user accounts with SPNs vulnerable to Kerberoasting"
    }
    
    $executionTime = (Get-Date) - $startTime
    
    return @{
        CheckId = "AD-T3-011"
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
            UsersWithSPNs = $usersWithSPNs.Count
            DuplicateSPNs = $duplicateSPNs.Count
        }
    }
    
} catch {
    return @{
        CheckId = "AD-T3-011"
        Timestamp = (Get-Date).ToString("o")
        Status = "Error"
        Score = 0
        Severity = "Medium"
        Category = "Authentication"
        Findings = @()
        Message = "Error checking SPN configurations: $_"
        AffectedObjects = 0
        IgnoredObjects = 0
        Metadata = @{
            Domain = $DomainName
            ExecutionTime = ((Get-Date) - $startTime).TotalSeconds
            Error = $_.Exception.Message
        }
    }
}