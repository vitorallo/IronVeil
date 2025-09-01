<#
.SYNOPSIS
Detects privileged user accounts with Service Principal Names (SPNs) that are vulnerable to Kerberoasting

.METADATA
{
  "id": "AD-T2-006",
  "name": "Privileged Users with Service Principal Names (SPNs)",
  "description": "Privileged accounts that have SPNs registered are vulnerable to Kerberoasting attacks, where attackers can request service tickets and crack them offline to obtain passwords. This is especially dangerous for privileged accounts.",
  "category": "CredentialExposure",
  "severity": "High",
  "weight": 8,
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
    
    # Import IronVeil ADSI Helper
    . "$PSScriptRoot\IronVeil-ADSIHelper.ps1"
    
    if (-not $DomainName) {
        throw "Domain name could not be determined"
    }
    
    # Get domain information
    $domainInfo = Get-IVDomainInfo -DomainName $DomainName
    $domainDN = $domainInfo.DistinguishedName
    $domainSID = $domainInfo.DomainSID
    
    # Define privileged groups to check
    $privilegedGroups = @(
        @{Name = "Domain Admins"; SID = "$domainSID-512"},
        @{Name = "Enterprise Admins"; SID = "$domainSID-519"},
        @{Name = "Schema Admins"; SID = "$domainSID-518"},
        @{Name = "Administrators"; SID = "S-1-5-32-544"},
        @{Name = "Account Operators"; SID = "S-1-5-32-548"},
        @{Name = "Server Operators"; SID = "S-1-5-32-549"},
        @{Name = "Print Operators"; SID = "S-1-5-32-550"},
        @{Name = "Backup Operators"; SID = "S-1-5-32-551"},
        @{Name = "Domain Controllers"; SID = "$domainSID-516"},
        @{Name = "Read-only Domain Controllers"; SID = "$domainSID-521"},
        @{Name = "Group Policy Creator Owners"; SID = "$domainSID-520"},
        @{Name = "Cryptographic Operators"; SID = "S-1-5-32-569"},
        @{Name = "Distributed COM Users"; SID = "S-1-5-32-562"}
    )
    
    # Get all privileged users
    $privilegedUsers = @{}
    
    foreach ($group in $privilegedGroups) {
        try {
            # Get group members recursively
            $groupMembers = Get-IVADGroupMember -Identity $group.SID -Recursive | 
                            Where-Object { $_.objectClass -eq "user" }
            
            foreach ($member in $groupMembers) {
                if (-not $privilegedUsers.ContainsKey($member.SamAccountName)) {
                    $privilegedUsers[$member.SamAccountName] = @{
                        DN = $member.DistinguishedName
                        Groups = @($group.Name)
                        SID = $member.SID
                    }
                }
                else {
                    $privilegedUsers[$member.SamAccountName].Groups += $group.Name
                }
            }
        }
        catch {
            # Group might not exist in this domain
        }
    }
    
    # Also check for users with adminCount=1 (indicates they're protected by AdminSDHolder)
    $adminCountUsers = Get-IVADUser -Filter "(adminCount=1)" -Properties @('servicePrincipalName', 'adminCount', 'memberOf', 'pwdLastSet', 'lastLogonTimestamp', 'userAccountControl')
    
    foreach ($user in $adminCountUsers) {
        if (-not $privilegedUsers.ContainsKey($user.sAMAccountName)) {
            $privilegedUsers[$user.sAMAccountName] = @{
                DN = $user.DistinguishedName
                Groups = @("AdminSDHolder-Protected")
                SID = $user.objectSid
            }
        }
    }
    
    # Now check each privileged user for SPNs
    $totalPrivilegedUsers = $privilegedUsers.Count
    $usersWithSPNs = 0
    
    foreach ($userName in $privilegedUsers.Keys) {
        try {
            $user = Get-IVADUser -Filter "(sAMAccountName=$userName)" -Properties @('servicePrincipalName', 'pwdLastSet', 'lastLogonTimestamp', 'userAccountControl', 'whenCreated', 'whenChanged')
            
            if ($user -and $user.Count -gt 0) {
                $user = $user[0]
                
                if ($user.servicePrincipalName -and $user.servicePrincipalName.Count -gt 0) {
                    $usersWithSPNs++
                    
                    # Determine risk level based on various factors
                    $riskLevel = "High"  # Base risk for privileged account with SPN
                    $riskFactors = @()
                    
                    # Check if account is enabled
                    $uac = [int]$user.userAccountControl
                    $isEnabled = -not ($uac -band 0x2)  # ACCOUNTDISABLE flag
                    
                    if ($isEnabled) {
                        $riskFactors += "Account is enabled"
                    }
                    else {
                        $riskLevel = "Medium"
                        $riskFactors += "Account is disabled (lower risk)"
                    }
                    
                    # Check password age
                    if ($user.pwdLastSet) {
                        $pwdLastSetTime = [DateTime]::FromFileTime([long]$user.pwdLastSet)
                        $passwordAge = ((Get-Date) - $pwdLastSetTime).Days
                        if ($passwordAge -gt 365) {
                            $riskLevel = "Critical"
                            $riskFactors += "Password not changed for $passwordAge days"
                        }
                        elseif ($passwordAge -gt 180) {
                            $riskFactors += "Password is $passwordAge days old"
                        }
                    }
                    else {
                        $riskFactors += "Password age unknown"
                    }
                    
                    # Check last logon
                    if ($user.lastLogonTimestamp) {
                        $lastLogonTime = [DateTime]::FromFileTime([long]$user.lastLogonTimestamp)
                        $daysSinceLogon = ((Get-Date) - $lastLogonTime).Days
                        if ($daysSinceLogon -gt 90) {
                            $riskFactors += "Inactive for $daysSinceLogon days"
                        }
                    }
                    
                    # Check for specific high-value groups
                    $userGroups = $privilegedUsers[$userName].Groups
                    if ($userGroups -contains "Domain Admins" -or $userGroups -contains "Enterprise Admins") {
                        $riskLevel = "Critical"
                        $riskFactors += "Member of highest privilege groups"
                    }
                    
                    # Check if it's a service account (common pattern)
                    $isLikelyServiceAccount = $false
                    if ($userName -match "^svc|service|sql|backup|exchange|sharepoint|iis" -or 
                        $uac -band 0x200000) {  # TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION
                        $isLikelyServiceAccount = $true
                        $riskFactors += "Appears to be a service account"
                    }
                    
                    # Build SPN list
                    $spnArray = if ($user.servicePrincipalName -is [array]) { 
                        $user.servicePrincipalName 
                    } else { 
                        @($user.servicePrincipalName) 
                    }
                    
                    $spnList = $spnArray -join "; "
                    if ($spnList.Length -gt 200) {
                        $spnList = $spnList.Substring(0, 200) + "..."
                    }
                    
                    $findings += @{
                        ObjectName = $userName
                        ObjectType = "User"
                        RiskLevel = $riskLevel
                        Description = "Privileged user has $($spnArray.Count) SPN(s) registered, making it vulnerable to Kerberoasting. Groups: $($userGroups -join ', '). Risk factors: $($riskFactors -join '; '). SPNs: $spnList"
                        Remediation = "1. If this is a service account, migrate to Group Managed Service Account (gMSA) or Managed Service Account (MSA). 2. If SPNs are not needed, remove them. 3. Ensure strong, unique password (25+ characters). 4. Implement regular password rotation. 5. Monitor for Kerberoasting attacks (Event ID 4769). 6. Consider removing from privileged groups if possible."
                        AffectedAttributes = @("servicePrincipalName", "memberOf", "passwordLastSet")
                    }
                }
            }
        }
        catch {
            # Skip if user cannot be retrieved
        }
    }
    
    # Also check for any user (not just privileged) with high-value SPNs
    $allUsersWithSPNs = Get-IVADUser -Filter "(servicePrincipalName=*)" -Properties @('servicePrincipalName', 'memberOf', 'adminCount', 'pwdLastSet', 'userAccountControl')
    
    $highValueSPNPatterns = @(
        "*sql*", "*exchange*", "*sharepoint*", "*adfs*", "*radius*", 
        "*vmware*", "*vcenter*", "*backup*", "*veeam*", "*netbackup*"
    )
    
    foreach ($user in $allUsersWithSPNs) {
        # Skip if already reported as privileged
        if ($privilegedUsers.ContainsKey($user.sAMAccountName)) {
            continue
        }
        
        # Check if SPN indicates high-value service
        $hasHighValueSPN = $false
        $matchedServices = @()
        
        $spnArray = if ($user.servicePrincipalName -is [array]) { 
            $user.servicePrincipalName 
        } else { 
            @($user.servicePrincipalName) 
        }
        
        foreach ($spn in $spnArray) {
            foreach ($pattern in $highValueSPNPatterns) {
                if ($spn -like $pattern) {
                    $hasHighValueSPN = $true
                    $service = $pattern.Replace("*", "")
                    if ($service -and $matchedServices -notcontains $service) {
                        $matchedServices += $service
                    }
                }
            }
        }
        
        if ($hasHighValueSPN) {
            $passwordAge = if ($user.pwdLastSet) { 
                $pwdLastSetTime = [DateTime]::FromFileTime([long]$user.pwdLastSet)
                ((Get-Date) - $pwdLastSetTime).Days 
            } else { 
                "Unknown" 
            }
            
            $findings += @{
                ObjectName = $user.sAMAccountName
                ObjectType = "User"
                RiskLevel = "Medium"
                Description = "Non-privileged user has high-value service SPN(s) for: $($matchedServices -join ', '). While not directly privileged, compromise could lead to service disruption or lateral movement. Password age: $passwordAge days."
                Remediation = "1. Migrate to managed service accounts if possible. 2. Ensure strong password policy. 3. Monitor for Kerberoasting attempts. 4. Review if service account needs these SPNs."
                AffectedAttributes = @("servicePrincipalName", "passwordLastSet")
            }
        }
    }
    
    # Calculate execution time
    $executionTime = ((Get-Date) - $startTime).TotalSeconds
    
    # Determine final score and status
    $score = 100  # Start with perfect score
    $status = "Success"
    $message = "Kerberoasting vulnerability assessment completed."
    
    if ($findings.Count -gt 0) {
        $criticalCount = @($findings | Where-Object { $_.RiskLevel -eq "Critical" }).Count
        $highCount = @($findings | Where-Object { $_.RiskLevel -eq "High" }).Count
        $mediumCount = @($findings | Where-Object { $_.RiskLevel -eq "Medium" }).Count
        
        if ($criticalCount -gt 0) {
            $score = 0
            $message = "CRITICAL: Found $criticalCount highly privileged account(s) vulnerable to Kerberoasting! These accounts have SPNs and weak password policies."
        }
        elseif ($highCount -gt 0) {
            $score = 25
            $message = "WARNING: Found $highCount privileged account(s) and $mediumCount service account(s) vulnerable to Kerberoasting attacks."
        }
        else {
            $score = 50
            $message = "Found $mediumCount account(s) with high-value SPNs that could be targeted for Kerberoasting."
        }
    }
    else {
        $message = "No privileged accounts with SPNs detected. Kerberoasting risk is minimal."
    }
    
    return @{
        CheckId = "AD-T2-006"
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
            TotalPrivilegedUsers = $totalPrivilegedUsers
            PrivilegedUsersWithSPNs = $usersWithSPNs
            TotalUsersWithSPNs = $allUsersWithSPNs.Count
        }
    }
}
catch {
    return @{
        CheckId = "AD-T2-006"
        Timestamp = (Get-Date).ToString("o")
        Status = "Error"
        Score = 0
        Severity = "High"
        Category = "CredentialExposure"
        Findings = @()
        Message = "Error executing Kerberoasting assessment: $_"
        AffectedObjects = 0
        IgnoredObjects = 0
        Metadata = @{
            Domain = $DomainName
            ExecutionTime = 0.0
            ErrorDetails = $_.Exception.Message
        }
    }
}