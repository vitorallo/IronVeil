<#
.SYNOPSIS
Checks for privileged accounts with poor management practices like PasswordNotRequired or DontExpirePassword

.METADATA
{
  "id": "AD-T3-012",
  "name": "Privileged Account Management Issues",
  "description": "Privileged accounts with PasswordNotRequired, DontExpirePassword flags or other poor management practices",
  "category": "PrivilegedAccess",
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
    
    # Define privileged groups
    $privilegedGroups = @(
        "Domain Admins",
        "Enterprise Admins",
        "Schema Admins",
        "Administrators",
        "Account Operators",
        "Server Operators",
        "Backup Operators",
        "Print Operators",
        "DnsAdmins",
        "DHCP Administrators",
        "Group Policy Creator Owners",
        "Cryptographic Operators",
        "Remote Desktop Users",
        "Remote Management Users"
    )
    
    # Get all privileged users
    $privilegedUsers = @{}
    
    foreach ($groupName in $privilegedGroups) {
        try {
            $group = Get-ADGroup -Identity $groupName -Server $DomainName -ErrorAction Stop
            $members = Get-ADGroupMember -Identity $group -Recursive -Server $DomainName -ErrorAction Stop
            
            foreach ($member in $members) {
                if ($member.objectClass -eq "user") {
                    if (-not $privilegedUsers.ContainsKey($member.DistinguishedName)) {
                        $privilegedUsers[$member.DistinguishedName] = @{
                            Groups = @($groupName)
                            DN = $member.DistinguishedName
                        }
                    } else {
                        $privilegedUsers[$member.DistinguishedName].Groups += $groupName
                    }
                }
            }
        } catch {
            if ($_.Exception.Message -notlike "*Cannot find an object with identity*") {
                Write-Warning "Could not check group '$groupName': $_"
            }
        }
    }
    
    # Also get users with AdminCount=1
    $adminCountUsers = Get-ADUser -Filter {AdminCount -eq 1} `
        -Properties AdminCount, DistinguishedName -Server $DomainName -ErrorAction Stop
    
    foreach ($user in $adminCountUsers) {
        if (-not $privilegedUsers.ContainsKey($user.DistinguishedName)) {
            $privilegedUsers[$user.DistinguishedName] = @{
                Groups = @("AdminCount=1")
                DN = $user.DistinguishedName
            }
        }
    }
    
    # Check each privileged user for management issues
    foreach ($userDN in $privilegedUsers.Keys) {
        try {
            $user = Get-ADUser -Identity $userDN `
                -Properties PasswordNotRequired, PasswordNeverExpires, AccountNotDelegated, `
                           AllowReversiblePasswordEncryption, CannotChangePassword, `
                           PasswordLastSet, LastLogonTimestamp, Enabled, LockedOut, `
                           AccountExpirationDate, SmartcardLogonRequired, userAccountControl, `
                           TrustedForDelegation, TrustedToAuthForDelegation, Description `
                -Server $DomainName -ErrorAction Stop
            
            $issues = @()
            $riskLevel = "Low"
            
            # Check for critical password policy issues
            if ($user.PasswordNotRequired) {
                $issues += "Password not required"
                $riskLevel = "Critical"
            }
            
            if ($user.AllowReversiblePasswordEncryption) {
                $issues += "Reversible encryption enabled"
                $riskLevel = "Critical"
            }
            
            # Check for high-risk settings
            if ($user.PasswordNeverExpires) {
                $issues += "Password never expires"
                if ($riskLevel -ne "Critical") {
                    $riskLevel = "High"
                }
            }
            
            if ($user.CannotChangePassword) {
                $issues += "Cannot change password"
                if ($riskLevel -eq "Low") {
                    $riskLevel = "Medium"
                }
            }
            
            # Check delegation settings
            if ($user.TrustedForDelegation) {
                $issues += "Unconstrained delegation enabled"
                $riskLevel = "High"
            }
            
            if ($user.TrustedToAuthForDelegation) {
                $issues += "Constrained delegation enabled"
                if ($riskLevel -eq "Low") {
                    $riskLevel = "Medium"
                }
            }
            
            if (-not $user.AccountNotDelegated) {
                # Account can be delegated
                if ($privilegedUsers[$userDN].Groups -contains "Domain Admins" -or 
                    $privilegedUsers[$userDN].Groups -contains "Enterprise Admins") {
                    $issues += "High-privilege account can be delegated"
                    if ($riskLevel -eq "Low") {
                        $riskLevel = "Medium"
                    }
                }
            }
            
            # Check password age
            if ($user.PasswordLastSet) {
                $passwordAge = ((Get-Date) - $user.PasswordLastSet).Days
                if ($passwordAge -gt 365) {
                    $issues += "Password is $passwordAge days old"
                    if ($riskLevel -eq "Low") {
                        $riskLevel = "Medium"
                    }
                } elseif ($passwordAge -gt 730) {
                    $issues += "Password is $passwordAge days old (very old)"
                    if ($riskLevel -ne "Critical") {
                        $riskLevel = "High"
                    }
                }
            } else {
                $issues += "Password never set"
                if ($riskLevel -ne "Critical") {
                    $riskLevel = "High"
                }
            }
            
            # Check last logon
            if ($user.Enabled) {
                if ($user.LastLogonTimestamp) {
                    $lastLogon = [DateTime]::FromFileTime($user.LastLogonTimestamp)
                    $daysSinceLogon = ((Get-Date) - $lastLogon).Days
                    
                    if ($daysSinceLogon -gt 90) {
                        $issues += "Inactive for $daysSinceLogon days but still enabled"
                        if ($riskLevel -eq "Low") {
                            $riskLevel = "Medium"
                        }
                    }
                }
            }
            
            # Check for missing Smart Card requirement for high-privilege accounts
            if (($privilegedUsers[$userDN].Groups -contains "Domain Admins" -or 
                 $privilegedUsers[$userDN].Groups -contains "Enterprise Admins") -and
                -not $user.SmartcardLogonRequired) {
                $issues += "No Smart Card requirement for high-privilege account"
                if ($riskLevel -eq "Low") {
                    $riskLevel = "Medium"
                }
            }
            
            # Check for service accounts in privileged groups
            if ($user.Description -match "service|svc|app" -or $user.SamAccountName -match "^svc|^srv|service") {
                $issues += "Appears to be a service account in privileged groups"
                if ($riskLevel -eq "Low") {
                    $riskLevel = "Medium"
                }
            }
            
            # Check userAccountControl flags
            $uac = $user.userAccountControl
            if ($uac) {
                # Check for DONT_REQ_PREAUTH (0x400000)
                if ($uac -band 0x400000) {
                    $issues += "Pre-authentication not required (AS-REP Roastable)"
                    if ($riskLevel -ne "Critical") {
                        $riskLevel = "High"
                    }
                }
                
                # Check for DES encryption (0x200000)
                if ($uac -band 0x200000) {
                    $issues += "DES encryption enabled"
                    if ($riskLevel -eq "Low") {
                        $riskLevel = "Medium"
                    }
                }
            }
            
            if ($issues.Count -gt 0) {
                $groupList = $privilegedUsers[$userDN].Groups -join ", "
                
                $findings += @{
                    ObjectName = $user.SamAccountName
                    ObjectType = "User"
                    RiskLevel = $riskLevel
                    Description = "Privileged account has management issues: $($issues -join '; '). Groups: $groupList"
                    Remediation = "Review and correct account settings. Enable strong password policies, remove unnecessary privileges, and enforce security best practices"
                    AffectedAttributes = @("userAccountControl", "PasswordPolicy", "Delegation")
                }
                $affectedCount++
                
                # Score impact
                if ($riskLevel -eq "Critical") {
                    $score -= 20
                } elseif ($riskLevel -eq "High") {
                    $score -= 15
                } elseif ($riskLevel -eq "Medium") {
                    $score -= 10
                } else {
                    $score -= 5
                }
            }
            
        } catch {
            $ignoredCount++
            Write-Warning "Could not check user ${userDN}: ${_}"
        }
    }
    
    # Check for nested privileged group memberships
    foreach ($groupName in @("Domain Admins", "Enterprise Admins", "Schema Admins")) {
        try {
            $group = Get-ADGroup -Identity $groupName -Server $DomainName -ErrorAction Stop
            $directMembers = Get-ADGroupMember -Identity $group -Server $DomainName -ErrorAction Stop
            
            $nestedGroups = $directMembers | Where-Object { $_.objectClass -eq "group" }
            
            if ($nestedGroups.Count -gt 0) {
                foreach ($nestedGroup in $nestedGroups) {
                    $findings += @{
                        ObjectName = $nestedGroup.Name
                        ObjectType = "Group"
                        RiskLevel = "Medium"
                        Description = "Group '$($nestedGroup.Name)' is nested in high-privilege group '$groupName'"
                        Remediation = "Avoid nesting groups in high-privilege groups. Use direct membership for better visibility and control"
                        AffectedAttributes = @("member")
                    }
                    $affectedCount++
                    $score -= 8
                }
            }
        } catch {
            # Group doesn't exist or can't be checked
        }
    }
    
    # Ensure score doesn't go below 0
    $score = [Math]::Max(0, $score)
    
    # Determine overall status
    $status = if ($findings.Count -eq 0) { "Success" } 
              elseif ($score -lt 50) { "Failed" } 
              else { "Warning" }
    
    $message = if ($findings.Count -eq 0) {
        "All privileged accounts follow security best practices"
    } else {
        "Found $($findings.Count) privileged account management issues"
    }
    
    $executionTime = (Get-Date) - $startTime
    
    return @{
        CheckId = "AD-T3-012"
        Timestamp = (Get-Date).ToString("o")
        Status = $status
        Score = $score
        Severity = "Medium"
        Category = "PrivilegedAccess"
        Findings = $findings
        Message = $message
        AffectedObjects = $affectedCount
        IgnoredObjects = $ignoredCount
        Metadata = @{
            Domain = $DomainName
            ExecutionTime = $executionTime.TotalSeconds
            PrivilegedUsersChecked = $privilegedUsers.Count
        }
    }
    
} catch {
    return @{
        CheckId = "AD-T3-012"
        Timestamp = (Get-Date).ToString("o")
        Status = "Error"
        Score = 0
        Severity = "Medium"
        Category = "PrivilegedAccess"
        Findings = @()
        Message = "Error checking privileged account management: $_"
        AffectedObjects = 0
        IgnoredObjects = 0
        Metadata = @{
            Domain = $DomainName
            ExecutionTime = ((Get-Date) - $startTime).TotalSeconds
            Error = $_.Exception.Message
        }
    }
}