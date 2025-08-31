<#
.SYNOPSIS
Checks if the Backup Operators group contains regular user accounts instead of dedicated service accounts

.METADATA
{
  "id": "AD-T4-004",
  "name": "Backup Operators Group Contains User Accounts",
  "description": "The Backup Operators group contains regular user accounts instead of dedicated service accounts, potentially providing excessive privileges",
  "category": "PrivilegedAccess",
  "severity": "Low",
  "weight": 4,
  "impact": 4,
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
    
    # Get domain information
    $domain = Get-ADDomain -Server $DomainName -ErrorAction Stop
    
    # Define privileged groups to check (including Backup Operators)
    $privilegedGroups = @(
        @{ Name = 'Backup Operators'; SID = 'S-1-5-32-551'; RiskLevel = 'Low' },
        @{ Name = 'Server Operators'; SID = 'S-1-5-32-549'; RiskLevel = 'Medium' },
        @{ Name = 'Print Operators'; SID = 'S-1-5-32-550'; RiskLevel = 'Low' },
        @{ Name = 'Account Operators'; SID = 'S-1-5-32-548'; RiskLevel = 'Medium' }
    )
    
    foreach ($group in $privilegedGroups) {
        try {
            # Get group members
            $groupObj = Get-ADGroup -Identity $group.SID -Server $DomainName -ErrorAction Stop
            $members = Get-ADGroupMember -Identity $groupObj -Server $DomainName -Recursive -ErrorAction Stop
            
            if ($members.Count -gt 0) {
                foreach ($member in $members) {
                    if ($member.objectClass -eq 'user') {
                        # Get user details
                        $user = Get-ADUser -Identity $member.DistinguishedName -Server $DomainName -Properties * -ErrorAction Stop
                        
                        # Check if this appears to be a regular user account
                        $isRegularUser = $false
                        $reasons = @()
                        
                        # Check 1: Has an email address (usually indicates human user)
                        if ($user.EmailAddress) {
                            $isRegularUser = $true
                            $reasons += "has email address"
                        }
                        
                        # Check 2: Has recent interactive logons
                        if ($user.LastLogonDate) {
                            $daysSinceLogon = (Get-Date) - $user.LastLogonDate
                            if ($daysSinceLogon.Days -lt 30) {
                                # Check logon type (would need event logs for detailed analysis)
                                $isRegularUser = $true
                                $reasons += "recent interactive logons"
                            }
                        }
                        
                        # Check 3: Account naming convention (not starting with svc, srv, service, etc.)
                        $serviceAccountPatterns = @('svc*', 'srv*', 'service*', 's-*', 'app*', 'task*')
                        $isServiceAccount = $false
                        foreach ($pattern in $serviceAccountPatterns) {
                            if ($user.SamAccountName -like $pattern) {
                                $isServiceAccount = $true
                                break
                            }
                        }
                        
                        if (-not $isServiceAccount) {
                            $isRegularUser = $true
                            $reasons += "naming convention suggests human user"
                        }
                        
                        # Check 4: Has a home directory or profile path
                        if ($user.HomeDirectory -or $user.ProfilePath) {
                            $isRegularUser = $true
                            $reasons += "has home directory/profile"
                        }
                        
                        # Check 5: Is member of interactive groups
                        $userGroups = Get-ADPrincipalGroupMembership -Identity $user.DistinguishedName -Server $DomainName -ErrorAction SilentlyContinue
                        if ($userGroups) {
                            $interactiveGroups = $userGroups | Where-Object { 
                                $_.Name -match 'Remote Desktop|Domain Users|Users' -and 
                                $_.Name -notmatch 'Denied|Restricted'
                            }
                            if ($interactiveGroups) {
                                $isRegularUser = $true
                                $reasons += "member of interactive groups"
                            }
                        }
                        
                        # Check 6: Password policy suggests human user
                        if ($user.PasswordNeverExpires -eq $false -and $user.PasswordLastSet) {
                            $passwordAge = (Get-Date) - $user.PasswordLastSet
                            if ($passwordAge.Days -lt 90) {
                                $isRegularUser = $true
                                $reasons += "regular password changes"
                            }
                        }
                        
                        if ($isRegularUser) {
                            $findings += @{
                                ObjectName = "$($user.SamAccountName) in $($group.Name)"
                                ObjectType = "User"
                                RiskLevel = $group.RiskLevel
                                Description = "User account '$($user.SamAccountName)' is a member of $($group.Name) group. Account appears to be a regular user account ($($reasons -join ', '))"
                                Remediation = "Remove regular user accounts from $($group.Name) group. Create dedicated service accounts for backup operations with principle of least privilege. Use Managed Service Accounts (MSA) or Group Managed Service Accounts (gMSA) where possible"
                                AffectedAttributes = @("memberOf", "objectClass")
                            }
                            $affectedCount++
                            $score -= if ($group.RiskLevel -eq 'Medium') { 15 } else { 10 }
                        } elseif ($user.Enabled -eq $true) {
                            # Still check if service account follows best practices
                            if ($user.PasswordNeverExpires -eq $false) {
                                $findings += @{
                                    ObjectName = "$($user.SamAccountName) in $($group.Name)"
                                    ObjectType = "User"
                                    RiskLevel = "Low"
                                    Description = "Service account '$($user.SamAccountName)' in $($group.Name) does not have 'Password Never Expires' set"
                                    Remediation = "Configure service accounts with 'Password Never Expires' or migrate to Managed Service Accounts (MSA)"
                                    AffectedAttributes = @("PasswordNeverExpires")
                                }
                                $score -= 3
                            }
                        }
                    } elseif ($member.objectClass -eq 'computer') {
                        # Computer accounts in Backup Operators is unusual
                        $findings += @{
                            ObjectName = "$($member.Name) in $($group.Name)"
                            ObjectType = "Computer"
                            RiskLevel = "Low"
                            Description = "Computer account '$($member.Name)' is a member of $($group.Name) group"
                            Remediation = "Review why computer account needs backup privileges. Consider using dedicated service accounts instead"
                            AffectedAttributes = @("memberOf")
                        }
                        $affectedCount++
                        $score -= 5
                    }
                }
                
                # Check if group is empty (best practice for unused privileged groups)
                if ($group.Name -eq 'Backup Operators' -and $members.Count -eq 0) {
                    Write-Verbose "Backup Operators group is empty (good practice if not needed)"
                }
            }
            
        } catch {
            $ignoredCount++
            Write-Warning "Could not check $($group.Name) group membership: $_"
        }
    }
    
    # Additional check: Look for users with backup privileges via other means
    try {
        # Check for users with SeBackupPrivilege via GPO (would need to parse GPOs)
        $usersWithBackupRights = Get-ADUser -Filter * -Server $DomainName -Properties * -ErrorAction SilentlyContinue |
            Where-Object { $_.Description -match 'backup' -or $_.Title -match 'backup' } |
            Select-Object -First 10
        
        foreach ($user in $usersWithBackupRights) {
            if ($user.Enabled -eq $true) {
                $findings += @{
                    ObjectName = $user.SamAccountName
                    ObjectType = "User"
                    RiskLevel = "Low"
                    Description = "User '$($user.SamAccountName)' has 'backup' in description/title, may have backup privileges outside of standard groups"
                    Remediation = "Review user privileges and ensure backup rights are granted through proper group membership with auditing"
                    AffectedAttributes = @("Description", "Title")
                }
                $score -= 2
            }
        }
    } catch {
        Write-Verbose "Could not check for users with backup privileges in descriptions"
    }
    
    # Ensure score doesn't go below 0
    $score = [Math]::Max(0, $score)
    
    # Determine overall status
    $status = if ($findings.Count -eq 0) { "Success" } 
              elseif ($score -lt 50) { "Failed" } 
              else { "Warning" }
    
    $message = if ($findings.Count -eq 0) {
        "Backup Operators and related privileged groups contain only appropriate service accounts"
    } else {
        "Found $($findings.Count) issues with privileged group membership affecting $affectedCount accounts"
    }
    
    $executionTime = (Get-Date) - $startTime
    
    return @{
        CheckId = "AD-T4-004"
        Timestamp = (Get-Date).ToString("o")
        Status = $status
        Score = $score
        Severity = "Low"
        Category = "PrivilegedAccess"
        Findings = $findings
        Message = $message
        AffectedObjects = $affectedCount
        IgnoredObjects = $ignoredCount
        Metadata = @{
            Domain = $DomainName
            ExecutionTime = $executionTime.TotalSeconds
            GroupsChecked = $privilegedGroups.Count
        }
    }
    
} catch {
    return @{
        CheckId = "AD-T4-004"
        Timestamp = (Get-Date).ToString("o")
        Status = "Error"
        Score = 0
        Severity = "Low"
        Category = "PrivilegedAccess"
        Findings = @()
        Message = "Error checking Backup Operators group membership: $_"
        AffectedObjects = 0
        IgnoredObjects = 0
        Metadata = @{
            Domain = $DomainName
            ExecutionTime = ((Get-Date) - $startTime).TotalSeconds
            Error = $_.Exception.Message
        }
    }
}