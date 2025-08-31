<#
.SYNOPSIS
Checks membership of built-in operator groups that have significant privileges

.METADATA
{
  "id": "AD-T3-005",
  "name": "Built-in Operator Groups Not Empty",
  "description": "Built-in operator groups have significant privileges and should be empty or contain only necessary accounts",
  "category": "PrivilegedAccess",
  "severity": "Medium",
  "weight": 5,
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
    
    # Define operator groups to check with their associated risks
    $operatorGroups = @(
        @{
            Name = "Account Operators"
            Risk = "Can create and manage user accounts and groups, potential for privilege escalation"
            RiskLevel = "High"
            ScoreImpact = 15
        },
        @{
            Name = "Server Operators"
            Risk = "Can log on to domain controllers locally, shut down the system, and perform backup/restore"
            RiskLevel = "High"
            ScoreImpact = 15
        },
        @{
            Name = "Print Operators"
            Risk = "Can manage printers and load printer drivers on domain controllers (driver exploits)"
            RiskLevel = "Medium"
            ScoreImpact = 10
        },
        @{
            Name = "Backup Operators"
            Risk = "Can backup and restore files, potentially access sensitive data and SAM database"
            RiskLevel = "High"
            ScoreImpact = 15
        },
        @{
            Name = "Replicator"
            Risk = "Used for file replication in a domain, should only contain service accounts if needed"
            RiskLevel = "Medium"
            ScoreImpact = 8
        },
        @{
            Name = "Pre-Windows 2000 Compatible Access"
            Risk = "Allows anonymous access to Active Directory, major security risk"
            RiskLevel = "High"
            ScoreImpact = 20
        },
        @{
            Name = "Remote Desktop Users"
            Risk = "Can log on via Remote Desktop to domain controllers if not properly restricted"
            RiskLevel = "Medium"
            ScoreImpact = 10
        },
        @{
            Name = "Network Configuration Operators"
            Risk = "Can configure network settings on domain controllers"
            RiskLevel = "Medium"
            ScoreImpact = 8
        },
        @{
            Name = "Incoming Forest Trust Builders"
            Risk = "Can create incoming forest trusts, potential for cross-forest attacks"
            RiskLevel = "High"
            ScoreImpact = 15
        }
    )
    
    foreach ($operatorGroup in $operatorGroups) {
        try {
            # Get the group
            $group = Get-ADGroup -Identity $operatorGroup.Name -Server $DomainName -ErrorAction Stop
            
            # Get group members
            $members = Get-ADGroupMember -Identity $group -Server $DomainName -ErrorAction Stop
            
            if ($members.Count -gt 0) {
                # Check each member
                $memberDetails = @()
                $hasPrivilegedMembers = $false
                
                foreach ($member in $members) {
                    $memberInfo = ""
                    
                    if ($member.objectClass -eq "user") {
                        try {
                            $user = Get-ADUser -Identity $member.DistinguishedName -Properties Enabled, LastLogonTimestamp, whenCreated -Server $DomainName
                            
                            $lastLogon = if ($user.LastLogonTimestamp) {
                                [DateTime]::FromFileTime($user.LastLogonTimestamp)
                            } else {
                                $null
                            }
                            
                            $memberInfo = "$($member.Name) (User - Enabled: $($user.Enabled)"
                            
                            if ($lastLogon) {
                                $daysSinceLogon = ((Get-Date) - $lastLogon).Days
                                $memberInfo += ", Last logon: $daysSinceLogon days ago"
                            } else {
                                $memberInfo += ", Never logged in"
                            }
                            
                            $memberInfo += ")"
                            
                            # Check if user is also in other privileged groups
                            $userGroups = Get-ADPrincipalGroupMembership -Identity $member.DistinguishedName -Server $DomainName
                            $privilegedGroups = $userGroups | Where-Object { 
                                $_.Name -in @("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators")
                            }
                            
                            if ($privilegedGroups) {
                                $hasPrivilegedMembers = $true
                                $memberInfo += " [ALSO IN: $($privilegedGroups.Name -join ', ')]"
                            }
                            
                        } catch {
                            $memberInfo = "$($member.Name) (User)"
                        }
                    } elseif ($member.objectClass -eq "group") {
                        $memberInfo = "$($member.Name) (Nested Group)"
                        
                        # Check nested group members count
                        try {
                            $nestedMembers = Get-ADGroupMember -Identity $member.DistinguishedName -Recursive -Server $DomainName
                            $memberInfo += " with $($nestedMembers.Count) total members"
                        } catch {
                            # Ignore nested group enumeration errors
                        }
                    } elseif ($member.objectClass -eq "computer") {
                        $memberInfo = "$($member.Name) (Computer)"
                    } else {
                        $memberInfo = "$($member.Name) ($($member.objectClass))"
                    }
                    
                    $memberDetails += $memberInfo
                }
                
                # Adjust risk level if privileged members are found
                $effectiveRiskLevel = if ($hasPrivilegedMembers -and $operatorGroup.RiskLevel -ne "High") {
                    "High"
                } else {
                    $operatorGroup.RiskLevel
                }
                
                $findings += @{
                    ObjectName = $operatorGroup.Name
                    ObjectType = "Group"
                    RiskLevel = $effectiveRiskLevel
                    Description = "$($operatorGroup.Name) has $($members.Count) member(s): $($memberDetails -join '; '). $($operatorGroup.Risk)"
                    Remediation = "Remove unnecessary members from $($operatorGroup.Name). Use dedicated service accounts with minimal privileges instead."
                    AffectedAttributes = @("member")
                }
                $affectedCount++
                
                # Apply score impact
                $scoreReduction = if ($hasPrivilegedMembers) {
                    $operatorGroup.ScoreImpact * 1.5
                } else {
                    $operatorGroup.ScoreImpact
                }
                $score -= [Math]::Min($scoreReduction, 100)
            }
            
        } catch {
            if ($_.Exception.Message -notlike "*Cannot find an object with identity*") {
                $ignoredCount++
                Write-Warning "Could not check group '$($operatorGroup.Name)': $_"
            }
            # Group doesn't exist in this domain, which is fine
        }
    }
    
    # Check for custom groups with operator-like permissions
    try {
        # Look for groups with AdminCount=1 that aren't well-known admin groups
        $customPrivilegedGroups = Get-ADGroup -Filter {AdminCount -eq 1} -Properties AdminCount, member -Server $DomainName |
            Where-Object { 
                $_.Name -notin @("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators", 
                                "Domain Controllers", "Read-only Domain Controllers", "Group Policy Creator Owners",
                                "Cert Publishers", "DnsAdmins", "DnsUpdateProxy")
            }
        
        foreach ($group in $customPrivilegedGroups) {
            $members = Get-ADGroupMember -Identity $group -Server $DomainName -ErrorAction SilentlyContinue
            
            if ($members.Count -gt 0) {
                $findings += @{
                    ObjectName = $group.Name
                    ObjectType = "Group"
                    RiskLevel = "Medium"
                    Description = "Custom privileged group (AdminCount=1) with $($members.Count) member(s)"
                    Remediation = "Review membership and necessity of this custom privileged group"
                    AffectedAttributes = @("AdminCount", "member")
                }
                $affectedCount++
                $score -= 5
            }
        }
    } catch {
        $ignoredCount++
        Write-Warning "Could not check custom privileged groups: $_"
    }
    
    # Ensure score doesn't go below 0
    $score = [Math]::Max(0, $score)
    
    # Determine overall status
    $status = if ($findings.Count -eq 0) { "Success" } 
              elseif ($score -lt 50) { "Failed" } 
              else { "Warning" }
    
    $message = if ($findings.Count -eq 0) {
        "All built-in operator groups are empty or properly managed"
    } else {
        "Found $($findings.Count) operator groups with unnecessary or risky memberships"
    }
    
    $executionTime = (Get-Date) - $startTime
    
    return @{
        CheckId = "AD-T3-005"
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
            GroupsChecked = $operatorGroups.Count
        }
    }
    
} catch {
    return @{
        CheckId = "AD-T3-005"
        Timestamp = (Get-Date).ToString("o")
        Status = "Error"
        Score = 0
        Severity = "Medium"
        Category = "PrivilegedAccess"
        Findings = @()
        Message = "Error checking operator group memberships: $_"
        AffectedObjects = 0
        IgnoredObjects = 0
        Metadata = @{
            Domain = $DomainName
            ExecutionTime = ((Get-Date) - $startTime).TotalSeconds
            Error = $_.Exception.Message
        }
    }
}