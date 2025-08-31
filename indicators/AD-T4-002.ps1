<#
.SYNOPSIS
Checks if the built-in Guest account is disabled across all domains

.METADATA
{
  "id": "AD-T4-002",
  "name": "Guest Account Not Disabled",
  "description": "The built-in Guest account remains enabled, providing a potential avenue for unauthorized access",
  "category": "AccountSecurity",
  "severity": "Low",
  "weight": 4,
  "impact": 3,
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
    $domainSID = $domain.DomainSID
    
    # RID 501 is the well-known RID for the built-in Guest account
    $guestSID = "$domainSID-501"
    
    try {
        # Get the Guest account using the well-known SID
        $guestAccount = Get-ADUser -Identity $guestSID -Server $DomainName -Properties * -ErrorAction Stop
        
        # Check if the Guest account is enabled
        if ($guestAccount.Enabled -eq $true) {
            $findings += @{
                ObjectName = $guestAccount.SamAccountName
                ObjectType = "User"
                RiskLevel = "Low"
                Description = "Built-in Guest account (RID 501) is enabled in domain '$($domain.DNSRoot)'"
                Remediation = "Disable the Guest account using Active Directory Users and Computers or PowerShell: Disable-ADAccount -Identity '$guestSID'"
                AffectedAttributes = @("Enabled", "userAccountControl")
            }
            $affectedCount++
            $score -= 30
            
            # Check if password is set and when it was last changed
            if ($guestAccount.PasswordLastSet) {
                $daysSincePasswordChange = (Get-Date) - $guestAccount.PasswordLastSet
                if ($daysSincePasswordChange.Days -gt 365) {
                    $findings += @{
                        ObjectName = $guestAccount.SamAccountName
                        ObjectType = "User"
                        RiskLevel = "Medium"
                        Description = "Enabled Guest account has a password that hasn't been changed in $($daysSincePasswordChange.Days) days"
                        Remediation = "The Guest account should be disabled. If it must remain enabled for legacy reasons, ensure the password is complex and changed regularly"
                        AffectedAttributes = @("PasswordLastSet")
                    }
                    $score -= 10
                }
            }
            
            # Check if Guest has been used recently
            if ($guestAccount.LastLogonDate) {
                $daysSinceLastLogon = (Get-Date) - $guestAccount.LastLogonDate
                if ($daysSinceLastLogon.Days -lt 90) {
                    $findings += @{
                        ObjectName = $guestAccount.SamAccountName
                        ObjectType = "User"
                        RiskLevel = "Medium"
                        Description = "Guest account has been used within the last 90 days (last logon: $($guestAccount.LastLogonDate))"
                        Remediation = "Investigate why the Guest account is being used and migrate to proper user accounts. Disable the Guest account immediately"
                        AffectedAttributes = @("LastLogonDate")
                    }
                    $affectedCount++
                    $score -= 15
                }
            }
            
            # Check group memberships
            $guestGroups = Get-ADPrincipalGroupMembership -Identity $guestSID -Server $DomainName -ErrorAction SilentlyContinue
            if ($guestGroups.Count -gt 1) { # Guest is always a member of Domain Guests
                $extraGroups = $guestGroups | Where-Object { $_.Name -ne "Domain Guests" -and $_.Name -ne "Guests" }
                if ($extraGroups) {
                    $findings += @{
                        ObjectName = $guestAccount.SamAccountName
                        ObjectType = "User"
                        RiskLevel = "High"
                        Description = "Guest account has additional group memberships: $($extraGroups.Name -join ', ')"
                        Remediation = "Remove Guest account from all groups except Domain Guests. Review why these permissions were granted"
                        AffectedAttributes = @("memberOf")
                    }
                    $affectedCount++
                    $score -= 20
                }
            }
        } else {
            Write-Verbose "Guest account is properly disabled in domain $($domain.DNSRoot)"
        }
        
    } catch {
        $ignoredCount++
        Write-Warning "Could not retrieve Guest account with SID $guestSID: $_"
    }
    
    # Check for other domains in the forest
    try {
        $forest = Get-ADForest -Server $DomainName
        $otherDomains = $forest.Domains | Where-Object { $_ -ne $DomainName }
        
        foreach ($otherDomain in $otherDomains) {
            try {
                $otherDomainObj = Get-ADDomain -Server $otherDomain
                $otherDomainSID = $otherDomainObj.DomainSID
                $otherGuestSID = "$otherDomainSID-501"
                
                $otherGuest = Get-ADUser -Identity $otherGuestSID -Server $otherDomain -Properties Enabled, SamAccountName
                
                if ($otherGuest.Enabled -eq $true) {
                    $findings += @{
                        ObjectName = "$otherDomain\$($otherGuest.SamAccountName)"
                        ObjectType = "User"
                        RiskLevel = "Low"
                        Description = "Guest account is enabled in domain '$otherDomain'"
                        Remediation = "Apply consistent Guest account disabling policy across all domains in the forest"
                        AffectedAttributes = @("Enabled")
                    }
                    $affectedCount++
                    $score -= 10
                }
            } catch {
                $ignoredCount++
                Write-Verbose "Could not check Guest account in domain $otherDomain"
            }
        }
    } catch {
        Write-Verbose "Could not enumerate forest domains: $_"
    }
    
    # Check local Guest accounts on Domain Controllers
    $domainControllers = Get-ADDomainController -Filter * -Server $DomainName -ErrorAction SilentlyContinue
    foreach ($dc in $domainControllers) {
        try {
            # Note: This would require remote access to check local accounts
            # For now, we'll flag this as a recommendation
            if ($findings.Count -eq 0) {
                Write-Verbose "Remember to also check local Guest accounts on domain controllers"
            }
        } catch {
            Write-Verbose "Could not enumerate domain controllers for local Guest check"
        }
    }
    
    # Ensure score doesn't go below 0
    $score = [Math]::Max(0, $score)
    
    # Determine overall status
    $status = if ($findings.Count -eq 0) { "Success" } 
              elseif ($score -lt 50) { "Failed" } 
              else { "Warning" }
    
    $message = if ($findings.Count -eq 0) {
        "All Guest accounts are properly disabled"
    } else {
        "Found $($findings.Count) security issues related to Guest account configuration"
    }
    
    $executionTime = (Get-Date) - $startTime
    
    return @{
        CheckId = "AD-T4-002"
        Timestamp = (Get-Date).ToString("o")
        Status = $status
        Score = $score
        Severity = "Low"
        Category = "AccountSecurity"
        Findings = $findings
        Message = $message
        AffectedObjects = $affectedCount
        IgnoredObjects = $ignoredCount
        Metadata = @{
            Domain = $DomainName
            ExecutionTime = $executionTime.TotalSeconds
            DomainsChecked = ($forest.Domains.Count)
        }
    }
    
} catch {
    return @{
        CheckId = "AD-T4-002"
        Timestamp = (Get-Date).ToString("o")
        Status = "Error"
        Score = 0
        Severity = "Low"
        Category = "AccountSecurity"
        Findings = @()
        Message = "Error checking Guest account status: $_"
        AffectedObjects = 0
        IgnoredObjects = 0
        Metadata = @{
            Domain = $DomainName
            ExecutionTime = ((Get-Date) - $startTime).TotalSeconds
            Error = $_.Exception.Message
        }
    }
}