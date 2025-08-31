<#
.SYNOPSIS
Checks if the default Domain Administrator account has been renamed from its well-known name

.METADATA
{
  "id": "AD-T4-001",
  "name": "Default Domain Administrator Account Not Renamed",
  "description": "The default 'Administrator' account in Active Directory has not been renamed from its well-known name, making it a prime target for attackers",
  "category": "AccountSecurity",
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
    $domainSID = $domain.DomainSID
    
    # RID 500 is the well-known RID for the built-in Administrator account
    $adminSID = "$domainSID-500"
    
    try {
        # Get the Administrator account using the well-known SID
        $adminAccount = Get-ADUser -Identity $adminSID -Server $DomainName -Properties * -ErrorAction Stop
        
        # Check if the account name is still "Administrator"
        if ($adminAccount.SamAccountName -eq "Administrator") {
            $findings += @{
                ObjectName = $adminAccount.SamAccountName
                ObjectType = "User"
                RiskLevel = "Low"
                Description = "Default Domain Administrator account (RID 500) has not been renamed from its well-known name 'Administrator'"
                Remediation = "Rename the built-in Administrator account to a non-obvious name to reduce targeted attacks. Use Group Policy to rename: Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > 'Accounts: Rename administrator account'"
                AffectedAttributes = @("SamAccountName", "Name")
            }
            $affectedCount++
            $score -= 25
            
            # Additional check for account status
            if ($adminAccount.Enabled -eq $true) {
                $findings += @{
                    ObjectName = $adminAccount.SamAccountName
                    ObjectType = "User"
                    RiskLevel = "Low"
                    Description = "Default Administrator account is both enabled and using the default name, increasing attack surface"
                    Remediation = "Consider creating a separate administrative account and disabling the built-in Administrator after renaming"
                    AffectedAttributes = @("Enabled", "SamAccountName")
                }
                $score -= 10
            }
        } else {
            # Account has been renamed - good practice
            Write-Verbose "Administrator account has been renamed to: $($adminAccount.SamAccountName)"
        }
        
        # Check if the account has been used recently (additional security check)
        if ($adminAccount.LastLogonDate) {
            $daysSinceLastLogon = (Get-Date) - $adminAccount.LastLogonDate
            if ($daysSinceLastLogon.Days -lt 30 -and $adminAccount.SamAccountName -eq "Administrator") {
                $findings += @{
                    ObjectName = $adminAccount.SamAccountName
                    ObjectType = "User"
                    RiskLevel = "Medium"
                    Description = "Default Administrator account with unchanged name has been used within the last 30 days"
                    Remediation = "The default Administrator account is actively being used. Create dedicated admin accounts for administrative tasks and rename this account"
                    AffectedAttributes = @("LastLogonDate", "SamAccountName")
                }
                $affectedCount++
                $score -= 15
            }
        }
        
    } catch {
        $ignoredCount++
        Write-Warning "Could not retrieve Administrator account with SID $adminSID: $_"
    }
    
    # Check for other domains in the forest
    try {
        $forest = Get-ADForest -Server $DomainName
        $otherDomains = $forest.Domains | Where-Object { $_ -ne $DomainName }
        
        foreach ($otherDomain in $otherDomains) {
            try {
                $otherDomainObj = Get-ADDomain -Server $otherDomain
                $otherDomainSID = $otherDomainObj.DomainSID
                $otherAdminSID = "$otherDomainSID-500"
                
                $otherAdmin = Get-ADUser -Identity $otherAdminSID -Server $otherDomain -Properties SamAccountName
                
                if ($otherAdmin.SamAccountName -eq "Administrator") {
                    $findings += @{
                        ObjectName = "$otherDomain\$($otherAdmin.SamAccountName)"
                        ObjectType = "User"
                        RiskLevel = "Low"
                        Description = "Administrator account in domain '$otherDomain' also uses default name"
                        Remediation = "Apply consistent administrator account renaming policy across all domains in the forest"
                        AffectedAttributes = @("SamAccountName")
                    }
                    $affectedCount++
                    $score -= 5
                }
            } catch {
                $ignoredCount++
                Write-Verbose "Could not check Administrator account in domain $otherDomain"
            }
        }
    } catch {
        Write-Verbose "Could not enumerate forest domains: $_"
    }
    
    # Ensure score doesn't go below 0
    $score = [Math]::Max(0, $score)
    
    # Determine overall status
    $status = if ($findings.Count -eq 0) { "Success" } 
              elseif ($score -lt 50) { "Failed" } 
              else { "Warning" }
    
    $message = if ($findings.Count -eq 0) {
        "Administrator account has been properly renamed from its default name"
    } else {
        "Found $($findings.Count) security issues related to default Administrator account naming"
    }
    
    $executionTime = (Get-Date) - $startTime
    
    return @{
        CheckId = "AD-T4-001"
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
            ForestRoot = $domain.Forest
        }
    }
    
} catch {
    return @{
        CheckId = "AD-T4-001"
        Timestamp = (Get-Date).ToString("o")
        Status = "Error"
        Score = 0
        Severity = "Low"
        Category = "AccountSecurity"
        Findings = @()
        Message = "Error checking Administrator account naming: $_"
        AffectedObjects = 0
        IgnoredObjects = 0
        Metadata = @{
            Domain = $DomainName
            ExecutionTime = ((Get-Date) - $startTime).TotalSeconds
            Error = $_.Exception.Message
        }
    }
}