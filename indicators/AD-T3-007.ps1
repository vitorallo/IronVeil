<#
.SYNOPSIS
Checks the ms-DS-MachineAccountQuota attribute which allows regular users to add computer accounts

.METADATA
{
  "id": "AD-T3-007",
  "name": "Machine Account Quota Greater Than Zero",
  "description": "The ms-DS-MachineAccountQuota attribute allows regular users to add computer accounts to the domain, which can be abused",
  "category": "DomainConfiguration",
  "severity": "Medium",
  "weight": 5,
  "impact": 5,
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
    
    # Get domain object
    $domain = Get-ADDomain -Server $DomainName -ErrorAction Stop
    $domainDN = $domain.DistinguishedName
    
    # Get the ms-DS-MachineAccountQuota value
    $domainObject = Get-ADObject -Identity $domainDN -Properties "ms-DS-MachineAccountQuota" -Server $DomainName -ErrorAction Stop
    
    $machineAccountQuota = $domainObject."ms-DS-MachineAccountQuota"
    
    # Default value is 10 if not set
    if ($null -eq $machineAccountQuota) {
        $machineAccountQuota = 10
        $isDefault = $true
    } else {
        $isDefault = $false
    }
    
    if ($machineAccountQuota -gt 0) {
        $riskLevel = if ($machineAccountQuota -ge 10) { "High" } 
                     elseif ($machineAccountQuota -ge 5) { "Medium" }
                     else { "Low" }
        
        $findings += @{
            ObjectName = $domain.DNSRoot
            ObjectType = "Domain"
            RiskLevel = $riskLevel
            Description = "Machine Account Quota is set to $machineAccountQuota$(if ($isDefault) { ' (default value)' } else { '' }). Any authenticated user can add up to $machineAccountQuota computer accounts to the domain"
            Remediation = "Set ms-DS-MachineAccountQuota to 0 to prevent regular users from adding computer accounts. Use 'Set-ADDomain -Identity $DomainName -Replace @{`"ms-DS-MachineAccountQuota`"=0}'"
            AffectedAttributes = @("ms-DS-MachineAccountQuota")
        }
        $affectedCount++
        
        # Calculate score impact based on quota value
        if ($machineAccountQuota -ge 10) {
            $score -= 30
        } elseif ($machineAccountQuota -ge 5) {
            $score -= 20
        } else {
            $score -= 10
        }
        
        # Check for existing computer accounts created by non-privileged users
        try {
            # Look for computer accounts where the creator is not a privileged account
            $computers = Get-ADComputer -Filter * -Properties mS-DS-CreatorSID, whenCreated -Server $DomainName -ErrorAction Stop
            
            $suspiciousComputers = @()
            $privilegedSIDs = @(
                "$($domain.DomainSID)-500", # Administrator
                "$($domain.DomainSID)-512", # Domain Admins
                "$($domain.DomainSID)-519", # Enterprise Admins
                "$($domain.DomainSID)-518", # Schema Admins
                "S-1-5-18", # SYSTEM
                "S-1-5-20"  # Network Service
            )
            
            foreach ($computer in $computers) {
                if ($computer."mS-DS-CreatorSID") {
                    $creatorSID = $computer."mS-DS-CreatorSID"
                    
                    # Check if creator is not privileged
                    $isPrivilegedCreator = $false
                    foreach ($privSID in $privilegedSIDs) {
                        if ($creatorSID -eq $privSID) {
                            $isPrivilegedCreator = $true
                            break
                        }
                    }
                    
                    if (-not $isPrivilegedCreator) {
                        try {
                            $creator = Get-ADObject -Identity $creatorSID -Server $DomainName -ErrorAction Stop
                            $creatorName = $creator.Name
                            
                            # Check if it's a regular user
                            if ($creator.ObjectClass -eq "user") {
                                $creatorUser = Get-ADUser -Identity $creatorSID -Properties memberOf -Server $DomainName
                                
                                # Check if user is in any admin groups
                                $isAdmin = $false
                                foreach ($group in $creatorUser.memberOf) {
                                    $groupName = ($group -split ",")[0] -replace "CN=", ""
                                    if ($groupName -in @("Domain Admins", "Enterprise Admins", "Administrators")) {
                                        $isAdmin = $true
                                        break
                                    }
                                }
                                
                                if (-not $isAdmin) {
                                    $suspiciousComputers += @{
                                        ComputerName = $computer.Name
                                        Creator = $creatorName
                                        CreatedDate = $computer.whenCreated
                                    }
                                }
                            }
                        } catch {
                            # Could not resolve creator
                            $suspiciousComputers += @{
                                ComputerName = $computer.Name
                                Creator = "Unknown (SID: $creatorSID)"
                                CreatedDate = $computer.whenCreated
                            }
                        }
                    }
                }
            }
            
            if ($suspiciousComputers.Count -gt 0) {
                # Group by creator
                $creatorGroups = $suspiciousComputers | Group-Object -Property Creator
                
                foreach ($group in $creatorGroups) {
                    $computerList = ($group.Group | ForEach-Object { $_.ComputerName }) -join ", "
                    
                    $findings += @{
                        ObjectName = $group.Name
                        ObjectType = "User"
                        RiskLevel = "Medium"
                        Description = "User '$($group.Name)' has created $($group.Count) computer account(s): $computerList"
                        Remediation = "Review these computer accounts and remove if unnecessary. Consider implementing a formal process for computer account creation"
                        AffectedAttributes = @("mS-DS-CreatorSID")
                    }
                    $affectedCount++
                    $score -= [Math]::Min(5 * $group.Count, 20)
                }
            }
            
        } catch {
            $ignoredCount++
            Write-Warning "Could not check computer account creators: $_"
        }
    }
    
    # Check if delegation exists for computer account creation
    try {
        # Look for delegated permissions to create computer objects
        $computersContainer = Get-ADObject -Identity "CN=Computers,$domainDN" -Properties nTSecurityDescriptor -Server $DomainName
        $acl = $computersContainer.nTSecurityDescriptor
        
        $delegatedUsers = @()
        foreach ($ace in $acl.Access) {
            if ($ace.ObjectType -eq "bf967a86-0de6-11d0-a285-00aa003049e2" -and # Computer object class
                $ace.ActiveDirectoryRights -match "CreateChild" -and
                $ace.AccessControlType -eq "Allow") {
                
                try {
                    $identity = Get-ADObject -Identity $ace.IdentityReference.Value -Server $DomainName -ErrorAction Stop
                    
                    if ($identity.ObjectClass -eq "user" -or $identity.ObjectClass -eq "group") {
                        if ($identity.Name -notin @("Domain Admins", "Enterprise Admins", "Administrators", "SYSTEM")) {
                            $delegatedUsers += $identity.Name
                        }
                    }
                } catch {
                    # Could not resolve identity
                }
            }
        }
        
        if ($delegatedUsers.Count -gt 0) {
            $findings += @{
                ObjectName = "Computers Container"
                ObjectType = "Container"
                RiskLevel = "Medium"
                Description = "Additional users/groups have delegated rights to create computer objects: $($delegatedUsers -join ', ')"
                Remediation = "Review and remove unnecessary delegated permissions for computer account creation"
                AffectedAttributes = @("nTSecurityDescriptor")
            }
            $affectedCount++
            $score -= 10
        }
        
    } catch {
        $ignoredCount++
        Write-Warning "Could not check delegated permissions: $_"
    }
    
    # Ensure score doesn't go below 0
    $score = [Math]::Max(0, $score)
    
    # Determine overall status
    $status = if ($findings.Count -eq 0) { "Success" } 
              elseif ($score -lt 50) { "Failed" } 
              else { "Warning" }
    
    $message = if ($findings.Count -eq 0) {
        "Machine Account Quota is properly configured (set to 0)"
    } else {
        "Machine Account Quota allows unprivileged users to create computer accounts"
    }
    
    $executionTime = (Get-Date) - $startTime
    
    return @{
        CheckId = "AD-T3-007"
        Timestamp = (Get-Date).ToString("o")
        Status = $status
        Score = $score
        Severity = "Medium"
        Category = "DomainConfiguration"
        Findings = $findings
        Message = $message
        AffectedObjects = $affectedCount
        IgnoredObjects = $ignoredCount
        Metadata = @{
            Domain = $DomainName
            ExecutionTime = $executionTime.TotalSeconds
            MachineAccountQuota = $machineAccountQuota
            IsDefaultValue = $isDefault
        }
    }
    
} catch {
    return @{
        CheckId = "AD-T3-007"
        Timestamp = (Get-Date).ToString("o")
        Status = "Error"
        Score = 0
        Severity = "Medium"
        Category = "DomainConfiguration"
        Findings = @()
        Message = "Error checking Machine Account Quota: $_"
        AffectedObjects = 0
        IgnoredObjects = 0
        Metadata = @{
            Domain = $DomainName
            ExecutionTime = ((Get-Date) - $startTime).TotalSeconds
            Error = $_.Exception.Message
        }
    }
}