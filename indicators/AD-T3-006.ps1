<#
.SYNOPSIS
Identifies privileged AD objects owned by unprivileged accounts

.METADATA
{
  "id": "AD-T3-006",
  "name": "Privileged Objects with Unprivileged Owners",
  "description": "Sensitive AD objects owned by unprivileged accounts can be modified by those accounts",
  "category": "Authorization",
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
    
    # Get domain information
    $domain = Get-ADDomain -Server $DomainName
    $domainSID = $domain.DomainSID
    
    # Define privileged groups to check
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
        "Group Policy Creator Owners"
    )
    
    # Define expected privileged owners (SIDs that are acceptable as owners)
    $expectedOwnerSIDs = @(
        "S-1-5-32-544",  # Administrators
        "$domainSID-512", # Domain Admins
        "$domainSID-519", # Enterprise Admins
        "$domainSID-518", # Schema Admins
        "S-1-5-18"       # SYSTEM
    )
    
    # Check privileged group objects
    foreach ($groupName in $privilegedGroups) {
        try {
            $group = Get-ADGroup -Identity $groupName -Properties nTSecurityDescriptor -Server $DomainName -ErrorAction Stop
            $owner = $group.nTSecurityDescriptor.Owner
            
            if ($owner) {
                $ownerSID = $owner.Value
                
                # Check if owner is not in expected privileged list
                if ($ownerSID -notin $expectedOwnerSIDs) {
                    try {
                        $ownerObject = Get-ADObject -Identity $ownerSID -Server $DomainName
                        $ownerName = $ownerObject.Name
                        
                        # Check if owner is a regular user
                        if ($ownerObject.ObjectClass -eq "user") {
                            $ownerUser = Get-ADUser -Identity $ownerSID -Properties memberOf -Server $DomainName
                            $isPrivileged = $false
                            
                            foreach ($memberOf in $ownerUser.memberOf) {
                                $memberGroupName = ($memberOf -split ",")[0] -replace "CN=", ""
                                if ($memberGroupName -in $privilegedGroups) {
                                    $isPrivileged = $true
                                    break
                                }
                            }
                            
                            if (-not $isPrivileged) {
                                $findings += @{
                                    ObjectName = $groupName
                                    ObjectType = "Group"
                                    RiskLevel = "High"
                                    Description = "Privileged group '$groupName' is owned by unprivileged user '$ownerName'"
                                    Remediation = "Change owner to Domain Admins or Administrators group using Active Directory Users and Computers"
                                    AffectedAttributes = @("nTSecurityDescriptor.Owner")
                                }
                                $affectedCount++
                                $score -= 15
                            }
                        }
                    } catch {
                        # Could not resolve owner
                        $findings += @{
                            ObjectName = $groupName
                            ObjectType = "Group"
                            RiskLevel = "Medium"
                            Description = "Privileged group '$groupName' has unknown owner (SID: $ownerSID)"
                            Remediation = "Verify and correct object ownership"
                            AffectedAttributes = @("nTSecurityDescriptor.Owner")
                        }
                        $affectedCount++
                        $score -= 10
                    }
                }
            }
        } catch {
            if ($_.Exception.Message -notlike "*Cannot find an object with identity*") {
                $ignoredCount++
                Write-Warning "Could not check group '$groupName': $_"
            }
        }
    }
    
    # Check Organizational Units
    try {
        $ous = Get-ADOrganizationalUnit -Filter * -Properties nTSecurityDescriptor -Server $DomainName -ErrorAction Stop
        
        foreach ($ou in $ous) {
            $owner = $ou.nTSecurityDescriptor.Owner
            
            if ($owner) {
                $ownerSID = $owner.Value
                
                if ($ownerSID -notin $expectedOwnerSIDs) {
                    try {
                        $ownerObject = Get-ADObject -Identity $ownerSID -Server $DomainName
                        
                        if ($ownerObject.ObjectClass -eq "user") {
                            $ownerUser = Get-ADUser -Identity $ownerSID -Properties memberOf -Server $DomainName
                            $isPrivileged = $false
                            
                            foreach ($memberOf in $ownerUser.memberOf) {
                                $memberGroupName = ($memberOf -split ",")[0] -replace "CN=", ""
                                if ($memberGroupName -in $privilegedGroups) {
                                    $isPrivileged = $true
                                    break
                                }
                            }
                            
                            if (-not $isPrivileged) {
                                # Check if OU contains privileged objects
                                $privilegedObjectsInOU = Get-ADObject -Filter {AdminCount -eq 1} -SearchBase $ou.DistinguishedName -SearchScope Subtree -ErrorAction SilentlyContinue
                                
                                if ($privilegedObjectsInOU) {
                                    $findings += @{
                                        ObjectName = $ou.Name
                                        ObjectType = "OrganizationalUnit"
                                        RiskLevel = "High"
                                        Description = "OU containing $($privilegedObjectsInOU.Count) privileged objects is owned by unprivileged user '$($ownerObject.Name)'"
                                        Remediation = "Change OU owner to Domain Admins or delegate appropriately"
                                        AffectedAttributes = @("nTSecurityDescriptor.Owner")
                                    }
                                    $affectedCount++
                                    $score -= 12
                                } elseif ($ou.Name -in @("Domain Controllers", "Admin", "Admins", "Service Accounts", "Privileged")) {
                                    $findings += @{
                                        ObjectName = $ou.Name
                                        ObjectType = "OrganizationalUnit"
                                        RiskLevel = "Medium"
                                        Description = "Sensitive OU '$($ou.Name)' is owned by unprivileged user '$($ownerObject.Name)'"
                                        Remediation = "Change OU owner to appropriate administrative group"
                                        AffectedAttributes = @("nTSecurityDescriptor.Owner")
                                    }
                                    $affectedCount++
                                    $score -= 8
                                }
                            }
                        }
                    } catch {
                        # Could not resolve owner
                    }
                }
            }
        }
    } catch {
        $ignoredCount++
        Write-Warning "Could not check Organizational Units: $_"
    }
    
    # Check GPO objects
    try {
        $gpos = Get-GPO -All -Domain $DomainName -ErrorAction Stop
        
        foreach ($gpo in $gpos) {
            # Get GPO permissions
            $gpoPermissions = Get-GPPermission -Guid $gpo.Id -All -Domain $DomainName -ErrorAction Stop
            
            # Find owner (usually the one with "GpoEditDeleteModifySecurity" permission)
            $owner = $gpoPermissions | Where-Object { $_.Permission -eq "GpoEditDeleteModifySecurity" } | Select-Object -First 1
            
            if ($owner -and $owner.Trustee.Name) {
                $ownerName = $owner.Trustee.Name
                
                # Check if owner is unprivileged
                if ($ownerName -notin @("Domain Admins", "Enterprise Admins", "SYSTEM", "Administrators", "Group Policy Creator Owners")) {
                    try {
                        $ownerUser = Get-ADUser -Filter {Name -eq $ownerName} -Properties memberOf -Server $DomainName -ErrorAction Stop
                        
                        if ($ownerUser) {
                            $isPrivileged = $false
                            
                            foreach ($memberOf in $ownerUser.memberOf) {
                                $memberGroupName = ($memberOf -split ",")[0] -replace "CN=", ""
                                if ($memberGroupName -in $privilegedGroups) {
                                    $isPrivileged = $true
                                    break
                                }
                            }
                            
                            if (-not $isPrivileged) {
                                # Check if GPO is linked to sensitive OUs
                                $linkedOUs = (Get-GPOReport -Guid $gpo.Id -ReportType Xml -Domain $DomainName | Select-Xml -XPath "//LinksTo").Node
                                $isCriticalGPO = $false
                                
                                if ($linkedOUs) {
                                    foreach ($link in $linkedOUs) {
                                        if ($link.SOMPath -like "*Domain Controllers*" -or $link.SOMPath -eq $domain.DistinguishedName) {
                                            $isCriticalGPO = $true
                                            break
                                        }
                                    }
                                }
                                
                                $findings += @{
                                    ObjectName = $gpo.DisplayName
                                    ObjectType = "GroupPolicyObject"
                                    RiskLevel = if ($isCriticalGPO) { "High" } else { "Medium" }
                                    Description = "GPO '$($gpo.DisplayName)' can be modified by unprivileged user '$ownerName'$(if ($isCriticalGPO) { ' (linked to critical OUs)' } else { '' })"
                                    Remediation = "Change GPO permissions to restrict modification to Domain Admins only"
                                    AffectedAttributes = @("GPO Permissions")
                                }
                                $affectedCount++
                                $score -= if ($isCriticalGPO) { 15 } else { 10 }
                            }
                        }
                    } catch {
                        # Not a user, might be a group
                    }
                }
            }
        }
    } catch {
        $ignoredCount++
        Write-Warning "Could not check GPO ownership: $_"
    }
    
    # Check AdminSDHolder object
    try {
        $adminSDHolder = Get-ADObject -Identity "CN=AdminSDHolder,CN=System,$($domain.DistinguishedName)" -Properties nTSecurityDescriptor -Server $DomainName
        $owner = $adminSDHolder.nTSecurityDescriptor.Owner
        
        if ($owner) {
            $ownerSID = $owner.Value
            
            if ($ownerSID -notin $expectedOwnerSIDs) {
                $findings += @{
                    ObjectName = "AdminSDHolder"
                    ObjectType = "SystemObject"
                    RiskLevel = "Critical"
                    Description = "AdminSDHolder object has non-standard owner (SID: $ownerSID) - affects all protected accounts"
                    Remediation = "Immediately reset AdminSDHolder owner to Domain Admins"
                    AffectedAttributes = @("nTSecurityDescriptor.Owner")
                }
                $affectedCount++
                $score -= 30
            }
        }
    } catch {
        $ignoredCount++
        Write-Warning "Could not check AdminSDHolder: $_"
    }
    
    # Ensure score doesn't go below 0
    $score = [Math]::Max(0, $score)
    
    # Determine overall status
    $status = if ($findings.Count -eq 0) { "Success" } 
              elseif ($score -lt 50) { "Failed" } 
              else { "Warning" }
    
    $message = if ($findings.Count -eq 0) {
        "All privileged objects have appropriate ownership"
    } else {
        "Found $($findings.Count) privileged objects with inappropriate ownership"
    }
    
    $executionTime = (Get-Date) - $startTime
    
    return @{
        CheckId = "AD-T3-006"
        Timestamp = (Get-Date).ToString("o")
        Status = $status
        Score = $score
        Severity = "Medium"
        Category = "Authorization"
        Findings = $findings
        Message = $message
        AffectedObjects = $affectedCount
        IgnoredObjects = $ignoredCount
        Metadata = @{
            Domain = $DomainName
            ExecutionTime = $executionTime.TotalSeconds
            ObjectTypesChecked = @("Groups", "OUs", "GPOs", "AdminSDHolder")
        }
    }
    
} catch {
    return @{
        CheckId = "AD-T3-006"
        Timestamp = (Get-Date).ToString("o")
        Status = "Error"
        Score = 0
        Severity = "Medium"
        Category = "Authorization"
        Findings = @()
        Message = "Error checking privileged object ownership: $_"
        AffectedObjects = 0
        IgnoredObjects = 0
        Metadata = @{
            Domain = $DomainName
            ExecutionTime = ((Get-Date) - $startTime).TotalSeconds
            Error = $_.Exception.Message
        }
    }
}