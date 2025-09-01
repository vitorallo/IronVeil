<#
.SYNOPSIS
Detects non-privileged users or groups with permissions to link GPOs at the domain level

.METADATA
{
  "id": "AD-T2-005",
  "name": "GPO Linking Delegation at Domain Level",
  "description": "Non-privileged users or groups with permissions to link GPOs at the domain level can deploy malicious policies affecting all domain users and computers. This check identifies excessive GPO linking permissions.",
  "category": "PrivilegeEscalation",
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
    
    # Import IronVeil ADSI Helper
    . "$PSScriptRoot\IronVeil-ADSIHelper.ps1"
    
    if (-not $DomainName) {
        throw "Domain name could not be determined"
    }
    
    # Get domain information
    $domainInfo = Get-IVDomainInfo -DomainName $DomainName
    $domainDN = $domainInfo.DistinguishedName
    $domainSID = $domainInfo.DomainSID
    
    # Define the GP-Link GUID for linking GPOs
    $gpLinkGuid = "f30e3bbe-9ff0-11d1-b603-0000f80367c1"  # GP-Link extended right
    $gpOptionsGuid = "f30e3bc0-9ff0-11d1-b603-0000f80367c1"  # GP-Options extended right
    
    # Define standard groups that should have GPO linking permissions
    $allowedPrincipals = @(
        "Domain Admins",
        "Enterprise Admins",
        "Administrators",
        "SYSTEM",
        "Group Policy Creator Owners"
    )
    
    # Convert to SIDs for comparison
    $allowedSIDs = @(
        "$domainSID-512",  # Domain Admins
        "$domainSID-519",  # Enterprise Admins
        "S-1-5-32-544",    # Builtin Administrators
        "S-1-5-18",        # Local System
        "$domainSID-520"   # Group Policy Creator Owners
    )
    
    # Check permissions on the domain object itself
    $domainACL = Get-IVADObjectACL -DistinguishedName $domainDN
    
    # Also check OUs at domain root level
    $criticalOUs = @()
    try {
        # Get Domain Controllers OU
        $dcOU = Get-IVADOrganizationalUnit -Filter "(&(objectClass=organizationalUnit)(name=Domain Controllers))" -SearchBase $domainDN -SearchScope "OneLevel"
        if ($dcOU -and $dcOU.Count -gt 0) {
            $criticalOUs += @{
                Name = "Domain Controllers OU"
                DN = $dcOU[0].DistinguishedName
                Critical = $true
            }
        }
        
        # Get other top-level OUs
        $topLevelOUs = Get-IVADOrganizationalUnit -Filter "(objectClass=organizationalUnit)" -SearchBase $domainDN -SearchScope "OneLevel"
        foreach ($ou in $topLevelOUs) {
            if ($ou.Name -ne "Domain Controllers") {
                $criticalOUs += @{
                    Name = $ou.Name
                    DN = $ou.DistinguishedName
                    Critical = $false
                }
            }
        }
    }
    catch {
        # Continue without OU checks
    }
    
    # Function to check ACL for GPO linking permissions
    function Check-GPOLinkingPermissions {
        param(
            [Parameter(Mandatory=$true)]
            $ACL,
            [Parameter(Mandatory=$true)]
            [string]$ObjectName,
            [Parameter(Mandatory=$true)]
            [string]$ObjectType,
            [Parameter(Mandatory=$false)]
            [bool]$IsCritical = $false
        )
        
        $unauthorizedPrincipals = @()
        
        foreach ($ace in $ACL.Access) {
            # Skip deny permissions
            if ($ace.AccessControlType -eq "Deny") {
                continue
            }
            
            $hasGPOLinkPermission = $false
            $permissionDetails = @()
            
            # Check for GP-Link permission
            if ($ace.ObjectType -eq $gpLinkGuid -or 
                ($ace.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight -and 
                 $ace.ObjectType -eq "00000000-0000-0000-0000-000000000000")) {
                $hasGPOLinkPermission = $true
                $permissionDetails += "GP-Link"
            }
            
            # Check for GP-Options permission
            if ($ace.ObjectType -eq $gpOptionsGuid) {
                $hasGPOLinkPermission = $true
                $permissionDetails += "GP-Options"
            }
            
            # Check for WriteProperty on gPLink or gPOptions attributes
            if ($ace.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty) {
                # gPLink attribute GUID
                if ($ace.ObjectType -eq "f30e3bbe-9ff0-11d1-b603-0000f80367c1") {
                    $hasGPOLinkPermission = $true
                    $permissionDetails += "Write-gPLink"
                }
                # gPOptions attribute GUID
                if ($ace.ObjectType -eq "f30e3bc0-9ff0-11d1-b603-0000f80367c1") {
                    $hasGPOLinkPermission = $true
                    $permissionDetails += "Write-gPOptions"
                }
            }
            
            # Check for GenericAll or GenericWrite
            if ($ace.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericAll) {
                $hasGPOLinkPermission = $true
                $permissionDetails += "GenericAll"
            }
            if ($ace.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite) {
                $hasGPOLinkPermission = $true
                $permissionDetails += "GenericWrite"
            }
            
            if ($hasGPOLinkPermission) {
                $identitySID = $ace.IdentityReference.Value
                $identityName = $ace.IdentityReference.Value
                
                # Convert to SID if needed
                if ($identitySID -like "*\*") {
                    try {
                        $sidObj = New-Object System.Security.Principal.NTAccount($identitySID)
                        $identitySID = $sidObj.Translate([System.Security.Principal.SecurityIdentifier]).Value
                    }
                    catch {
                        # Keep original format
                    }
                }
                
                # Check if this is an allowed principal
                $isAllowed = $false
                foreach ($allowedSID in $allowedSIDs) {
                    if ($identitySID -eq $allowedSID -or $identitySID -like "*$allowedSID*") {
                        $isAllowed = $true
                        break
                    }
                }
                
                foreach ($allowedName in $allowedPrincipals) {
                    if ($identityName -like "*$allowedName*") {
                        $isAllowed = $true
                        break
                    }
                }
                
                if (-not $isAllowed) {
                    # Get more information about the principal
                    $principalInfo = $null
                    try {
                        if ($identitySID -match "^S-1-") {
                            # Search by SID - need to convert SID to searchable format
                            $sidBytes = (New-Object System.Security.Principal.SecurityIdentifier($identitySID)).GetBinaryForm()
                            $hexSid = ($sidBytes | ForEach-Object { "\{0:x2}" -f $_ }) -join ""
                            $principalInfo = Get-IVADObject -Filter "(objectSID=$hexSid)" -Properties @('objectClass', 'memberOf', 'whenCreated')
                        }
                        else {
                            $samName = $identityName.Split('\')[-1]
                            $principalInfo = Get-IVADObject -Filter "(sAMAccountName=$samName)" -Properties @('objectClass', 'memberOf', 'whenCreated')
                        }
                    }
                    catch {
                        # Couldn't get additional info
                    }
                    
                    $unauthorizedPrincipals += @{
                        Name = $identityName
                        Permissions = $permissionDetails -join ", "
                        ObjectClass = if ($principalInfo) { $principalInfo.objectClass } else { "Unknown" }
                        MemberOf = if ($principalInfo -and $principalInfo.memberOf) { 
                            ($principalInfo.memberOf | ForEach-Object { 
                                ($_ -split ",")[0] -replace "CN=", "" 
                            })[0..2] -join ", "
                        } else { "N/A" }
                    }
                }
            }
        }
        
        return $unauthorizedPrincipals
    }
    
    # Check domain-level permissions
    $domainUnauthorized = Check-GPOLinkingPermissions -ACL $domainACL -ObjectName $DomainName -ObjectType "Domain" -IsCritical $true
    
    foreach ($principal in $domainUnauthorized) {
        $findings += @{
            ObjectName = $principal.Name
            ObjectType = "Principal"
            RiskLevel = "Critical"
            Description = "Non-administrative principal has GPO linking permissions at DOMAIN level. Permissions: $($principal.Permissions). This allows deployment of policies affecting ALL domain objects. Object type: $($principal.ObjectClass), Member of: $($principal.MemberOf)"
            Remediation = "1. IMMEDIATELY remove GPO linking permissions from this principal at domain level. 2. Review audit logs for any GPOs linked by this account. 3. Verify all currently linked GPOs are legitimate. 4. Investigate how these permissions were granted. 5. Consider this a potential security breach."
            AffectedAttributes = @("gPLink", "gPOptions", "nTSecurityDescriptor")
        }
    }
    
    # Check critical OUs
    foreach ($ou in $criticalOUs) {
        try {
            $ouACL = Get-IVADObjectACL -DistinguishedName $ou.DN
            $ouUnauthorized = Check-GPOLinkingPermissions -ACL $ouACL -ObjectName $ou.Name -ObjectType "OrganizationalUnit" -IsCritical $ou.Critical
            
            foreach ($principal in $ouUnauthorized) {
                $riskLevel = if ($ou.Critical) { "High" } else { "Medium" }
                $findings += @{
                    ObjectName = $principal.Name
                    ObjectType = "Principal"
                    RiskLevel = $riskLevel
                    Description = "Non-administrative principal has GPO linking permissions on $($ou.Name). Permissions: $($principal.Permissions). Object type: $($principal.ObjectClass). This OU contains $(if($ou.Critical){'CRITICAL domain controllers'}else{'organizational objects'})."
                    Remediation = "1. Remove GPO linking permissions from this principal on $($ou.Name). 2. Review any GPOs linked to this OU. 3. Implement least-privilege model for GPO management. 4. Use delegation carefully and document all delegations."
                    AffectedAttributes = @("gPLink", "gPOptions", "ouACL")
                }
            }
        }
        catch {
            # Skip if can't access OU
        }
    }
    
    # Check for users who can create GPOs (different but related permission)
    try {
        $gpContainer = "CN=Policies,CN=System,$domainDN"
        $gpContainerACL = Get-IVADObjectACL -DistinguishedName $gpContainer
        
        foreach ($ace in $gpContainerACL.Access) {
            if ($ace.AccessControlType -eq "Allow" -and 
                ($ace.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::CreateChild)) {
                
                $identityName = $ace.IdentityReference.Value
                $isAllowed = $false
                
                foreach ($allowedName in $allowedPrincipals) {
                    if ($identityName -like "*$allowedName*") {
                        $isAllowed = $true
                        break
                    }
                }
                
                if (-not $isAllowed -and $identityName -notlike "*Group Policy Creator Owners*") {
                    $findings += @{
                        ObjectName = $identityName
                        ObjectType = "Principal"
                        RiskLevel = "Medium"
                        Description = "Non-standard principal can CREATE new Group Policy Objects. While they cannot link them without additional permissions, this is still a security concern."
                        Remediation = "1. Review if this principal needs GPO creation rights. 2. Remove CreateChild permission from the Group Policy container if not required. 3. Monitor GPO creation events from this account."
                        AffectedAttributes = @("CreateChild", "GroupPolicyContainer")
                    }
                }
            }
        }
    }
    catch {
        # Skip GPO container check
    }
    
    # Calculate execution time
    $executionTime = ((Get-Date) - $startTime).TotalSeconds
    
    # Determine final score and status
    $score = 100  # Start with perfect score
    $status = "Success"
    $message = "GPO linking delegation assessment completed."
    
    if ($findings.Count -gt 0) {
        $criticalCount = @($findings | Where-Object { $_.RiskLevel -eq "Critical" }).Count
        $highCount = @($findings | Where-Object { $_.RiskLevel -eq "High" }).Count
        $mediumCount = @($findings | Where-Object { $_.RiskLevel -eq "Medium" }).Count
        
        if ($criticalCount -gt 0) {
            $score = 0
            $message = "CRITICAL: Found $criticalCount principal(s) with domain-level GPO linking permissions! This is a severe security risk."
        }
        elseif ($highCount -gt 0) {
            $score = 25
            $message = "WARNING: Found $highCount principal(s) with GPO linking permissions on critical OUs and $mediumCount on regular OUs."
        }
        else {
            $score = 50
            $message = "Found $mediumCount principal(s) with excessive GPO-related permissions requiring review."
        }
    }
    else {
        $message = "GPO linking permissions are properly restricted to administrative accounts only."
    }
    
    return @{
        CheckId = "AD-T2-005"
        Timestamp = (Get-Date).ToString("o")
        Status = $status
        Score = $score
        Severity = "High"
        Category = "PrivilegeEscalation"
        Findings = $findings
        Message = $message
        AffectedObjects = $findings.Count
        IgnoredObjects = 0
        Metadata = @{
            Domain = $DomainName
            ExecutionTime = [Math]::Round($executionTime, 2)
            OUsChecked = $criticalOUs.Count + 1  # +1 for domain itself
            UnauthorizedPrincipals = $findings.Count
        }
    }
}
catch {
    return @{
        CheckId = "AD-T2-005"
        Timestamp = (Get-Date).ToString("o")
        Status = "Error"
        Score = 0
        Severity = "High"
        Category = "PrivilegeEscalation"
        Findings = @()
        Message = "Error executing GPO delegation assessment: $_"
        AffectedObjects = 0
        IgnoredObjects = 0
        Metadata = @{
            Domain = $DomainName
            ExecutionTime = 0.0
            ErrorDetails = $_.Exception.Message
        }
    }
}