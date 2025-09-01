<#
.SYNOPSIS
Detects weak or misconfigured Access Control Lists (ACLs) with DCSync rights

.METADATA
{
  "id": "AD-T2-001",
  "name": "Weak or Misconfigured ACLs with DCSync Rights",
  "description": "Detects improperly set permissions on AD objects that grant non-default principals DCSync rights. DCSync attacks allow attackers to impersonate a domain controller and request password hashes for any user, including domain administrators.",
  "category": "PrivilegeEscalation",
  "severity": "High",
  "weight": 8,
  "impact": 9,
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
    
    # Import ADSI helper functions
    $helperPath = Join-Path $PSScriptRoot "IronVeil-ADSIHelper.ps1"
    . $helperPath
    
    if (-not $DomainName) {
        throw "Domain name could not be determined"
    }
    
    # Get domain information using ADSI
    $domainInfo = Get-IVDomainInfo -DomainName $DomainName
    $domainDN = $domainInfo.DistinguishedName
    $domainSID = $domainInfo.DomainSID
    
    # Define the DCSync-related extended rights GUIDs
    $dcSyncRights = @{
        "DS-Replication-Get-Changes" = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
        "DS-Replication-Get-Changes-All" = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
        "DS-Replication-Get-Changes-In-Filtered-Set" = "89e95b76-444d-4c62-991a-0facbeda640c"
    }
    
    # Get the default groups that should have DCSync rights
    $allowedPrincipals = @(
        "Domain Controllers",
        "Enterprise Domain Controllers",
        "Administrators",
        "Domain Admins",
        "Enterprise Admins",
        "SYSTEM",
        "LocalSystem"
    )
    
    # Convert allowed principals to SIDs for comparison
    $allowedSIDs = @(
        "$domainSID-516",  # Domain Controllers
        "$domainSID-512",  # Domain Admins
        "$domainSID-519",  # Enterprise Admins
        "S-1-5-32-544",    # Builtin Administrators
        "S-1-5-18",        # Local System
        "S-1-5-9"          # Enterprise Domain Controllers
    )
    
    # Get the ACL of the domain object using ADSI
    $domainACL = Get-IVDomainACL -DomainDN $domainDN
    
    # Check each ACE in the ACL
    foreach ($ace in $domainACL.Access) {
        # Skip deny permissions
        if ($ace.AccessControlType -eq "Deny") {
            continue
        }
        
        # Check if this ACE grants any DCSync-related rights
        $hasDCSync = $false
        $grantedRights = @()
        
        foreach ($rightName in $dcSyncRights.Keys) {
            $rightGuid = [guid]$dcSyncRights[$rightName]
            
            # Check if this ACE includes the specific extended right
            if ($ace.ObjectType -eq $rightGuid -or 
                ($ace.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) -and 
                $ace.ObjectType -eq ([guid]"00000000-0000-0000-0000-000000000000")) {
                
                $hasDCSync = $true
                $grantedRights += $rightName
            }
        }
        
        if ($hasDCSync) {
            # Get the identity that has these rights
            $identitySID = $ace.IdentityReference.Value
            
            # Convert to SID if it's in domain\user format
            if ($identitySID -like "*\*") {
                try {
                    $sidObj = New-Object System.Security.Principal.NTAccount($identitySID)
                    $identitySID = $sidObj.Translate([System.Security.Principal.SecurityIdentifier]).Value
                }
                catch {
                    # Keep the original format if translation fails
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
            
            # Also check by name for domain-specific groups
            $identityName = $ace.IdentityReference.Value
            foreach ($allowedName in $allowedPrincipals) {
                if ($identityName -like "*$allowedName*") {
                    $isAllowed = $true
                    break
                }
            }
            
            if (-not $isAllowed) {
                # This is a non-standard principal with DCSync rights
                $objectInfo = $null
                try {
                    # Try to get more information about the principal using ADSI
                    if ($identitySID -match "^S-1-") {
                        $objectInfo = Get-IVObjectBySID -SID $identitySID -Properties @('objectClass', 'whenCreated', 'whenChanged')
                    }
                    else {
                        $splitName = $identityName.Split('\')[-1]
                        $objectInfo = Get-IVObjectByName -Name $splitName -Properties @('objectClass', 'whenCreated', 'whenChanged')
                    }
                }
                catch {
                    # Couldn't get additional info
                }
                
                $objectType = "Unknown"
                $additionalInfo = ""
                
                if ($objectInfo) {
                    $objectType = if ($objectInfo.objectClass) { 
                        if ($objectInfo.objectClass -is [Array]) { $objectInfo.objectClass[-1] } else { $objectInfo.objectClass }
                    } else { "Unknown" }
                    
                    if ($objectInfo.whenCreated) {
                        $whenCreated = if ($objectInfo.whenCreated -is [Array]) { $objectInfo.whenCreated[0] } else { $objectInfo.whenCreated }
                        $daysSinceCreation = ((Get-Date) - $whenCreated).Days
                        
                        $whenChanged = if ($objectInfo.whenChanged) {
                            if ($objectInfo.whenChanged -is [Array]) { $objectInfo.whenChanged[0] } else { $objectInfo.whenChanged }
                        } else { $whenCreated }
                        
                        $daysSinceModification = ((Get-Date) - $whenChanged).Days
                        $additionalInfo = "Created $daysSinceCreation days ago, last modified $daysSinceModification days ago"
                    }
                }
                
                $findings += @{
                    ObjectName = $identityName
                    ObjectType = $objectType
                    RiskLevel = "High"
                    Description = "Non-standard principal has DCSync rights on the domain. Rights granted: $($grantedRights -join ', '). $additionalInfo. This could allow an attacker to extract password hashes for all domain users."
                    Remediation = "1. Review why this principal has DCSync rights. 2. If not required, remove these permissions immediately. 3. If legitimate, document the business justification. 4. Monitor this account for suspicious activity. 5. Consider implementing additional controls like privileged access workstations."
                    AffectedAttributes = @("nTSecurityDescriptor", "objectType") + $grantedRights
                }
            }
        }
    }
    
    # Also check for any principals with GenericAll rights on the domain
    foreach ($ace in $domainACL.Access) {
        if ($ace.AccessControlType -eq "Allow" -and 
            ($ace.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericAll)) {
            
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
                # Check if we already reported this principal for DCSync rights
                $alreadyReported = $false
                foreach ($finding in $findings) {
                    if ($finding.ObjectName -eq $identityName) {
                        $alreadyReported = $true
                        break
                    }
                }
                
                if (-not $alreadyReported) {
                    $findings += @{
                        ObjectName = $identityName
                        ObjectType = "Principal"
                        RiskLevel = "High"
                        Description = "Non-standard principal has GenericAll rights on the domain. This includes DCSync capabilities and full control over the domain object."
                        Remediation = "1. IMMEDIATE ACTION: Review and likely remove these excessive permissions. 2. GenericAll on the domain is extremely dangerous. 3. Investigate how these permissions were granted. 4. Check audit logs for any use of these permissions. 5. Consider this a potential compromise."
                        AffectedAttributes = @("nTSecurityDescriptor", "ActiveDirectoryRights", "GenericAll")
                    }
                }
            }
        }
    }
    
    # Calculate execution time
    $executionTime = ((Get-Date) - $startTime).TotalSeconds
    
    # Determine final score and status
    $score = 100  # Start with perfect score
    $status = "Success"
    $message = "DCSync rights assessment completed successfully."
    
    if ($findings.Count -gt 0) {
        # Calculate score based on number of findings
        $score = [Math]::Max(0, 100 - ($findings.Count * 25))
        $message = "WARNING: Found $($findings.Count) non-standard principal(s) with DCSync or equivalent rights. These permissions could allow password hash extraction for all domain users."
    }
    else {
        $message = "No weak ACLs with DCSync rights detected. Only standard administrative groups have these permissions."
    }
    
    return @{
        CheckId = "AD-T2-001"
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
            TotalACEsChecked = $domainACL.Access.Count
            AllowedPrincipalsCount = $allowedPrincipals.Count
        }
    }
}
catch {
    return @{
        CheckId = "AD-T2-001"
        Timestamp = (Get-Date).ToString("o")
        Status = "Error"
        Score = 0
        Severity = "High"
        Category = "PrivilegeEscalation"
        Findings = @()
        Message = "Error executing DCSync ACL assessment: $_"
        AffectedObjects = 0
        IgnoredObjects = 0
        Metadata = @{
            Domain = $DomainName
            ExecutionTime = 0.0
            ErrorDetails = $_.Exception.Message
        }
    }
}