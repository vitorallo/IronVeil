<#
.SYNOPSIS
Monitors for unauthorized ACL modifications on the AdminSDHolder object

.METADATA
{
  "id": "AD-T3-014",
  "name": "AdminSDHolder Object Permission Changes",
  "description": "The AdminSDHolder object controls security template for all privileged accounts - unauthorized changes affect all protected objects",
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
    
    # Get domain information
    $domain = Get-ADDomain -Server $DomainName
    $domainDN = $domain.DistinguishedName
    $domainSID = $domain.DomainSID
    
    # Get AdminSDHolder object
    $adminSDHolderDN = "CN=AdminSDHolder,CN=System,$domainDN"
    $adminSDHolder = Get-ADObject -Identity $adminSDHolderDN -Properties nTSecurityDescriptor, whenChanged, whenCreated -Server $DomainName -ErrorAction Stop
    
    # Define expected default permissions for AdminSDHolder
    $expectedPrincipals = @{
        "Domain Admins" = "FullControl"
        "Enterprise Admins" = "FullControl"
        "Schema Admins" = "FullControl"
        "Administrators" = "FullControl"
        "SYSTEM" = "FullControl"
        "SELF" = "ReadProperty,WriteProperty"
        "Authenticated Users" = "ReadProperty"
    }
    
    # Get current ACL
    $acl = $adminSDHolder.nTSecurityDescriptor
    $currentPermissions = @{}
    $unexpectedPermissions = @()
    
    foreach ($ace in $acl.Access) {
        try {
            # Resolve the identity
            $identity = $null
            $identityName = $null
            
            if ($ace.IdentityReference -match "^S-1-") {
                # It's a SID
                try {
                    $identity = Get-ADObject -Identity $ace.IdentityReference -Server $DomainName -ErrorAction Stop
                    $identityName = $identity.Name
                } catch {
                    $identityName = $ace.IdentityReference.ToString()
                }
            } else {
                $identityName = $ace.IdentityReference.ToString()
                # Remove domain prefix if present
                if ($identityName -match "\\") {
                    $identityName = $identityName.Split("\")[1]
                }
            }
            
            # Check if this is an expected principal
            $isExpected = $false
            $isAppropriate = $false
            
            foreach ($expected in $expectedPrincipals.Keys) {
                if ($identityName -eq $expected -or $identityName -match $expected) {
                    $isExpected = $true
                    
                    # Check if permissions are appropriate
                    if ($ace.AccessControlType -eq "Allow") {
                        if ($expectedPrincipals[$expected] -eq "FullControl" -and 
                            $ace.ActiveDirectoryRights -match "GenericAll|FullControl") {
                            $isAppropriate = $true
                        } elseif ($ace.ActiveDirectoryRights -match $expectedPrincipals[$expected]) {
                            $isAppropriate = $true
                        }
                    }
                    break
                }
            }
            
            if (-not $isExpected -and $ace.AccessControlType -eq "Allow") {
                # Unexpected permission found
                $rights = $ace.ActiveDirectoryRights.ToString()
                
                # Determine risk level based on permissions
                $riskLevel = "Low"
                if ($rights -match "GenericAll|GenericWrite|WriteDacl|WriteOwner") {
                    $riskLevel = "High"
                } elseif ($rights -match "WriteProperty|CreateChild|DeleteChild") {
                    $riskLevel = "Medium"
                }
                
                $unexpectedPermissions += @{
                    Identity = $identityName
                    Rights = $rights
                    RiskLevel = $riskLevel
                    Type = $ace.AccessControlType
                }
            } elseif ($isExpected -and -not $isAppropriate -and $ace.AccessControlType -eq "Allow") {
                # Expected principal but wrong permissions
                $unexpectedPermissions += @{
                    Identity = $identityName
                    Rights = $ace.ActiveDirectoryRights.ToString()
                    RiskLevel = "Medium"
                    Type = "Modified"
                    Expected = $expectedPrincipals[$identityName]
                }
            }
            
            # Track current permissions
            if (-not $currentPermissions.ContainsKey($identityName)) {
                $currentPermissions[$identityName] = @()
            }
            $currentPermissions[$identityName] += $ace.ActiveDirectoryRights.ToString()
            
        } catch {
            Write-Warning "Could not process ACE: $_"
        }
    }
    
    # Check for unexpected permissions
    if ($unexpectedPermissions.Count -gt 0) {
        foreach ($perm in $unexpectedPermissions) {
            $description = if ($perm.Type -eq "Modified") {
                "Principal '$($perm.Identity)' has modified permissions: $($perm.Rights) (expected: $($perm.Expected))"
            } else {
                "Unexpected principal '$($perm.Identity)' has permissions: $($perm.Rights)"
            }
            
            $findings += @{
                ObjectName = "AdminSDHolder"
                ObjectType = "SystemObject"
                RiskLevel = $perm.RiskLevel
                Description = $description
                Remediation = "Reset AdminSDHolder permissions to default using 'dsacls `"$adminSDHolderDN`" /resetDefaultDACL' or manually remove unauthorized permissions"
                AffectedAttributes = @("nTSecurityDescriptor")
            }
            $affectedCount++
            
            if ($perm.RiskLevel -eq "High") {
                $score -= 20
            } elseif ($perm.RiskLevel -eq "Medium") {
                $score -= 15
            } else {
                $score -= 10
            }
        }
    }
    
    # Check for missing expected permissions
    foreach ($expected in $expectedPrincipals.Keys) {
        $found = $false
        foreach ($current in $currentPermissions.Keys) {
            if ($current -eq $expected -or $current -match $expected) {
                $found = $true
                break
            }
        }
        
        if (-not $found) {
            $findings += @{
                ObjectName = "AdminSDHolder"
                ObjectType = "SystemObject"
                RiskLevel = "High"
                Description = "Expected principal '$expected' is missing from AdminSDHolder permissions"
                Remediation = "Restore default AdminSDHolder permissions to ensure proper security inheritance"
                AffectedAttributes = @("nTSecurityDescriptor")
            }
            $affectedCount++
            $score -= 15
        }
    }
    
    # Check AdminSDHolder owner
    $owner = $acl.Owner
    if ($owner) {
        $ownerName = $null
        if ($owner -match "^S-1-") {
            try {
                $ownerObj = Get-ADObject -Identity $owner -Server $DomainName -ErrorAction Stop
                $ownerName = $ownerObj.Name
            } catch {
                $ownerName = $owner.ToString()
            }
        } else {
            $ownerName = $owner.ToString()
            if ($ownerName -match "\\") {
                $ownerName = $ownerName.Split("\")[1]
            }
        }
        
        if ($ownerName -notin @("Domain Admins", "Enterprise Admins", "Administrators", "BUILTIN\Administrators")) {
            $findings += @{
                ObjectName = "AdminSDHolder"
                ObjectType = "SystemObject"
                RiskLevel = "Critical"
                Description = "AdminSDHolder has non-standard owner: '$ownerName'"
                Remediation = "Immediately change AdminSDHolder owner to Domain Admins"
                AffectedAttributes = @("Owner")
            }
            $affectedCount++
            $score -= 30
        }
    }
    
    # Check when AdminSDHolder was last modified
    $daysSinceModified = ((Get-Date) - $adminSDHolder.whenChanged).Days
    if ($daysSinceModified -lt 7) {
        $findings += @{
            ObjectName = "AdminSDHolder"
            ObjectType = "SystemObject"
            RiskLevel = "Medium"
            Description = "AdminSDHolder was recently modified ($daysSinceModified days ago)"
            Remediation = "Review recent changes to AdminSDHolder and verify they were authorized"
            AffectedAttributes = @("whenChanged")
        }
        $affectedCount++
        $score -= 10
    }
    
    # Check SDProp (Security Descriptor Propagation) task settings
    try {
        # Get PDC Emulator
        $pdc = (Get-ADDomainController -Discover -Service PrimaryDC -DomainName $DomainName).HostName
        
        # Check registry for SDProp interval (AdminSDProtectFrequency)
        $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $pdc)
        $key = $reg.OpenSubKey("SYSTEM\CurrentControlSet\Services\NTDS\Parameters")
        
        if ($key) {
            $sdpropInterval = $key.GetValue("AdminSDProtectFrequency")
            
            if ($sdpropInterval -and $sdpropInterval -ne 3600) {
                # Non-default interval (default is 3600 seconds = 1 hour)
                $findings += @{
                    ObjectName = "SDProp Task"
                    ObjectType = "Configuration"
                    RiskLevel = if ($sdpropInterval -gt 7200) { "Medium" } else { "Low" }
                    Description = "SDProp task interval is non-default: $sdpropInterval seconds (default: 3600)"
                    Remediation = "Consider resetting AdminSDProtectFrequency to default (3600) unless there's a specific requirement"
                    AffectedAttributes = @("AdminSDProtectFrequency")
                }
                $affectedCount++
                $score -= 5
            }
            
            $key.Close()
        }
        $reg.Close()
    } catch {
        $ignoredCount++
        Write-Warning "Could not check SDProp settings: $_"
    }
    
    # Check protected accounts (AdminCount=1) for inheritance disabled
    try {
        $protectedAccounts = Get-ADObject -Filter {AdminCount -eq 1} `
            -Properties nTSecurityDescriptor, ObjectClass -Server $DomainName -ErrorAction Stop | 
            Select-Object -First 50  # Limit for performance
        
        $inheritanceIssues = 0
        foreach ($account in $protectedAccounts) {
            $accountAcl = $account.nTSecurityDescriptor
            
            # Check if inheritance is manually enabled (should be disabled for protected accounts)
            if (-not $accountAcl.AreAccessRulesProtected) {
                $inheritanceIssues++
            }
        }
        
        if ($inheritanceIssues -gt 0) {
            $findings += @{
                ObjectName = "Protected Accounts"
                ObjectType = "Multiple"
                RiskLevel = "Medium"
                Description = "$inheritanceIssues protected account(s) have inheritance manually enabled (should be disabled)"
                Remediation = "Let SDProp task reset permissions on protected accounts, or manually disable inheritance"
                AffectedAttributes = @("Inheritance")
            }
            $affectedCount++
            $score -= 10
        }
    } catch {
        $ignoredCount++
        Write-Warning "Could not check protected accounts: $_"
    }
    
    # Check for Deny ACEs on AdminSDHolder
    $denyAces = $acl.Access | Where-Object { $_.AccessControlType -eq "Deny" }
    if ($denyAces.Count -gt 0) {
        foreach ($denyAce in $denyAces) {
            $identityName = $denyAce.IdentityReference.ToString()
            if ($identityName -match "\\") {
                $identityName = $identityName.Split("\")[1]
            }
            
            $findings += @{
                ObjectName = "AdminSDHolder"
                ObjectType = "SystemObject"
                RiskLevel = "Medium"
                Description = "Deny ACE found for '$identityName' with rights: $($denyAce.ActiveDirectoryRights)"
                Remediation = "Review and remove unnecessary Deny ACEs from AdminSDHolder"
                AffectedAttributes = @("Deny ACEs")
            }
            $affectedCount++
            $score -= 8
        }
    }
    
    # Ensure score doesn't go below 0
    $score = [Math]::Max(0, $score)
    
    # Determine overall status
    $status = if ($findings.Count -eq 0) { "Success" } 
              elseif ($score -lt 50) { "Failed" } 
              else { "Warning" }
    
    $message = if ($findings.Count -eq 0) {
        "AdminSDHolder permissions are properly configured"
    } else {
        "Found $($findings.Count) issues with AdminSDHolder configuration"
    }
    
    $executionTime = (Get-Date) - $startTime
    
    return @{
        CheckId = "AD-T3-014"
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
            LastModified = $adminSDHolder.whenChanged.ToString("o")
            DaysSinceModified = $daysSinceModified
        }
    }
    
} catch {
    return @{
        CheckId = "AD-T3-014"
        Timestamp = (Get-Date).ToString("o")
        Status = "Error"
        Score = 0
        Severity = "Medium"
        Category = "PrivilegedAccess"
        Findings = @()
        Message = "Error checking AdminSDHolder permissions: $_"
        AffectedObjects = 0
        IgnoredObjects = 0
        Metadata = @{
            Domain = $DomainName
            ExecutionTime = ((Get-Date) - $startTime).TotalSeconds
            Error = $_.Exception.Message
        }
    }
}