<#
.SYNOPSIS
Detects well-known privileged SIDs injected into user SIDHistory attributes

.METADATA
{
  "id": "AD-T1-002",
  "name": "Well-known Privileged SIDs in SIDHistory",
  "description": "SID History injection involves adding privileged Security Identifiers (SIDs) to user objects' SIDHistory attribute. This allows attackers to gain elevated privileges without being members of privileged groups. This check identifies unexpected privileged SIDs in user SIDHistory attributes.",
  "category": "PrivilegeEscalation",
  "severity": "Critical",
  "weight": 10,
  "impact": 10,
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
    
    # Import required module
    Import-Module ActiveDirectory -ErrorAction SilentlyContinue
    
    if (-not $DomainName) {
        throw "Domain name could not be determined"
    }
    
    # Get domain information
    $domain = Get-ADDomain -Identity $DomainName
    $domainSID = $domain.DomainSID.Value
    
    # Define well-known privileged SIDs to check for
    $privilegedSIDs = @{
        # Domain-specific privileged groups (will append domain SID)
        "512" = "Domain Admins"
        "519" = "Enterprise Admins"
        "518" = "Schema Admins"
        "520" = "Group Policy Creator Owners"
        "544" = "Administrators"
        "548" = "Account Operators"
        "549" = "Server Operators"
        "550" = "Print Operators"
        "551" = "Backup Operators"
        "552" = "Replicators"
        
        # Well-known SIDs that should never be in SIDHistory
        "S-1-5-32-544" = "BUILTIN\Administrators"
        "S-1-5-32-548" = "BUILTIN\Account Operators"
        "S-1-5-32-549" = "BUILTIN\Server Operators"
        "S-1-5-32-550" = "BUILTIN\Print Operators"
        "S-1-5-32-551" = "BUILTIN\Backup Operators"
        "S-1-5-32-552" = "BUILTIN\Replicators"
    }
    
    # Build list of domain-specific privileged SIDs
    $domainPrivilegedSIDs = @{}
    foreach ($rid in @("512", "519", "518", "520", "544", "548", "549", "550", "551", "552")) {
        $sid = "$domainSID-$rid"
        $domainPrivilegedSIDs[$sid] = $privilegedSIDs[$rid]
    }
    
    # Combine all privileged SIDs
    $allPrivilegedSIDs = $domainPrivilegedSIDs.Clone()
    foreach ($key in $privilegedSIDs.Keys) {
        if ($key.StartsWith("S-1-")) {
            $allPrivilegedSIDs[$key] = $privilegedSIDs[$key]
        }
    }
    
    # Get all users with non-empty SIDHistory
    $filter = "(&(objectClass=user)(objectCategory=person)(sIDHistory=*))"
    $usersWithSIDHistory = Get-ADObject -LDAPFilter $filter -Properties sIDHistory, samAccountName, distinguishedName, enabled, whenCreated, whenChanged, memberOf
    
    # Also check computer accounts as they can have SIDHistory too
    $computerFilter = "(&(objectClass=computer)(sIDHistory=*))"
    $computersWithSIDHistory = Get-ADObject -LDAPFilter $computerFilter -Properties sIDHistory, samAccountName, distinguishedName, enabled, whenCreated, whenChanged
    
    # Combine users and computers
    $allObjectsWithSIDHistory = @()
    if ($usersWithSIDHistory) {
        $allObjectsWithSIDHistory += $usersWithSIDHistory
    }
    if ($computersWithSIDHistory) {
        $allObjectsWithSIDHistory += $computersWithSIDHistory
    }
    
    # Check each object's SIDHistory
    foreach ($obj in $allObjectsWithSIDHistory) {
        $objType = if ($obj.objectClass -contains "computer") { "Computer" } else { "User" }
        $suspiciousSIDs = @()
        $isAlreadyPrivileged = $false
        
        # Check if user is already in privileged groups (for context)
        if ($obj.memberOf) {
            $privilegedGroupPatterns = @(
                "*Domain Admins*",
                "*Enterprise Admins*",
                "*Schema Admins*",
                "*Administrators*"
            )
            
            foreach ($group in $obj.memberOf) {
                foreach ($pattern in $privilegedGroupPatterns) {
                    if ($group -like $pattern) {
                        $isAlreadyPrivileged = $true
                        break
                    }
                }
            }
        }
        
        # Check each SID in SIDHistory
        foreach ($sidBytes in $obj.sIDHistory) {
            # Convert byte array to SID string
            $sid = (New-Object System.Security.Principal.SecurityIdentifier($sidBytes, 0)).Value
            
            # Check if this SID is in our privileged list
            if ($allPrivilegedSIDs.ContainsKey($sid)) {
                $suspiciousSIDs += @{
                    SID = $sid
                    GroupName = $allPrivilegedSIDs[$sid]
                }
            }
            
            # Also check for any SID from a different domain (potential cross-domain attack)
            if (-not $sid.StartsWith($domainSID) -and $sid -match "^S-1-5-21-") {
                $suspiciousSIDs += @{
                    SID = $sid
                    GroupName = "Foreign Domain SID"
                }
            }
        }
        
        # If suspicious SIDs found, create a finding
        if ($suspiciousSIDs.Count -gt 0) {
            $sidList = ($suspiciousSIDs | ForEach-Object { "$($_.GroupName) ($($_.SID))" }) -join "; "
            $daysSinceCreation = (Get-Date) - $obj.whenCreated
            $daysSinceModification = (Get-Date) - $obj.whenChanged
            
            # Determine risk level based on various factors
            $riskLevel = "Critical"
            $riskFactors = @()
            
            if ($suspiciousSIDs.Count -gt 1) {
                $riskFactors += "Multiple privileged SIDs"
            }
            
            if ($daysSinceModification.Days -lt 30) {
                $riskFactors += "Recently modified"
            }
            
            if (-not $isAlreadyPrivileged) {
                $riskFactors += "Account not legitimately privileged"
            }
            
            if ($objType -eq "Computer") {
                $riskFactors += "Computer account with SIDHistory"
            }
            
            $description = "$objType account has privileged SIDs in SIDHistory attribute: $sidList."
            if ($riskFactors.Count -gt 0) {
                $description += " Risk factors: $($riskFactors -join '; ')."
            }
            
            $findings += @{
                ObjectName = $obj.samAccountName
                ObjectType = $objType
                RiskLevel = $riskLevel
                Description = $description
                Remediation = "1. IMMEDIATE ACTION: This is likely a compromise. 2. Clear the SIDHistory attribute for this account. 3. Reset the account password. 4. Audit all actions performed by this account. 5. Check for persistence mechanisms. 6. Investigate how SIDHistory was modified. 7. Consider this account fully compromised."
                AffectedAttributes = @("sIDHistory", "whenChanged")
            }
        }
    }
    
    # Also check for any objects with unusually large SIDHistory (potential SID history attack)
    foreach ($obj in $allObjectsWithSIDHistory) {
        if ($obj.sIDHistory.Count -gt 5) {
            $objType = if ($obj.objectClass -contains "computer") { "Computer" } else { "User" }
            
            $findings += @{
                ObjectName = $obj.samAccountName
                ObjectType = $objType
                RiskLevel = "High"
                Description = "$objType account has unusually large SIDHistory with $($obj.sIDHistory.Count) entries. This could indicate SID history stuffing attack."
                Remediation = "1. Review all SIDs in the SIDHistory attribute. 2. Clear unnecessary SIDHistory entries. 3. Investigate why so many SIDs are present. 4. Consider this a potential indicator of compromise."
                AffectedAttributes = @("sIDHistory")
            }
        }
    }
    
    # Calculate execution time
    $executionTime = ((Get-Date) - $startTime).TotalSeconds
    
    # Determine final score and status
    $score = 100  # Start with perfect score
    $status = "Success"
    $message = "SIDHistory privilege escalation check completed successfully."
    
    if ($findings.Count -gt 0) {
        $criticalCount = @($findings | Where-Object { $_.RiskLevel -eq "Critical" }).Count
        $highCount = @($findings | Where-Object { $_.RiskLevel -eq "High" }).Count
        
        if ($criticalCount -gt 0) {
            $score = 0
            $message = "CRITICAL: Privileged SID injection detected! Found $criticalCount accounts with injected privileged SIDs. This indicates active compromise."
        }
        else {
            $score = 25
            $message = "WARNING: Suspicious SIDHistory usage detected. Found $highCount accounts with unusual SIDHistory requiring investigation."
        }
    }
    else {
        if ($allObjectsWithSIDHistory.Count -gt 0) {
            $message = "No malicious SIDHistory usage detected. Found $($allObjectsWithSIDHistory.Count) objects with SIDHistory but none contain privileged SIDs."
            $score = 90  # Small deduction for having SIDHistory at all
        }
        else {
            $message = "No SIDHistory usage detected. Environment is clean from SIDHistory-based attacks."
        }
    }
    
    return @{
        CheckId = "AD-T1-002"
        Timestamp = (Get-Date).ToString("o")
        Status = $status
        Score = $score
        Severity = "Critical"
        Category = "PrivilegeEscalation"
        Findings = $findings
        Message = $message
        AffectedObjects = $findings.Count
        IgnoredObjects = $allObjectsWithSIDHistory.Count - $findings.Count
        Metadata = @{
            Domain = $DomainName
            ExecutionTime = [Math]::Round($executionTime, 2)
            TotalObjectsWithSIDHistory = $allObjectsWithSIDHistory.Count
            PrivilegedSIDsChecked = $allPrivilegedSIDs.Count
        }
    }
}
catch {
    return @{
        CheckId = "AD-T1-002"
        Timestamp = (Get-Date).ToString("o")
        Status = "Error"
        Score = 0
        Severity = "Critical"
        Category = "PrivilegeEscalation"
        Findings = @()
        Message = "Error executing SIDHistory privilege check: $_"
        AffectedObjects = 0
        IgnoredObjects = 0
        Metadata = @{
            Domain = $DomainName
            ExecutionTime = 0.0
            ErrorDetails = $_.Exception.Message
        }
    }
}