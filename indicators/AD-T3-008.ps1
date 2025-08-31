<#
.SYNOPSIS
Identifies computer objects with Resource-Based Constrained Delegation (RBCD) configured

.METADATA
{
  "id": "AD-T3-008",
  "name": "Resource-Based Constrained Delegation (RBCD) on Computer Objects",
  "description": "RBCD configured on computer objects can be abused for privilege escalation and lateral movement",
  "category": "Delegation",
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
    
    # Get all computer objects with RBCD configured
    $computersWithRBCD = Get-ADComputer -Filter {msDS-AllowedToActOnBehalfOfOtherIdentity -like "*"} `
        -Properties msDS-AllowedToActOnBehalfOfOtherIdentity, OperatingSystem, LastLogonTimestamp, servicePrincipalName `
        -Server $DomainName -ErrorAction Stop
    
    foreach ($computer in $computersWithRBCD) {
        try {
            # Parse the msDS-AllowedToActOnBehalfOfOtherIdentity attribute
            $rbcdACL = $computer."msDS-AllowedToActOnBehalfOfOtherIdentity"
            $allowedPrincipals = @()
            
            if ($rbcdACL) {
                # Convert security descriptor to readable format
                $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor($rbcdACL, 0)
                
                foreach ($ace in $sd.DiscretionaryAcl) {
                    if ($ace.AccessMask -band 0x00000001) { # GenericAll permission
                        try {
                            $sid = $ace.SecurityIdentifier.Value
                            $principal = Get-ADObject -Identity $sid -Server $DomainName -ErrorAction Stop
                            
                            $principalInfo = @{
                                Name = $principal.Name
                                Type = $principal.ObjectClass
                                SID = $sid
                            }
                            
                            # Check if it's a user or computer account
                            if ($principal.ObjectClass -eq "user") {
                                $user = Get-ADUser -Identity $sid -Properties memberOf, Enabled -Server $DomainName
                                $principalInfo.Enabled = $user.Enabled
                                
                                # Check if user is privileged
                                $isPrivileged = $false
                                foreach ($group in $user.memberOf) {
                                    $groupName = ($group -split ",")[0] -replace "CN=", ""
                                    if ($groupName -in @("Domain Admins", "Enterprise Admins", "Administrators")) {
                                        $isPrivileged = $true
                                        $principalInfo.Privileged = $true
                                        break
                                    }
                                }
                            } elseif ($principal.ObjectClass -eq "computer") {
                                $principalComputer = Get-ADComputer -Identity $sid -Properties Enabled -Server $DomainName
                                $principalInfo.Enabled = $principalComputer.Enabled
                            }
                            
                            $allowedPrincipals += $principalInfo
                            
                        } catch {
                            $allowedPrincipals += @{
                                Name = "Unknown"
                                Type = "Unknown"
                                SID = $sid
                            }
                        }
                    }
                }
            }
            
            if ($allowedPrincipals.Count -gt 0) {
                # Determine risk level based on computer type and allowed principals
                $isDC = $computer.OperatingSystem -like "*Domain Controller*"
                $isServer = $computer.OperatingSystem -like "*Server*"
                $hasUserDelegation = ($allowedPrincipals | Where-Object { $_.Type -eq "user" }).Count -gt 0
                $hasEnabledDelegation = ($allowedPrincipals | Where-Object { $_.Enabled -eq $true }).Count -gt 0
                
                $riskLevel = if ($isDC) { "Critical" }
                            elseif ($isServer -and $hasUserDelegation) { "High" }
                            elseif ($hasUserDelegation) { "Medium" }
                            else { "Low" }
                
                $delegationList = $allowedPrincipals | ForEach-Object {
                    "$($_.Name) ($($_.Type)$(if ($_.Privileged) { ', PRIVILEGED' }))"
                }
                
                $findings += @{
                    ObjectName = $computer.Name
                    ObjectType = "Computer"
                    RiskLevel = $riskLevel
                    Description = "Computer has RBCD configured allowing delegation from: $($delegationList -join '; ')"
                    Remediation = "Review RBCD configuration and remove unnecessary delegations. Use 'Set-ADComputer -Identity $($computer.Name) -PrincipalsAllowedToDelegateToAccount $null' to clear"
                    AffectedAttributes = @("msDS-AllowedToActOnBehalfOfOtherIdentity")
                }
                $affectedCount++
                
                # Score impact based on risk
                if ($isDC) {
                    $score -= 30
                } elseif ($isServer -and $hasUserDelegation) {
                    $score -= 20
                } elseif ($hasUserDelegation) {
                    $score -= 15
                } else {
                    $score -= 10
                }
            }
            
        } catch {
            $ignoredCount++
            Write-Warning "Could not process RBCD for computer $($computer.Name): $_"
        }
    }
    
    # Check for users with rights to configure RBCD on computers
    try {
        $computers = Get-ADComputer -Filter * -Properties nTSecurityDescriptor -Server $DomainName -ErrorAction Stop | 
            Select-Object -First 100  # Sample for performance
        
        $usersWithRBCDRights = @{}
        
        foreach ($comp in $computers) {
            $acl = $comp.nTSecurityDescriptor
            
            foreach ($ace in $acl.Access) {
                # Check for write permission on msDS-AllowedToActOnBehalfOfOtherIdentity
                if ($ace.ObjectType -eq "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79" -and # msDS-AllowedToActOnBehalfOfOtherIdentity
                    $ace.ActiveDirectoryRights -match "WriteProperty" -and
                    $ace.AccessControlType -eq "Allow") {
                    
                    try {
                        $identity = Get-ADObject -Identity $ace.IdentityReference.Value -Server $DomainName -ErrorAction Stop
                        
                        if ($identity.ObjectClass -eq "user" -and 
                            $identity.Name -notin @("SYSTEM", "Administrators", "Domain Admins", "Enterprise Admins")) {
                            
                            if (-not $usersWithRBCDRights.ContainsKey($identity.Name)) {
                                $usersWithRBCDRights[$identity.Name] = 0
                            }
                            $usersWithRBCDRights[$identity.Name]++
                        }
                    } catch {
                        # Could not resolve identity
                    }
                }
            }
        }
        
        foreach ($user in $usersWithRBCDRights.Keys) {
            $findings += @{
                ObjectName = $user
                ObjectType = "User"
                RiskLevel = "Medium"
                Description = "User has rights to configure RBCD on at least $($usersWithRBCDRights[$user]) computer(s)"
                Remediation = "Review and remove unnecessary RBCD configuration rights"
                AffectedAttributes = @("Write msDS-AllowedToActOnBehalfOfOtherIdentity")
            }
            $affectedCount++
            $score -= 5
        }
        
    } catch {
        $ignoredCount++
        Write-Warning "Could not check RBCD configuration rights: $_"
    }
    
    # Ensure score doesn't go below 0
    $score = [Math]::Max(0, $score)
    
    # Determine overall status
    $status = if ($findings.Count -eq 0) { "Success" } 
              elseif ($score -lt 50) { "Failed" } 
              else { "Warning" }
    
    $message = if ($findings.Count -eq 0) {
        "No risky RBCD configurations detected on computer objects"
    } else {
        "Found $affectedCount computer objects with potentially risky RBCD configurations"
    }
    
    $executionTime = (Get-Date) - $startTime
    
    return @{
        CheckId = "AD-T3-008"
        Timestamp = (Get-Date).ToString("o")
        Status = $status
        Score = $score
        Severity = "Medium"
        Category = "Delegation"
        Findings = $findings
        Message = $message
        AffectedObjects = $affectedCount
        IgnoredObjects = $ignoredCount
        Metadata = @{
            Domain = $DomainName
            ExecutionTime = $executionTime.TotalSeconds
            ComputersWithRBCD = $computersWithRBCD.Count
        }
    }
    
} catch {
    return @{
        CheckId = "AD-T3-008"
        Timestamp = (Get-Date).ToString("o")
        Status = "Error"
        Score = 0
        Severity = "Medium"
        Category = "Delegation"
        Findings = @()
        Message = "Error checking RBCD configurations: $_"
        AffectedObjects = 0
        IgnoredObjects = 0
        Metadata = @{
            Domain = $DomainName
            ExecutionTime = ((Get-Date) - $startTime).TotalSeconds
            Error = $_.Exception.Message
        }
    }
}