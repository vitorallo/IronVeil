<#
.SYNOPSIS
Detects accounts configured for unconstrained delegation which can impersonate any user

.METADATA
{
  "id": "AD-T1-006",
  "name": "Unconstrained Delegation on Any Account",
  "description": "When a computer or user account is configured for unconstrained delegation, it can impersonate any user to any service. This is extremely dangerous as it allows privilege escalation through ticket harvesting. This check identifies all accounts with the Trusted for Delegation attribute enabled.",
  "category": "KerberosAttack",
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
    # Load ADSI helper library
    $helperPath = Join-Path $PSScriptRoot "IronVeil-ADSIHelper.ps1"
    . $helperPath
    
    if (-not $DomainName) {
        throw "Domain name could not be determined"
    }
    
    # Get domain information using ADSI
    $domainInfo = Get-IVDomainInfo -DomainName $DomainName
    $domainDN = $domainInfo.DistinguishedName
    
    # Get list of Domain Controllers (they have unconstrained delegation by default and that's expected)
    $domainControllers = Get-IVADDomainController | Select-Object -ExpandProperty sAMAccountName | ForEach-Object { $_.Replace('$', '') }
    
    # Search for accounts with unconstrained delegation
    # userAccountControl flag 0x80000 (524288) = TRUSTED_FOR_DELEGATION
    # Using LDAP matching rule for bitwise AND
    $filter = "(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))"
    
    # Get both user and computer accounts with unconstrained delegation
    $unconstrainedAccounts = Search-IVADObjects -Filter $filter -Properties @('samAccountName', 'objectClass', 'userAccountControl', 'whenCreated', 'whenChanged', 'servicePrincipalName', 'memberOf', 'distinguishedName', 'description')
    
    foreach ($account in $unconstrainedAccounts) {
        $objType = switch ($account.objectClass) {
            "computer" { "Computer" }
            "user" { "User" }
            default { "Object" }
        }
        
        # Check if this is a Domain Controller (expected to have unconstrained delegation)
        $isDomainController = $false
        if ($objType -eq "Computer") {
            $computerName = $account.Name
            if ($domainControllers -contains $computerName) {
                $isDomainController = $true
            }
        }
        
        # Domain Controllers having unconstrained delegation is expected, but we'll note it at lower severity
        if ($isDomainController) {
            # Still report it but at lower risk
            $findings += @{
                ObjectName = $account.samAccountName
                ObjectType = "DomainController"
                RiskLevel = "Low"
                Description = "Domain Controller has unconstrained delegation (this is expected behavior). While normal, ensure the DC is properly secured as compromise would allow ticket harvesting."
                Remediation = "1. This is expected for Domain Controllers. 2. Ensure DCs are properly hardened. 3. Monitor DC access closely. 4. Implement credential guard where possible. 5. Restrict physical and network access to DCs."
                AffectedAttributes = @("userAccountControl", "TRUSTED_FOR_DELEGATION")
            }
        }
        else {
            # Non-DC with unconstrained delegation is high risk
            $riskLevel = "Critical"
            $riskFactors = @()
            
            # Check how recently this was configured
            $changedValue = if ($account.whenChanged -is [Array]) { $account.whenChanged[0] } else { $account.whenChanged }
            $createdValue = if ($account.whenCreated -is [Array]) { $account.whenCreated[0] } else { $account.whenCreated }
            $changedDate = Convert-IVFileTimeToDateTime -FileTime ([Int64]$changedValue)
            $createdDate = Convert-IVFileTimeToDateTime -FileTime ([Int64]$createdValue)
            $daysSinceChange = if ($changedDate) { ((Get-Date) - $changedDate).Days } else { 0 }
            $daysSinceCreation = if ($createdDate) { ((Get-Date) - $createdDate).Days } else { 0 }
            
            if ($daysSinceChange -lt 30) {
                $riskFactors += "Recently modified ($daysSinceChange days ago)"
            }
            
            if ($daysSinceCreation -lt 30) {
                $riskFactors += "Recently created ($daysSinceCreation days ago)"
            }
            
            # Check if it's a privileged account
            $isPrivileged = $false
            $privilegedGroups = @()
            
            if ($objType -eq "User" -and $account.memberOf) {
                $privGroups = $account.memberOf | Where-Object { 
                    $_ -match "Domain Admins|Enterprise Admins|Schema Admins|Administrators|Account Operators|Backup Operators|Server Operators"
                }
                if ($privGroups) {
                    $isPrivileged = $true
                    foreach ($group in $privGroups) {
                        if ($group -match "CN=([^,]+),") {
                            $privilegedGroups += $Matches[1]
                        }
                    }
                    $riskFactors += "Member of privileged groups: $($privilegedGroups -join ', ')"
                }
            }
            
            # Check if account is enabled
            $isEnabled = $true
            if ($account.enabled -eq $false) {
                $isEnabled = $false
                $riskLevel = "High"  # Lower from Critical if disabled
                $riskFactors += "Account is disabled (reduced risk)"
            }
            
            # Check for specific high-value targets
            if ($objType -eq "Computer") {
                # Check if it's a server with critical services
                if ($account.servicePrincipalName) {
                    $criticalSPNs = $account.servicePrincipalName | Where-Object {
                        $_ -match "(?i)(MSSQL|Exchange|LDAP|HTTP|TERMSRV)"
                    }
                    if ($criticalSPNs) {
                        $riskFactors += "Hosts critical services: $($criticalSPNs -join ', ')"
                    }
                }
                
                # Check if it's in Servers OU or similar
                if ($account.distinguishedName -match "(?i)OU=Servers|OU=Infrastructure") {
                    $riskFactors += "Located in infrastructure OU"
                }
            }
            
            $description = "$objType account has unconstrained delegation enabled, allowing it to impersonate ANY user to ANY service."
            if ($riskFactors.Count -gt 0) {
                $description += " Risk factors: $($riskFactors -join '; ')."
            }
            
            $remediation = if ($objType -eq "Computer") {
                "1. URGENT: Remove unconstrained delegation unless absolutely required. 2. If needed, migrate to constrained delegation or RBCD. 3. This computer can harvest TGTs from any user that authenticates to it. 4. Reset the computer account password. 5. Audit all recent authentications to this system. 6. Check for compromise indicators."
            }
            else {
                "1. CRITICAL: User accounts should NEVER have unconstrained delegation. 2. Remove this permission immediately. 3. Reset the account password. 4. Audit all actions performed by this account. 5. Investigate how this was configured. 6. Consider this account compromised."
            }
            
            $findings += @{
                ObjectName = $account.samAccountName
                ObjectType = $objType
                RiskLevel = $riskLevel
                Description = $description
                Remediation = $remediation
                AffectedAttributes = @("userAccountControl", "TRUSTED_FOR_DELEGATION")
            }
        }
    }
    
    # Check for KRBTGT with unconstrained delegation (should never happen)
    $krbtgtAccount = Get-IVADUser -SamAccountName "krbtgt" -Properties @('userAccountControl')
    $krbtgtUacValue = if ($krbtgtAccount.userAccountControl -is [Array]) { $krbtgtAccount.userAccountControl[0] } else { $krbtgtAccount.userAccountControl }
    if ($krbtgtAccount -and (([int]$krbtgtUacValue) -band 0x80000)) {
        $findings += @{
            ObjectName = "krbtgt"
            ObjectType = "ServiceAccount"
            RiskLevel = "Critical"
            Description = "CATASTROPHIC: KRBTGT account has unconstrained delegation! This should NEVER occur and indicates severe compromise."
            Remediation = "1. IMMEDIATE ACTION REQUIRED. 2. Remove unconstrained delegation from KRBTGT. 3. Reset KRBTGT password TWICE. 4. Consider entire domain compromised. 5. Initiate full incident response. 6. Audit all Kerberos tickets."
            AffectedAttributes = @("userAccountControl", "TRUSTED_FOR_DELEGATION")
        }
    }
    
    # Also check for accounts that might be trying to bypass detection
    # Look for accounts with both SERVER_TRUST_ACCOUNT and TRUSTED_FOR_DELEGATION
    $filter2 = "(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(userAccountControl:1.2.840.113556.1.4.803:=8192))"
    $hiddenDelegation = Search-IVADObjects -Filter $filter2 -Properties @('samAccountName', 'objectClass')
    
    foreach ($account in $hiddenDelegation) {
        # Skip if already reported
        if ($findings | Where-Object { $_.ObjectName -eq $account.samAccountName }) {
            continue
        }
        
        $objType = switch ($account.objectClass) {
            "computer" { "Computer" }
            "user" { "User" }
            default { "Object" }
        }
        
        $findings += @{
            ObjectName = $account.samAccountName
            ObjectType = $objType
            RiskLevel = "High"
            Description = "$objType account has unusual combination of SERVER_TRUST_ACCOUNT and TRUSTED_FOR_DELEGATION flags. This might be an attempt to hide unconstrained delegation."
            Remediation = "1. Investigate this unusual configuration. 2. Review the account's purpose and permissions. 3. Consider removing delegation permissions. 4. Monitor for suspicious activity."
            AffectedAttributes = @("userAccountControl", "SERVER_TRUST_ACCOUNT", "TRUSTED_FOR_DELEGATION")
        }
    }
    
    # Calculate statistics
    $totalUnconstrained = $unconstrainedAccounts.Count
    $nonDCUnconstrained = $totalUnconstrained - @($domainControllers).Count
    
    # Calculate execution time
    $executionTime = ((Get-Date) - $startTime).TotalSeconds
    
    # Determine final score and status
    $score = 100
    $status = "Success"
    $message = "Unconstrained delegation check completed successfully."
    
    if ($findings.Count -gt 0) {
        $criticalCount = @($findings | Where-Object { $_.RiskLevel -eq "Critical" }).Count
        $highCount = @($findings | Where-Object { $_.RiskLevel -eq "High" }).Count
        $lowCount = @($findings | Where-Object { $_.RiskLevel -eq "Low" }).Count
        
        # Check for non-DC unconstrained delegation
        $nonDCFindings = $findings | Where-Object { $_.ObjectType -ne "DomainController" -and $_.RiskLevel -in @("Critical", "High") }
        
        if ($nonDCFindings.Count -gt 0) {
            $score = 0
            $message = "CRITICAL: Found $($nonDCFindings.Count) non-DC accounts with unconstrained delegation! This is a severe security risk allowing privilege escalation."
        }
        elseif ($criticalCount -gt 0) {
            $score = 0
            $message = "CRITICAL: Found $criticalCount critical unconstrained delegation issues requiring immediate remediation."
        }
        elseif ($highCount -gt 0) {
            $score = 25
            $message = "WARNING: Found $highCount high-risk unconstrained delegation configurations."
        }
        else {
            $score = 90
            $message = "Only Domain Controllers have unconstrained delegation (expected). Found $lowCount DCs with standard configuration."
        }
    }
    else {
        $message = "No unconstrained delegation found on any accounts. Environment is properly configured."
    }
    
    return @{
        CheckId = "AD-T1-006"
        Timestamp = (Get-Date).ToString("o")
        Status = $status
        Score = $score
        Severity = "Critical"
        Category = "KerberosAttack"
        Findings = $findings
        Message = $message
        AffectedObjects = $findings.Count
        IgnoredObjects = 0
        Metadata = @{
            Domain = $DomainName
            ExecutionTime = [Math]::Round($executionTime, 2)
            TotalUnconstrainedAccounts = $totalUnconstrained
            NonDCUnconstrainedAccounts = $nonDCUnconstrained
            DomainControllerCount = $domainControllers.Count
            ChecksPerformed = @("Unconstrained Delegation", "KRBTGT Check", "Hidden Delegation")
        }
    }
}
catch {
    return @{
        CheckId = "AD-T1-006"
        Timestamp = (Get-Date).ToString("o")
        Status = "Error"
        Score = 0
        Severity = "Critical"
        Category = "KerberosAttack"
        Findings = @()
        Message = "Error executing unconstrained delegation check: $_"
        AffectedObjects = 0
        IgnoredObjects = 0
        Metadata = @{
            Domain = $DomainName
            ExecutionTime = 0.0
            ErrorDetails = $_.Exception.Message
        }
    }
}