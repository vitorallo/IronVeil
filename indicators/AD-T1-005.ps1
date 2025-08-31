<#
.SYNOPSIS
Detects accounts configured for constrained delegation to the KRBTGT service

.METADATA
{
  "id": "AD-T1-005",
  "name": "Constrained Delegation to KRBTGT",
  "description": "Accounts configured for constrained delegation specifically to the KRBTGT service can obtain tickets for any user, essentially bypassing all Kerberos security. This check examines the msDS-AllowedToDelegateTo attribute for entries related to KRBTGT service.",
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
    Import-Module ActiveDirectory -ErrorAction SilentlyContinue
    
    if (-not $DomainName) {
        throw "Domain name could not be determined"
    }
    
    # Get domain information
    $domain = Get-ADDomain -Identity $DomainName
    $domainDN = $domain.DistinguishedName
    $domainNetBIOS = $domain.NetBIOSName
    
    # Search for any accounts with constrained delegation configured
    # The msDS-AllowedToDelegateTo attribute contains the SPNs the account can delegate to
    $filter = "(msDS-AllowedToDelegateTo=*)"
    $delegatedAccounts = Get-ADObject -LDAPFilter $filter -Properties msDS-AllowedToDelegateTo, samAccountName, objectClass, userAccountControl, whenChanged, memberOf, servicePrincipalName
    
    foreach ($account in $delegatedAccounts) {
        $objType = switch ($account.objectClass) {
            "computer" { "Computer" }
            "user" { "User" }
            default { "Object" }
        }
        
        # Check each SPN in the allowed delegation list
        foreach ($spn in $account.'msDS-AllowedToDelegateTo') {
            # Check if this SPN is related to KRBTGT
            # KRBTGT SPNs typically look like: krbtgt/DOMAIN or krbtgt/DOMAIN.COM
            if ($spn -match "(?i)krbtgt/") {
                # CRITICAL: Constrained delegation to KRBTGT should NEVER be allowed
                $findings += @{
                    ObjectName = $account.samAccountName
                    ObjectType = $objType
                    RiskLevel = "Critical"
                    Description = "CRITICAL SECURITY BREACH: $objType account has constrained delegation to KRBTGT service ($spn)! This allows the account to request tickets as ANY user in the domain, completely bypassing Kerberos security."
                    Remediation = "1. IMMEDIATE ACTION REQUIRED - This is an active compromise! 2. Remove the KRBTGT SPN from msDS-AllowedToDelegateTo immediately. 3. Disable this account temporarily. 4. Reset the account password. 5. Audit all actions performed by this account. 6. Reset KRBTGT password twice. 7. Investigate how this delegation was configured. 8. Initiate incident response procedures."
                    AffectedAttributes = @("msDS-AllowedToDelegateTo", "krbtgt_delegation")
                }
            }
            # Also check for other highly privileged SPNs
            elseif ($spn -match "(?i)(ldap/|cifs/|host/).*\$($domain.DNSRoot)") {
                # Check if it's delegating to a Domain Controller
                $targetServer = $null
                if ($spn -match "(?i)(ldap|cifs|host)/([^/]+)") {
                    $targetServer = $Matches[2].Split('.')[0]
                }
                
                $domainControllers = Get-ADDomainController -Filter * | Select-Object -ExpandProperty Name
                $isDCTarget = $false
                
                if ($targetServer -and $domainControllers -contains $targetServer) {
                    $isDCTarget = $true
                }
                
                if ($isDCTarget) {
                    $findings += @{
                        ObjectName = $account.samAccountName
                        ObjectType = $objType
                        RiskLevel = "High"
                        Description = "$objType account has constrained delegation to Domain Controller services ($spn). This is highly privileged and could be abused for privilege escalation."
                        Remediation = "1. Review if this delegation is absolutely necessary. 2. Document the business justification. 3. Ensure the account is properly secured. 4. Monitor for suspicious use of this delegation. 5. Consider using Resource-Based Constrained Delegation instead. 6. Implement additional monitoring for this account."
                        AffectedAttributes = @("msDS-AllowedToDelegateTo", "dc_delegation")
                    }
                }
            }
        }
        
        # Additional checks for accounts with any constrained delegation
        
        # Check if Protocol Transition is enabled (S4U2Self)
        # This is indicated by the TRUSTED_TO_AUTH_FOR_DELEGATION flag (0x1000000)
        if ($account.userAccountControl -band 0x1000000) {
            $hasKrbtgtDelegation = $account.'msDS-AllowedToDelegateTo' | Where-Object { $_ -match "(?i)krbtgt/" }
            
            if ($hasKrbtgtDelegation) {
                $findings += @{
                    ObjectName = $account.samAccountName
                    ObjectType = $objType
                    RiskLevel = "Critical"
                    Description = "Account with KRBTGT delegation also has Protocol Transition (S4U2Self) enabled! This doubles the attack surface allowing impersonation without user interaction."
                    Remediation = "1. Remove TRUSTED_TO_AUTH_FOR_DELEGATION flag immediately. 2. This combination is extremely dangerous. 3. Review all delegations for this account. 4. Consider this account fully compromised."
                    AffectedAttributes = @("userAccountControl", "TRUSTED_TO_AUTH_FOR_DELEGATION")
                }
            }
            else {
                # Even without KRBTGT, S4U2Self is risky
                $findings += @{
                    ObjectName = $account.samAccountName
                    ObjectType = $objType
                    RiskLevel = "High"
                    Description = "Account has Protocol Transition (S4U2Self) enabled with constrained delegation. This allows the account to obtain tickets on behalf of any user without their credentials."
                    Remediation = "1. Review if Protocol Transition is required. 2. Most scenarios don't need S4U2Self. 3. Consider removing TRUSTED_TO_AUTH_FOR_DELEGATION flag. 4. Implement strict monitoring for this account."
                    AffectedAttributes = @("userAccountControl", "TRUSTED_TO_AUTH_FOR_DELEGATION")
                }
            }
        }
        
        # Check if this is a privileged account with delegation
        $isPrivileged = $false
        if ($objType -eq "User" -and $account.memberOf) {
            $privilegedGroups = $account.memberOf | Where-Object { 
                $_ -match "Domain Admins|Enterprise Admins|Schema Admins|Administrators|Account Operators|Backup Operators"
            }
            if ($privilegedGroups) {
                $isPrivileged = $true
            }
        }
        elseif ($objType -eq "Computer") {
            # Check if it's a Domain Controller
            $domainControllers = Get-ADDomainController -Filter * | Select-Object -ExpandProperty Name
            if ($domainControllers -contains $account.Name) {
                $isPrivileged = $true
            }
        }
        
        if ($isPrivileged -and $account.'msDS-AllowedToDelegateTo'.Count -gt 0) {
            $delegationList = $account.'msDS-AllowedToDelegateTo' -join "; "
            $findings += @{
                ObjectName = $account.samAccountName
                ObjectType = $objType
                RiskLevel = "High"
                Description = "Privileged $objType account has constrained delegation configured. Delegated SPNs: $delegationList. Privileged accounts with delegation pose significant risk."
                Remediation = "1. Review if delegation is necessary for privileged accounts. 2. Consider using a separate, non-privileged service account. 3. Implement strict controls and monitoring. 4. Document the business requirement."
                AffectedAttributes = @("msDS-AllowedToDelegateTo", "privileged_delegation")
            }
        }
    }
    
    # Also check for traditional unconstrained delegation (covered in AD-T1-006 but check KRBTGT specifically here)
    $krbtgtAccount = Get-ADUser -Identity "krbtgt" -Properties userAccountControl, msDS-AllowedToDelegateTo -ErrorAction SilentlyContinue
    
    if ($krbtgtAccount) {
        # Check if KRBTGT has any delegation settings (it shouldn't)
        if ($krbtgtAccount.'msDS-AllowedToDelegateTo') {
            $delegationList = $krbtgtAccount.'msDS-AllowedToDelegateTo' -join "; "
            $findings += @{
                ObjectName = "krbtgt"
                ObjectType = "ServiceAccount"
                RiskLevel = "Critical"
                Description = "KRBTGT account has constrained delegation configured! Delegated to: $delegationList. This should NEVER happen and indicates compromise."
                Remediation = "1. Remove all delegation from KRBTGT immediately. 2. Reset KRBTGT password twice. 3. This is a critical security breach. 4. Initiate incident response."
                AffectedAttributes = @("msDS-AllowedToDelegateTo")
            }
        }
        
        # Check for unconstrained delegation on KRBTGT
        if ($krbtgtAccount.userAccountControl -band 0x80000) {
            $findings += @{
                ObjectName = "krbtgt"
                ObjectType = "ServiceAccount"
                RiskLevel = "Critical"
                Description = "KRBTGT account has UNCONSTRAINED delegation enabled! This is catastrophic and allows complete domain compromise."
                Remediation = "1. Remove unconstrained delegation from KRBTGT immediately. 2. Reset KRBTGT password twice. 3. Consider entire domain compromised. 4. Full incident response required."
                AffectedAttributes = @("userAccountControl", "TRUSTED_FOR_DELEGATION")
            }
        }
    }
    
    # Check for any SPNs that might be trying to impersonate KRBTGT
    $filter = "(servicePrincipalName=*krbtgt*)"
    $suspiciousSPNs = Get-ADObject -LDAPFilter $filter -Properties servicePrincipalName, samAccountName, objectClass
    
    foreach ($obj in $suspiciousSPNs) {
        # Skip the actual KRBTGT account
        if ($obj.samAccountName -eq "krbtgt") {
            continue
        }
        
        $objType = switch ($obj.objectClass) {
            "computer" { "Computer" }
            "user" { "User" }
            default { "Object" }
        }
        
        $spnList = $obj.servicePrincipalName -join "; "
        $findings += @{
            ObjectName = $obj.samAccountName
            ObjectType = $objType
            RiskLevel = "High"
            Description = "$objType account has suspicious KRBTGT-related SPNs: $spnList. This could be an attempt to impersonate or hijack KRBTGT functionality."
            Remediation = "1. Investigate why this account has KRBTGT-related SPNs. 2. Remove suspicious SPNs immediately. 3. Reset account password. 4. Audit all activities from this account."
            AffectedAttributes = @("servicePrincipalName")
        }
    }
    
    # Calculate execution time
    $executionTime = ((Get-Date) - $startTime).TotalSeconds
    
    # Determine final score and status
    $score = 100
    $status = "Success"
    $message = "Constrained delegation to KRBTGT check completed successfully."
    
    if ($findings.Count -gt 0) {
        $criticalCount = @($findings | Where-Object { $_.RiskLevel -eq "Critical" }).Count
        $highCount = @($findings | Where-Object { $_.RiskLevel -eq "High" }).Count
        
        # Check specifically for KRBTGT delegation
        $krbtgtDelegation = $findings | Where-Object { $_.Description -match "(?i)krbtgt.*delegation" -and $_.RiskLevel -eq "Critical" }
        
        if ($krbtgtDelegation) {
            $score = 0
            $message = "CATASTROPHIC: Found constrained delegation to KRBTGT service! This allows complete domain compromise. Found $criticalCount critical issues requiring immediate action."
        }
        elseif ($criticalCount -gt 0) {
            $score = 5
            $message = "CRITICAL: Found $criticalCount critical delegation issues including KRBTGT-related problems."
        }
        elseif ($highCount -gt 0) {
            $score = 30
            $message = "WARNING: Found $highCount high-risk delegation configurations that could be abused for privilege escalation."
        }
        else {
            $score = 75
            $message = "Minor delegation issues found requiring review."
        }
    }
    else {
        if ($delegatedAccounts.Count -gt 0) {
            $message = "No constrained delegation to KRBTGT detected. Found $($delegatedAccounts.Count) accounts with constrained delegation to other services (normal)."
            $score = 95  # Small deduction for having delegation at all
        }
        else {
            $message = "No constrained delegation configured in the domain. KRBTGT service is properly protected."
        }
    }
    
    return @{
        CheckId = "AD-T1-005"
        Timestamp = (Get-Date).ToString("o")
        Status = $status
        Score = $score
        Severity = "Critical"
        Category = "KerberosAttack"
        Findings = $findings
        Message = $message
        AffectedObjects = $findings.Count
        IgnoredObjects = $delegatedAccounts.Count - @($findings | Where-Object { $_.AffectedAttributes -contains "msDS-AllowedToDelegateTo" }).Count
        Metadata = @{
            Domain = $DomainName
            ExecutionTime = [Math]::Round($executionTime, 2)
            TotalDelegatedAccounts = $delegatedAccounts.Count
            ChecksPerformed = @("KRBTGT Delegation", "Protocol Transition", "Privileged Delegation", "Suspicious SPNs")
        }
    }
}
catch {
    return @{
        CheckId = "AD-T1-005"
        Timestamp = (Get-Date).ToString("o")
        Status = "Error"
        Score = 0
        Severity = "Critical"
        Category = "KerberosAttack"
        Findings = @()
        Message = "Error executing constrained delegation to KRBTGT check: $_"
        AffectedObjects = 0
        IgnoredObjects = 0
        Metadata = @{
            Domain = $DomainName
            ExecutionTime = 0.0
            ErrorDetails = $_.Exception.Message
        }
    }
}