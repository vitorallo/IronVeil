<#
.SYNOPSIS
Detects Resource-Based Constrained Delegation configured on the KRBTGT account

.METADATA
{
  "id": "AD-T1-004",
  "name": "KRBTGT Account with Resource-Based Constrained Delegation",
  "description": "When Resource-Based Constrained Delegation (RBCD) is configured on the KRBTGT account, it allows attackers to generate TGS requests as any user, essentially compromising the entire Kerberos authentication system. This check examines the msDS-AllowedToActOnBehalfOfOtherIdentity attribute on the KRBTGT account.",
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
    
    # Load ADSI helper library
    $helperPath = Join-Path $PSScriptRoot "IronVeil-ADSIHelper.ps1"
    . $helperPath
    
    if (-not $DomainName) {
        throw "Domain name could not be determined"
    }
    
    # Get domain information using ADSI
    $domainInfo = Get-IVDomainInfo -DomainName $DomainName
    $domainDN = $domainInfo.DistinguishedName
    
    # Get the KRBTGT account using ADSI
    $krbtgtAccount = Get-IVADUser -SamAccountName "krbtgt" -Properties @('msDS-AllowedToActOnBehalfOfOtherIdentity', 'whenChanged', 'pwdLastSet', 'userAccountControl', 'description')
    
    if (-not $krbtgtAccount) {
        throw "Unable to find KRBTGT account in domain $DomainName"
    }
    
    # Check if RBCD is configured on KRBTGT
    if ($krbtgtAccount.'msDS-AllowedToActOnBehalfOfOtherIdentity') {
        # CRITICAL: RBCD should NEVER be configured on KRBTGT
        $allowedPrincipals = @()
        
        try {
            # Parse the security descriptor to identify allowed principals
            $descriptor = $krbtgtAccount.'msDS-AllowedToActOnBehalfOfOtherIdentity'
            $securityDescriptor = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $descriptor, 0
            
            foreach ($ace in $securityDescriptor.DiscretionaryAcl) {
                if ($ace.AceType -eq "AccessAllowed") {
                    $sid = $ace.SecurityIdentifier.Value
                    
                    # Try to resolve the SID to a name
                    try {
                        $principal = Search-IVADObjects -Filter "(objectSid=$sid)" -Properties @('samAccountName', 'distinguishedName') | Select-Object -First 1
                        if ($principal) {
                            $allowedPrincipals += @{
                                Name = $principal.samAccountName
                                DN = $principal.distinguishedName
                                SID = $sid
                            }
                        }
                        else {
                            $allowedPrincipals += @{
                                Name = "Unknown"
                                DN = "Unable to resolve"
                                SID = $sid
                            }
                        }
                    }
                    catch {
                        $allowedPrincipals += @{
                            Name = "Error resolving"
                            DN = "Error"
                            SID = $sid
                        }
                    }
                }
            }
        }
        catch {
            $allowedPrincipals += @{
                Name = "Unable to parse"
                DN = "Parse error"
                SID = "Unknown"
            }
        }
        
        $principalList = ($allowedPrincipals | ForEach-Object { "$($_.Name) ($($_.SID))" }) -join "; "
        
        $findings += @{
            ObjectName = "krbtgt"
            ObjectType = "ServiceAccount"
            RiskLevel = "Critical"
            Description = "CRITICAL SECURITY BREACH: Resource-Based Constrained Delegation is configured on the KRBTGT account! This allows complete compromise of Kerberos authentication. Allowed principals: $principalList. This configuration allows these principals to impersonate ANY user in the domain."
            Remediation = "1. IMMEDIATE ACTION REQUIRED - This is an active compromise! 2. Clear the msDS-AllowedToActOnBehalfOfOtherIdentity attribute on KRBTGT immediately. 3. Reset the KRBTGT password TWICE (wait 10+ hours between resets). 4. Audit all Kerberos tickets issued recently. 5. Investigate how this configuration was set. 6. Consider all domain authentication compromised. 7. Initiate full incident response procedures."
            AffectedAttributes = @("msDS-AllowedToActOnBehalfOfOtherIdentity")
        }
    }
    
    # Additional checks for KRBTGT account security
    
    # Check KRBTGT password age
    if ($krbtgtAccount.pwdLastSet) {
        $pwdLastSetValue = if ($krbtgtAccount.pwdLastSet -is [Array]) { $krbtgtAccount.pwdLastSet[0] } else { $krbtgtAccount.pwdLastSet }
        $passwordLastSet = Convert-IVFileTimeToDateTime -FileTime ([Int64]$pwdLastSetValue)
        if ($passwordLastSet) {
            $passwordAge = (Get-Date) - $passwordLastSet
        
        if ($passwordAge.Days -gt 180) {
            # Microsoft recommends changing KRBTGT password periodically
            $findings += @{
                ObjectName = "krbtgt"
                ObjectType = "ServiceAccount"
                RiskLevel = "High"
                Description = "KRBTGT account password hasn't been changed in $([int]$passwordAge.Days) days. Old KRBTGT passwords can be exploited for Golden Ticket attacks even after remediation."
                Remediation = "1. Plan KRBTGT password reset during maintenance window. 2. Reset KRBTGT password twice, waiting 10+ hours between resets. 3. This invalidates any potential Golden Tickets. 4. Document the reset for future reference. 5. Implement regular KRBTGT password rotation policy (every 180 days recommended)."
                AffectedAttributes = @("pwdLastSet")
            }
        }
        elseif ($passwordAge.Hours -lt 24) {
            # Very recent password change could indicate compromise or remediation
            $findings += @{
                ObjectName = "krbtgt"
                ObjectType = "ServiceAccount"
                RiskLevel = "High"
                Description = "KRBTGT account password was changed within the last 24 hours. While this could be legitimate maintenance, it requires verification as it could indicate recent compromise or ongoing incident response."
                Remediation = "1. Verify this password change was authorized and documented. 2. If unauthorized, treat as active compromise. 3. Check audit logs for who made the change. 4. Ensure proper double-reset procedure was followed if this was remediation."
                AffectedAttributes = @("pwdLastSet", "whenChanged")
            }
        }
        }
    }
    
    # Check if KRBTGT is enabled (it should be disabled in most cases)
    $uacValue = if ($krbtgtAccount.userAccountControl -is [Array]) { $krbtgtAccount.userAccountControl[0] } else { $krbtgtAccount.userAccountControl }
    if (-not (Test-IVUserAccountControl -UAC ([int]$uacValue) -Flag 'ACCOUNTDISABLE')) {
        $findings += @{
            ObjectName = "krbtgt"
            ObjectType = "ServiceAccount"
            RiskLevel = "Medium"
            Description = "KRBTGT account is enabled. While this is the default, Microsoft recommends disabling this account as it's only used internally by the KDC service."
            Remediation = "1. Consider disabling the KRBTGT account for additional security. 2. This account is only used internally and doesn't need to be enabled. 3. Test in non-production environment first."
            AffectedAttributes = @("Enabled")
        }
    }
    
    # Check for any other accounts with RBCD configured (comprehensive check)
    $filter = "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)"
    $accountsWithRBCD = Search-IVADObjects -Filter $filter -Properties @('msDS-AllowedToActOnBehalfOfOtherIdentity', 'samAccountName', 'objectClass', 'whenChanged')
    
    foreach ($account in $accountsWithRBCD) {
        # Skip if we already reported on KRBTGT
        if ($account.samAccountName -eq "krbtgt") {
            continue
        }
        
        $objType = switch ($account.objectClass) {
            "computer" { "Computer" }
            "user" { "User" }
            default { "Object" }
        }
        
        # Determine risk level based on account type and privileges
        $riskLevel = "Medium"
        $isPrivileged = $false
        
        # Check if it's a Domain Controller
        $domainControllers = Get-IVADDomainController | Select-Object -ExpandProperty sAMAccountName | ForEach-Object { $_.Replace('$', '') }
        if ($objType -eq "Computer" -and $domainControllers -contains $account.samAccountName.Replace('$', '')) {
            $riskLevel = "High"
            $isPrivileged = $true
        }
        
        # Check if it's a privileged user/service account
        if ($objType -eq "User") {
            $user = Get-IVADUser -SamAccountName $account.samAccountName -Properties @('memberOf')
            if ($user.memberOf) {
                $privilegedGroups = $user.memberOf | Where-Object { 
                    $_ -match "Domain Admins|Enterprise Admins|Schema Admins|Administrators"
                }
                if ($privilegedGroups) {
                    $riskLevel = "High"
                    $isPrivileged = $true
                }
            }
        }
        
        $whenChangedValue = if ($account.whenChanged -is [Array]) { $account.whenChanged[0] } else { $account.whenChanged }
        $changedDate = Convert-IVFileTimeToDateTime -FileTime ([Int64]$whenChangedValue)
        $daysSinceChange = if ($changedDate) { ((Get-Date) - $changedDate).Days } else { 0 }
        
        $description = "$objType account has Resource-Based Constrained Delegation configured."
        if ($isPrivileged) {
            $description += " This is a PRIVILEGED account, increasing the risk."
        }
        if ($daysSinceChange -lt 30) {
            $description += " Configuration was modified within the last $daysSinceChange days."
        }
        
        $findings += @{
            ObjectName = $account.samAccountName
            ObjectType = $objType
            RiskLevel = $riskLevel
            Description = $description
            Remediation = "1. Review if RBCD is legitimately needed for this account. 2. Document the business justification if required. 3. Ensure only specific, necessary principals are allowed. 4. Consider using traditional constrained delegation if possible. 5. Monitor this account for suspicious delegation usage."
            AffectedAttributes = @("msDS-AllowedToActOnBehalfOfOtherIdentity")
        }
    }
    
    # Calculate execution time
    $executionTime = ((Get-Date) - $startTime).TotalSeconds
    
    # Determine final score and status
    $score = 100
    $status = "Success"
    $message = "KRBTGT RBCD security check completed successfully."
    
    if ($findings.Count -gt 0) {
        $criticalCount = @($findings | Where-Object { $_.RiskLevel -eq "Critical" }).Count
        $highCount = @($findings | Where-Object { $_.RiskLevel -eq "High" }).Count
        $mediumCount = @($findings | Where-Object { $_.RiskLevel -eq "Medium" }).Count
        
        # Check specifically for KRBTGT RBCD
        $krbtgtRBCD = $findings | Where-Object { $_.ObjectName -eq "krbtgt" -and $_.Description -match "Resource-Based Constrained Delegation" }
        
        if ($krbtgtRBCD) {
            $score = 0
            $message = "CATASTROPHIC: KRBTGT account has RBCD configured! This is an ACTIVE COMPROMISE allowing complete domain takeover. Immediate incident response required!"
        }
        elseif ($criticalCount -gt 0) {
            $score = 10
            $message = "CRITICAL: Found $criticalCount critical KRBTGT security issues requiring immediate attention."
        }
        elseif ($highCount -gt 0) {
            $score = 25
            $message = "WARNING: Found $highCount high-risk issues with KRBTGT or RBCD configuration needing attention."
        }
        else {
            $score = 75
            $message = "Minor RBCD configuration issues found. $mediumCount medium-risk items should be reviewed."
        }
    }
    else {
        $message = "KRBTGT account is secure. No Resource-Based Constrained Delegation found on KRBTGT. Total of $($accountsWithRBCD.Count) accounts have RBCD configured in the domain."
    }
    
    return @{
        CheckId = "AD-T1-004"
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
            KRBTGTPasswordAge = if ($krbtgtAccount.pwdLastSet) { $pwdValue = if ($krbtgtAccount.pwdLastSet -is [Array]) { $krbtgtAccount.pwdLastSet[0] } else { $krbtgtAccount.pwdLastSet }; $passwordLastSet = Convert-IVFileTimeToDateTime -FileTime ([Int64]$pwdValue); if ($passwordLastSet) { [int]((Get-Date) - $passwordLastSet).Days } else { "Unknown" } } else { "Unknown" }
            TotalRBCDAccounts = $accountsWithRBCD.Count
            ChecksPerformed = @("KRBTGT RBCD", "KRBTGT Password Age", "KRBTGT Status", "Domain-wide RBCD")
        }
    }
}
catch {
    return @{
        CheckId = "AD-T1-004"
        Timestamp = (Get-Date).ToString("o")
        Status = "Error"
        Score = 0
        Severity = "Critical"
        Category = "KerberosAttack"
        Findings = @()
        Message = "Error executing KRBTGT RBCD check: $_"
        AffectedObjects = 0
        IgnoredObjects = 0
        Metadata = @{
            Domain = $DomainName
            ExecutionTime = 0.0
            ErrorDetails = $_.Exception.Message
        }
    }
}