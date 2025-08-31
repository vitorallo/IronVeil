<#
.SYNOPSIS
Detects accounts configured with unconstrained delegation using ADSI (no RSAT required)

.METADATA
{
  "id": "AD-T1-006",
  "name": "Unconstrained Delegation on Any Account",
  "description": "When a computer or user account is configured for unconstrained delegation, it can impersonate any user to any service on any server. This is a highly risky configuration that allows significant lateral movement.",
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

# Load helper library
$helperPath = Join-Path $PSScriptRoot "IronVeil-ADSIHelper.ps1"
if (Test-Path $helperPath) {
    . $helperPath
} else {
    Write-Error "Helper library not found at $helperPath"
    exit 1
}

try {
    $startTime = Get-Date
    $findings = @()
    
    if (-not $DomainName) {
        $computerSystem = Get-WmiObject Win32_ComputerSystem
        $DomainName = $computerSystem.Domain
        if (-not $DomainName) {
            throw "Domain name could not be determined"
        }
    }
    
    # Get domain information using ADSI
    $domainInfo = Get-IVDomainInfo -DomainName $DomainName
    
    Write-Verbose "Checking for unconstrained delegation in domain: $DomainName"
    
    # Get all domain controllers first (they have unconstrained delegation by default)
    $domainControllers = @()
    try {
        # DCs have primaryGroupID=516
        $dcFilter = "(&(objectClass=computer)(primaryGroupID=516))"
        $dcs = Search-IVADObjects -Filter $dcFilter -Properties @('sAMAccountName', 'dNSHostName')
        $domainControllers = $dcs | ForEach-Object { $_.sAMAccountName.ToLower() }
        Write-Verbose "Found $($domainControllers.Count) domain controllers"
    }
    catch {
        Write-Warning "Could not enumerate domain controllers: $_"
    }
    
    # Search for accounts with unconstrained delegation
    # UserAccountControl flag TRUSTED_FOR_DELEGATION = 0x80000 (524288)
    # Using LDAP matching rule for bitwise AND: 1.2.840.113556.1.4.803
    $unconstrainedFilter = "(userAccountControl:1.2.840.113556.1.4.803:=524288)"
    
    Write-Verbose "Searching for accounts with unconstrained delegation..."
    
    # Search for both users and computers with unconstrained delegation
    $properties = @(
        'sAMAccountName',
        'distinguishedName',
        'objectClass',
        'userAccountControl',
        'servicePrincipalName',
        'memberOf',
        'adminCount',
        'lastLogonTimestamp',
        'whenCreated',
        'description'
    )
    
    $unconstrainedAccounts = Search-IVADObjects -Filter $unconstrainedFilter -Properties $properties
    
    Write-Verbose "Found $($unconstrainedAccounts.Count) accounts with unconstrained delegation"
    
    foreach ($account in $unconstrainedAccounts) {
        $accountName = $account.sAMAccountName
        $accountDN = $account.distinguishedName
        $objectClass = if ($account.objectClass -contains 'computer') { 'Computer' } else { 'User' }
        $uac = [int]$account.userAccountControl
        
        # Skip domain controllers (they need unconstrained delegation)
        if ($objectClass -eq 'Computer' -and $accountName.ToLower() -in $domainControllers) {
            Write-Verbose "Skipping domain controller: $accountName"
            continue
        }
        
        # Check if it's the KRBTGT account (critical finding)
        $isKRBTGT = $accountName -eq 'krbtgt'
        
        # Determine risk level based on account type and privileges
        $riskLevel = "High"
        $description = "Account has unconstrained delegation enabled"
        
        # Check for additional risk factors
        $riskFactors = @()
        
        # Check if account is privileged (adminCount=1)
        if ($account.adminCount -eq 1) {
            $riskFactors += "Privileged account (adminCount=1)"
            $riskLevel = "Critical"
        }
        
        # Check if it's a service account (has SPNs)
        if ($account.servicePrincipalName -and $account.servicePrincipalName.Count -gt 0) {
            $spnCount = $account.servicePrincipalName.Count
            $riskFactors += "Service account with $spnCount SPN(s)"
        }
        
        # Check if computer account (non-DC)
        if ($objectClass -eq 'Computer') {
            $riskFactors += "Computer account (potential for compromise)"
            # Check if it's a server OS
            if ($account.operatingSystem -like "*Server*") {
                $riskFactors += "Server operating system"
                $riskLevel = "Critical"
            }
        }
        
        # Check account age
        if ($account.whenCreated) {
            $accountAge = (Get-Date) - [DateTime]$account.whenCreated
            if ($accountAge.Days -lt 30) {
                $riskFactors += "Recently created account (${accountAge.Days} days old)"
            }
        }
        
        # Check last logon
        if ($account.lastLogonTimestamp) {
            $lastLogon = Convert-IVFileTimeToDateTime -FileTime ([Int64]$account.lastLogonTimestamp)
            if ($lastLogon) {
                $daysSinceLogon = (Get-Date) - $lastLogon
                if ($daysSinceLogon.Days -gt 90) {
                    $riskFactors += "Inactive account (last logon ${daysSinceLogon.Days} days ago)"
                }
            }
        }
        
        # Special case for KRBTGT
        if ($isKRBTGT) {
            $riskLevel = "Critical"
            $description = "KRBTGT account has unconstrained delegation - SEVERE SECURITY RISK"
            $riskFactors += "Golden Ticket attack vector"
        }
        
        # Check for additional dangerous UAC flags
        if (Test-IVUserAccountControl -UAC $uac -Flag 'DONT_EXPIRE_PASSWORD') {
            $riskFactors += "Password never expires"
        }
        if (Test-IVUserAccountControl -UAC $uac -Flag 'PASSWD_NOTREQD') {
            $riskFactors += "Password not required"
            $riskLevel = "Critical"
        }
        
        # Build detailed description
        if ($riskFactors.Count -gt 0) {
            $description += " with additional risk factors: " + ($riskFactors -join "; ")
        }
        
        # Create finding
        $finding = @{
            ObjectName = $accountName
            ObjectType = $objectClass
            RiskLevel = $riskLevel
            Description = $description
            Remediation = if ($isKRBTGT) {
                "IMMEDIATELY remove unconstrained delegation from KRBTGT account. This is a critical security vulnerability."
            } elseif ($objectClass -eq 'Computer') {
                "Consider using constrained delegation or removing delegation entirely. If delegation is required, implement Resource-Based Constrained Delegation (RBCD) instead."
            } else {
                "Remove unconstrained delegation from this account. Use constrained delegation if delegation is required."
            }
            AffectedAttributes = @("userAccountControl", "TrustedForDelegation")
            DistinguishedName = $accountDN
            RiskFactors = $riskFactors
            LastLogon = if ($lastLogon) { $lastLogon.ToString("yyyy-MM-dd HH:mm:ss") } else { "Never" }
        }
        
        $findings += $finding
    }
    
    # Calculate score based on findings
    $score = 100
    $criticalCount = ($findings | Where-Object { $_.RiskLevel -eq "Critical" }).Count
    $highCount = ($findings | Where-Object { $_.RiskLevel -eq "High" }).Count
    $mediumCount = ($findings | Where-Object { $_.RiskLevel -eq "Medium" }).Count
    
    # Deduct points based on findings
    $score -= ($criticalCount * 30)  # Critical findings have major impact
    $score -= ($highCount * 15)       # High findings have significant impact
    $score -= ($mediumCount * 5)      # Medium findings have moderate impact
    $score = [Math]::Max(0, $score)
    
    # Determine overall status
    $status = if ($findings.Count -eq 0) { "Success" } else { "Failed" }
    
    # Build summary message
    $message = if ($findings.Count -eq 0) {
        "No accounts with unconstrained delegation found (excluding domain controllers)"
    } else {
        $summary = "Found $($findings.Count) account(s) with unconstrained delegation"
        if ($criticalCount -gt 0) {
            $summary += " including $criticalCount CRITICAL finding(s)"
        }
        $summary
    }
    
    # Check if KRBTGT is affected
    if ($findings | Where-Object { $_.ObjectName -eq 'krbtgt' }) {
        $message = "CRITICAL: KRBTGT has unconstrained delegation! " + $message
    }
    
    $endTime = Get-Date
    $executionTime = ($endTime - $startTime).TotalSeconds
    
    # Return standardized output
    return @{
        CheckId = "AD-T1-006"
        Timestamp = (Get-Date).ToString("o")
        Status = $status
        Score = $score
        Severity = "Critical"
        Category = "PrivilegeEscalation"
        Findings = $findings
        Message = $message
        AffectedObjects = $findings.Count
        IgnoredObjects = $domainControllers.Count
        Metadata = @{
            Domain = $DomainName
            ExecutionTime = [Math]::Round($executionTime, 2)
            DomainControllersExcluded = $domainControllers.Count
            TotalAccountsScanned = $unconstrainedAccounts.Count
            CriticalFindings = $criticalCount
            HighFindings = $highCount
            CheckMethod = "ADSI (No RSAT Required)"
        }
    }
}
catch {
    $endTime = Get-Date
    $executionTime = if ($startTime) { ($endTime - $startTime).TotalSeconds } else { 0 }
    
    return @{
        CheckId = "AD-T1-006"
        Timestamp = (Get-Date).ToString("o")
        Status = "Error"
        Score = 0
        Severity = "Critical"
        Category = "PrivilegeEscalation"
        Findings = @()
        Message = "Error checking unconstrained delegation: $_"
        AffectedObjects = 0
        IgnoredObjects = 0
        Metadata = @{
            Domain = $DomainName
            ExecutionTime = [Math]::Round($executionTime, 2)
            ErrorDetails = $_.Exception.Message
            CheckMethod = "ADSI (No RSAT Required)"
        }
    }
}