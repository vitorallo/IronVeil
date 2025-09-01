<#
.SYNOPSIS
Detects evidence of Mimikatz DCShadow attacks in Active Directory

.METADATA
{
  "id": "AD-T1-001",
  "name": "Evidence of Mimikatz DCShadow Attack",
  "description": "DCShadow allows attackers to inject arbitrary changes into Active Directory by registering a fake domain controller and using normal AD replication to push malicious changes. This check looks for unusual replication requests, temporary domain controller registrations, and unexpected schema modifications.",
  "category": "PersistenceAndBackdoor",
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
        $DomainName = $env:USERDNSDOMAIN
        if (-not $DomainName) {
            throw "Domain name could not be determined"
        }
    }
    
    # Get domain information using ADSI
    $domainInfo = Get-IVDomainInfo -DomainName $DomainName
    $domainDN = $domainInfo.DistinguishedName
    
    # Check 1: Look for suspicious computer objects that might be fake DCs
    # DCShadow typically creates computer objects with specific attributes
    $suspiciousComputers = @()
    
    # Search for computer objects with server reference but not actual DCs
    $filter = "(&(objectClass=computer)(serverReference=*))"
    $computers = Search-IVADObjects -Filter $filter -Properties @("serverReference", "whenCreated", "whenChanged", "servicePrincipalName", "userAccountControl") -SearchBase $domainDN
    
    # Get list of legitimate domain controllers
    $legitimateDCs = Get-IVADDomainController | Select-Object -ExpandProperty sAMAccountName | ForEach-Object { $_.Replace('$', '') }
    
    foreach ($computer in $computers) {
        $computerName = $computer.name
        if (-not $computerName) {
            $computerName = ($computer.distinguishedName -split ',')[0] -replace '^CN=', ''
        }
        
        # Check if this computer is not in the legitimate DC list
        if ($legitimateDCs -notcontains $computerName) {
            # Additional checks for DCShadow indicators
            $isSuspicious = $false
            $suspicionReasons = @()
            
            # Check if created recently (within last 30 days)
            $createdDate = Convert-IVFileTimeToDateTime -FileTime ([Int64]$computer.whenCreated)
            if ($createdDate) {
                $daysSinceCreation = (Get-Date) - $createdDate
                if ($daysSinceCreation.Days -lt 30) {
                    $isSuspicious = $true
                    $suspicionReasons += "Recently created (within 30 days)"
                }
            }
            
            # Check for DC-like SPNs on non-DC computer
            if ($computer.servicePrincipalName) {
                $dcSpns = $computer.servicePrincipalName | Where-Object { $_ -match "GC/|ldap/|E3514235-4B06-11D1-AB04-00C04FC2DCD2" }
                if ($dcSpns) {
                    $isSuspicious = $true
                    $suspicionReasons += "Has Domain Controller SPNs"
                }
            }
            
            if ($isSuspicious) {
                $findings += @{
                    ObjectName = $computerName
                    ObjectType = "Computer"
                    RiskLevel = "Critical"
                    Description = "Potential DCShadow attack: Computer object with DC attributes but not a legitimate DC. Reasons: $($suspicionReasons -join '; ')"
                    Remediation = "1. Investigate this computer object immediately. 2. Check audit logs for who created this object. 3. If confirmed malicious, disable and remove the object. 4. Reset KRBTGT password twice. 5. Review all recent AD changes."
                    AffectedAttributes = @("serverReference", "servicePrincipalName", "whenCreated")
                }
            }
        }
    }
    
    # Check 2: Look for objects in the Configuration partition that shouldn't be there
    $configDN = $domainInfo.ConfigurationNamingContext
    $sitesContainer = "CN=Sites,$configDN"
    
    # Check for suspicious server objects in Sites container
    $serverFilter = "(objectClass=server)"
    $servers = Search-IVADObjects -Filter $serverFilter -SearchBase $sitesContainer -Properties @("whenCreated", "whenChanged")
    
    foreach ($server in $servers) {
        $serverName = $server.name
        if (-not $serverName) {
            $serverName = ($server.distinguishedName -split ',')[0] -replace '^CN=', ''
        }
        
        # Check if this server is not in the legitimate DC list
        if ($legitimateDCs -notcontains $serverName) {
            $createdDate = Convert-IVFileTimeToDateTime -FileTime ([Int64]$server.whenCreated)
            if ($createdDate) {
                $daysSinceCreation = (Get-Date) - $createdDate
                
                # Flag if created recently and not a known DC
                if ($daysSinceCreation.Days -lt 30) {
                    $findings += @{
                        ObjectName = $serverName
                        ObjectType = "Server"
                        RiskLevel = "Critical"
                        Description = "Suspicious server object in Sites container not matching any legitimate DC, created within last 30 days. This is a strong indicator of DCShadow attack."
                        Remediation = "1. IMMEDIATE ACTION REQUIRED. 2. Investigate who created this server object. 3. Remove the suspicious server object from Sites container. 4. Audit all recent replication metadata. 5. Consider this a confirmed breach and initiate incident response."
                        AffectedAttributes = @("whenCreated", "distinguishedName")
                    }
                }
            }
        }
    }
    
    # Check 3: Look for unusual changes to critical objects
    # Check for recent modifications to schema, configuration, or domain naming contexts
    $criticalObjects = @(
        @{DN = "CN=Schema,$configDN"; Type = "Schema"},
        @{DN = $configDN; Type = "Configuration"},
        @{DN = $domainDN; Type = "Domain"}
    )
    
    foreach ($criticalObj in $criticalObjects) {
        try {
            $obj = Get-IVADObject -DistinguishedName $criticalObj.DN -Properties @("whenChanged", "modifyTimeStamp")
            if ($obj -and $obj.whenChanged) {
                $modifiedDate = Convert-IVFileTimeToDateTime -FileTime ([Int64]$obj.whenChanged)
                if ($modifiedDate) {
                    $daysSinceModification = (Get-Date) - $modifiedDate
                    
                    # Flag if modified very recently (within 7 days) - adjust threshold as needed
                    if ($daysSinceModification.Days -lt 7) {
                        $findings += @{
                            ObjectName = $criticalObj.DN
                            ObjectType = $criticalObj.Type
                            RiskLevel = "High"
                            Description = "Critical AD object recently modified (within 7 days). While this could be legitimate, it should be verified against change management records."
                            Remediation = "1. Verify this change against change management records. 2. Review the specific attributes that were modified. 3. Check audit logs for who made the change. 4. If unauthorized, investigate as potential DCShadow activity."
                            AffectedAttributes = @("whenChanged", "modifyTimeStamp")
                        }
                    }
                }
            }
        }
        catch {
            # Silently continue if we can't access the object
        }
    }
    
    # Check 4: Look for unusual NTDS Service objects
    $ntdsFilter = "(objectClass=nTDSDSA)"
    $ntdsSettings = Search-IVADObjects -Filter $ntdsFilter -SearchBase $configDN -Properties @("whenCreated", "options")
    
    foreach ($ntds in $ntdsSettings) {
        $parentServer = ($ntds.distinguishedName -split ",", 2)[1]
        $serverName = ($parentServer -split "=", 2)[1] -split ",", 2 | Select-Object -First 1
        
        if ($legitimateDCs -notcontains $serverName) {
            $findings += @{
                ObjectName = $serverName
                ObjectType = "NTDS-Settings"
                RiskLevel = "Critical"
                Description = "NTDS Settings object found for non-domain controller. This is a critical indicator of DCShadow attack attempting to register a rogue DC."
                Remediation = "1. CRITICAL: Potential active attack. 2. Immediately remove this NTDS Settings object. 3. Investigate all replication metadata. 4. Reset KRBTGT password twice. 5. Initiate full incident response. 6. Review all AD changes in the last 30 days."
                AffectedAttributes = @("objectClass", "whenCreated", "options")
            }
        }
    }
    
    # Calculate execution time
    $executionTime = ((Get-Date) - $startTime).TotalSeconds
    
    # Determine final score and status
    $score = 100  # Start with perfect score
    $status = "Success"
    $message = "DCShadow attack detection completed successfully."
    
    if ($findings.Count -gt 0) {
        $score = 0  # Critical findings mean score of 0
        $criticalCount = @($findings | Where-Object { $_.RiskLevel -eq "Critical" }).Count
        $highCount = @($findings | Where-Object { $_.RiskLevel -eq "High" }).Count
        
        if ($criticalCount -gt 0) {
            $message = "CRITICAL: Strong indicators of DCShadow attack detected! Found $criticalCount critical and $highCount high-risk indicators. Immediate investigation required."
        }
        else {
            $score = 25  # Only high-risk findings
            $message = "WARNING: Potential DCShadow indicators detected. Found $highCount high-risk indicators requiring investigation."
        }
    }
    else {
        $message = "No evidence of DCShadow attacks detected. Environment appears clean."
    }
    
    return @{
        CheckId = "AD-T1-001"
        Timestamp = (Get-Date).ToString("o")
        Status = $status
        Score = $score
        Severity = "Critical"
        Category = "PersistenceAndBackdoor"
        Findings = $findings
        Message = $message
        AffectedObjects = $findings.Count
        IgnoredObjects = 0
        Metadata = @{
            Domain = $DomainName
            ExecutionTime = [Math]::Round($executionTime, 2)
            LegitimateeDCCount = $legitimateDCs.Count
            ChecksPerformed = @("Suspicious Computers", "Configuration Partition", "Critical Object Modifications", "NTDS Settings")
        }
    }
}
catch {
    return @{
        CheckId = "AD-T1-001"
        Timestamp = (Get-Date).ToString("o")
        Status = "Error"
        Score = 0
        Severity = "Critical"
        Category = "PersistenceAndBackdoor"
        Findings = @()
        Message = "Error executing DCShadow detection: $_"
        AffectedObjects = 0
        IgnoredObjects = 0
        Metadata = @{
            Domain = $DomainName
            ExecutionTime = 0.0
            ErrorDetails = $_.Exception.Message
        }
    }
}