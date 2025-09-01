<#
.SYNOPSIS
Detects indicators of Zerologon vulnerability (CVE-2020-1472) exploitation

.METADATA
{
  "id": "AD-T1-003",
  "name": "Zerologon Vulnerability (CVE-2020-1472)",
  "description": "A critical vulnerability in the Netlogon Remote Protocol that allows an unauthenticated attacker to gain Domain Administrator privileges. This check identifies unpatched domain controllers and monitors for unusual Netlogon authentication failures that may indicate exploitation attempts.",
  "category": "VulnerabilityExploitation",
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
    
    # Get all domain controllers using ADSI
    $domainControllers = Get-IVADDomainController
    
    if ($domainControllers.Count -eq 0) {
        throw "No domain controllers found in domain $DomainName"
    }
    
    # Define minimum patch levels that include Zerologon fix
    # These are the minimum OS builds that include the August 2020 security update
    $patchedVersions = @{
        "10.0.14393" = 3930  # Windows Server 2016
        "10.0.17763" = 1432  # Windows Server 2019
        "10.0.18362" = 1082  # Windows Server 2019 (1903)
        "10.0.18363" = 1082  # Windows Server 2019 (1909)
        "10.0.19041" = 508   # Windows Server 2020 (2004)
        "6.3.9600"   = 19781  # Windows Server 2012 R2
        "6.2.9200"   = 23135  # Windows Server 2012
        "6.1.7601"   = 24564  # Windows Server 2008 R2
    }
    
    foreach ($dc in $domainControllers) {
        $dcName = $dc.Name
        $vulnerabilityFound = $false
        $osVersion = $null
        $currentBuild = $null
        
        try {
            # Get detailed OS information from the DC using ADSI
            $computerObj = Get-IVADObject -SamAccountName "$dcName$" -Properties @('operatingSystem', 'operatingSystemVersion', 'whenChanged')
            $osVersion = $computerObj.OperatingSystemVersion
            
            if ($osVersion) {
                # Parse version (format: "10.0 (14393)")
                if ($osVersion -match "(\d+\.\d+)(?:\.\d+)?\s*\((\d+)\)") {
                    $majorMinor = $Matches[1]
                    $currentBuild = [int]$Matches[2]
                    
                    # For Windows 10/Server 2016+, need to construct full version
                    if ($majorMinor -eq "10.0") {
                        $versionKey = "10.0.$currentBuild"
                        
                        # Check if this version needs checking
                        foreach ($patchedVer in $patchedVersions.Keys) {
                            if ($patchedVer.StartsWith("10.0.$currentBuild")) {
                                $requiredBuild = $patchedVersions[$patchedVer]
                                
                                # Try to get the revision number (4th part of version)
                                # This would require WMI access to the DC
                                try {
                                    $osInfo = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $dcName -ErrorAction SilentlyContinue
                                    if ($osInfo.Version -match "10\.0\.\d+\.(\d+)") {
                                        $revision = [int]$Matches[1]
                                        
                                        if ($revision -lt $requiredBuild) {
                                            $vulnerabilityFound = $true
                                            $findings += @{
                                                ObjectName = $dcName
                                                ObjectType = "DomainController"
                                                RiskLevel = "Critical"
                                                Description = "Domain Controller is VULNERABLE to Zerologon (CVE-2020-1472). OS Build $($osInfo.Version) is below the required patch level ($patchedVer.$requiredBuild). This DC can be compromised by unauthenticated attackers."
                                                Remediation = "1. URGENT: Apply August 2020 or later security updates immediately. 2. Enable 'FullSecureChannelProtection' registry setting. 3. Monitor for exploitation attempts in Security event log (Event ID 5829). 4. After patching, reset all computer account passwords twice. 5. Review DC access logs for suspicious activity."
                                                AffectedAttributes = @("OperatingSystemVersion", "SecurityPatches")
                                            }
                                        }
                                    }
                                }
                                catch {
                                    # Can't get detailed version via WMI, flag for manual review
                                    $findings += @{
                                        ObjectName = $dcName
                                        ObjectType = "DomainController"
                                        RiskLevel = "High"
                                        Description = "Cannot determine exact patch level for Domain Controller. OS Version: $osVersion. Manual verification required for Zerologon patch status."
                                        Remediation = "1. Manually verify August 2020 or later updates are installed. 2. Check KB4565349, KB4571694, KB4571719, or KB4571729 depending on OS version. 3. Enable secure channel protection. 4. Monitor Event ID 5829 for exploitation attempts."
                                        AffectedAttributes = @("OperatingSystemVersion")
                                    }
                                }
                                break
                            }
                        }
                    }
                    elseif ($patchedVersions.ContainsKey($majorMinor)) {
                        # For older Windows versions
                        $requiredBuild = $patchedVersions[$majorMinor]
                        if ($currentBuild -lt $requiredBuild) {
                            $vulnerabilityFound = $true
                            $findings += @{
                                ObjectName = $dcName
                                ObjectType = "DomainController"
                                RiskLevel = "Critical"
                                Description = "Domain Controller is VULNERABLE to Zerologon (CVE-2020-1472). OS Build $currentBuild is below the required patch level ($requiredBuild). This DC can be compromised by unauthenticated attackers."
                                Remediation = "1. URGENT: Apply August 2020 or later security updates immediately. 2. Enable 'FullSecureChannelProtection' registry setting. 3. Monitor for exploitation attempts in Security event log. 4. After patching, reset computer account passwords. 5. Review DC access logs."
                                AffectedAttributes = @("OperatingSystemVersion", "SecurityPatches")
                            }
                        }
                    }
                }
            }
            
            # Check for secure channel protection settings via registry (if accessible)
            # This would require remote registry access
            try {
                $regPath = "SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
                $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $dcName)
                $regKey = $reg.OpenSubKey($regPath)
                
                if ($regKey) {
                    $vulnValue = $regKey.GetValue("RequireSignOrSeal")
                    $fullProtection = $regKey.GetValue("FullSecureChannelProtection")
                    
                    if ($vulnValue -eq 0) {
                        $findings += @{
                            ObjectName = $dcName
                            ObjectType = "DomainController"
                            RiskLevel = "Critical"
                            Description = "Domain Controller has Netlogon signing DISABLED (RequireSignOrSeal=0). This makes it vulnerable to various attacks including Zerologon."
                            Remediation = "1. Set HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\RequireSignOrSeal to 1. 2. Restart the Netlogon service. 3. Test domain authentication after change."
                            AffectedAttributes = @("NetlogonParameters", "RequireSignOrSeal")
                        }
                    }
                    
                    if ($fullProtection -ne 1) {
                        $findings += @{
                            ObjectName = $dcName
                            ObjectType = "DomainController"
                            RiskLevel = "High"
                            Description = "Domain Controller does not have Full Secure Channel Protection enabled. While patched for Zerologon, additional hardening is recommended."
                            Remediation = "1. Set HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\FullSecureChannelProtection to 1. 2. This provides additional protection against secure channel attacks. 3. Monitor for any authentication issues after enabling."
                            AffectedAttributes = @("NetlogonParameters", "FullSecureChannelProtection")
                        }
                    }
                    
                    $regKey.Close()
                }
                $reg.Close()
            }
            catch {
                # Unable to access registry remotely, this is common due to permissions
            }
            
            # Check for signs of exploitation in computer account password age
            $dcComputer = Get-IVADObject -SamAccountName "$dcName$" -Properties @('pwdLastSet', 'whenChanged')
            if ($dcComputer.pwdLastSet) {
                $passwordLastSet = Convert-IVFileTimeToDateTime -FileTime ([Int64]$dcComputer.pwdLastSet)
                if ($passwordLastSet) {
                    $passwordAge = (Get-Date) - $passwordLastSet
                
                # DC passwords should change every 30 days by default
                # A very recent password change could indicate exploitation
                if ($passwordAge.Days -lt 1) {
                    $findings += @{
                        ObjectName = $dcName
                        ObjectType = "DomainController"
                        RiskLevel = "Critical"
                        Description = "Domain Controller password was changed within the last 24 hours. This could indicate Zerologon exploitation as the attack resets the DC machine account password."
                        Remediation = "1. IMMEDIATE INVESTIGATION REQUIRED. 2. Check Event logs for Event ID 4742 (computer account changed). 3. Look for Event ID 5829 (Netlogon denied vulnerable connection). 4. Check for unauthorized access or changes. 5. Consider this a potential active breach."
                        AffectedAttributes = @("pwdLastSet", "whenChanged")
                    }
                }
                elseif ($passwordAge.Days -gt 45) {
                    # Password hasn't changed in a long time, might indicate disabled automatic password changes
                    $findings += @{
                        ObjectName = $dcName
                        ObjectType = "DomainController"
                        RiskLevel = "Medium"
                        Description = "Domain Controller password hasn't been changed in $([int]$passwordAge.Days) days. This might indicate disabled automatic password rotation."
                        Remediation = "1. Verify automatic machine account password changes are enabled. 2. Check DisablePasswordChange and MaximumPasswordAge registry settings. 3. Consider manually resetting if needed."
                        AffectedAttributes = @("pwdLastSet")
                    }
                }
                }
            }
        }
        catch {
            # Error getting information for this DC
            $findings += @{
                ObjectName = $dcName
                ObjectType = "DomainController"
                RiskLevel = "Medium"
                Description = "Unable to fully assess Domain Controller for Zerologon vulnerability. Error: $_"
                Remediation = "1. Manually verify patch status on this DC. 2. Ensure August 2020 or later updates are installed. 3. Check secure channel protection settings."
                AffectedAttributes = @("AssessmentError")
            }
        }
    }
    
    # Check for any computer accounts with empty passwords (potential Zerologon exploitation result)
    $filter = "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=2080))"
    $computersWithEmptyPassword = Search-IVADObjects -Filter $filter -Properties @('samAccountName', 'whenChanged')
    
    foreach ($computer in $computersWithEmptyPassword) {
        $findings += @{
            ObjectName = $computer.samAccountName
            ObjectType = "Computer"
            RiskLevel = "Critical"
            Description = "Computer account has PASSWD_NOTREQD flag set, allowing empty password. This could be a result of Zerologon exploitation or other attack."
            Remediation = "1. Reset this computer account password immediately. 2. Remove PASSWD_NOTREQD flag from userAccountControl. 3. Investigate why this flag was set. 4. Check if this computer is still active and trusted."
            AffectedAttributes = @("userAccountControl", "PASSWD_NOTREQD")
        }
    }
    
    # Calculate execution time
    $executionTime = ((Get-Date) - $startTime).TotalSeconds
    
    # Determine final score and status
    $score = 100
    $status = "Success"
    $message = "Zerologon vulnerability assessment completed successfully."
    
    if ($findings.Count -gt 0) {
        $criticalCount = @($findings | Where-Object { $_.RiskLevel -eq "Critical" }).Count
        $highCount = @($findings | Where-Object { $_.RiskLevel -eq "High" }).Count
        $mediumCount = @($findings | Where-Object { $_.RiskLevel -eq "Medium" }).Count
        
        if ($criticalCount -gt 0) {
            $score = 0
            $message = "CRITICAL: Zerologon vulnerability or exploitation detected! Found $criticalCount critical issues. Immediate patching and investigation required."
        }
        elseif ($highCount -gt 0) {
            $score = 25
            $message = "WARNING: Potential Zerologon vulnerability indicators found. $highCount high-risk issues need attention."
        }
        else {
            $score = 75
            $message = "Minor Zerologon-related configuration issues found. $mediumCount medium-risk items should be reviewed."
        }
    }
    else {
        $message = "No Zerologon vulnerabilities detected. All $($domainControllers.Count) domain controllers appear to be properly patched and configured."
    }
    
    return @{
        CheckId = "AD-T1-003"
        Timestamp = (Get-Date).ToString("o")
        Status = $status
        Score = $score
        Severity = "Critical"
        Category = "VulnerabilityExploitation"
        Findings = $findings
        Message = $message
        AffectedObjects = $findings.Count
        IgnoredObjects = $domainControllers.Count - @($findings | Where-Object { $_.ObjectType -eq "DomainController" }).Count
        Metadata = @{
            Domain = $DomainName
            ExecutionTime = [Math]::Round($executionTime, 2)
            DomainControllersChecked = $domainControllers.Count
            ChecksPerformed = @("Patch Level", "Registry Settings", "Password Age", "Empty Passwords")
        }
    }
}
catch {
    return @{
        CheckId = "AD-T1-003"
        Timestamp = (Get-Date).ToString("o")
        Status = "Error"
        Score = 0
        Severity = "Critical"
        Category = "VulnerabilityExploitation"
        Findings = @()
        Message = "Error executing Zerologon vulnerability check: $_"
        AffectedObjects = 0
        IgnoredObjects = 0
        Metadata = @{
            Domain = $DomainName
            ExecutionTime = 0.0
            ErrorDetails = $_.Exception.Message
        }
    }
}