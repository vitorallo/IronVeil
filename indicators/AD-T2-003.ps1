<#
.SYNOPSIS
Detects if Print Spooler service is enabled on Domain Controllers

.METADATA
{
  "id": "AD-T2-003",
  "name": "Print Spooler Enabled on Domain Controllers",
  "description": "The Print Spooler service, when enabled on Domain Controllers, exposes them to vulnerabilities like PrintNightmare (CVE-2021-34527) and other print spooler exploits that can lead to privilege escalation and remote code execution.",
  "category": "VulnerableConfiguration",
  "severity": "High",
  "weight": 7,
  "impact": 8,
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
    
    # Get all domain controllers
    try {
        $domainControllers = Get-ADDomainController -Filter * -Server $DomainName
    }
    catch {
        throw "Unable to retrieve domain controllers: $_"
    }
    
    if ($domainControllers.Count -eq 0) {
        throw "No domain controllers found in domain $DomainName"
    }
    
    $totalDCs = $domainControllers.Count
    $dcChecked = 0
    $dcWithSpooler = 0
    $dcUnavailable = 0
    
    foreach ($dc in $domainControllers) {
        $dcName = $dc.HostName
        $dcShortName = $dc.Name
        
        try {
            # Check if DC is reachable
            $pingResult = Test-Connection -ComputerName $dcName -Count 1 -Quiet
            
            if (-not $pingResult) {
                $dcUnavailable++
                $findings += @{
                    ObjectName = $dcName
                    ObjectType = "DomainController"
                    RiskLevel = "Medium"
                    Description = "Domain Controller is unreachable. Cannot verify Print Spooler status. This DC might be offline or network connectivity issues exist."
                    Remediation = "1. Verify network connectivity to this DC. 2. If DC is online, check firewall rules. 3. Once accessible, verify Print Spooler is disabled."
                    AffectedAttributes = @("ServiceStatus", "Connectivity")
                }
                continue
            }
            
            # Check Print Spooler service status using WMI
            $service = $null
            try {
                $service = Get-WmiObject -Class Win32_Service -ComputerName $dcName -Filter "Name='Spooler'" -ErrorAction Stop
            }
            catch {
                # Try alternative method using Get-Service
                try {
                    $service = Get-Service -Name Spooler -ComputerName $dcName -ErrorAction Stop
                }
                catch {
                    # If both methods fail, try using remote registry
                    $regKey = $null
                    try {
                        $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $dcName)
                        $regKey = $reg.OpenSubKey("SYSTEM\\CurrentControlSet\\Services\\Spooler")
                        if ($regKey) {
                            $startType = $regKey.GetValue("Start")
                            $service = @{
                                State = if ($startType -eq 4) { "Disabled" } else { "Unknown" }
                                StartMode = switch ($startType) {
                                    2 { "Automatic" }
                                    3 { "Manual" }
                                    4 { "Disabled" }
                                    default { "Unknown" }
                                }
                            }
                        }
                    }
                    catch {
                        # Cannot determine service status
                        $findings += @{
                            ObjectName = $dcName
                            ObjectType = "DomainController"
                            RiskLevel = "Medium"
                            Description = "Unable to determine Print Spooler service status on this Domain Controller. Access denied or insufficient permissions."
                            Remediation = "1. Manually check Print Spooler status on this DC. 2. Ensure it is disabled. 3. Grant necessary permissions for monitoring if needed."
                            AffectedAttributes = @("ServiceStatus", "Permissions")
                        }
                        continue
                    }
                    finally {
                        if ($regKey) { $regKey.Close() }
                        if ($reg) { $reg.Close() }
                    }
                }
            }
            
            $dcChecked++
            
            if ($service) {
                $serviceState = if ($service.State) { $service.State } elseif ($service.Status) { $service.Status } else { "Unknown" }
                $serviceStartMode = if ($service.StartMode) { $service.StartMode } elseif ($service.StartType) { $service.StartType } else { "Unknown" }
                
                # Check if service is not disabled
                if ($serviceStartMode -ne "Disabled" -and $serviceState -ne "Disabled") {
                    $dcWithSpooler++
                    
                    $riskLevel = "High"
                    $description = "Print Spooler service is enabled on Domain Controller. Current state: $serviceState, Start mode: $serviceStartMode. "
                    
                    # Determine specific risk based on service state
                    if ($serviceState -eq "Running" -or $serviceState -eq "Started") {
                        $riskLevel = "Critical"
                        $description += "SERVICE IS CURRENTLY RUNNING! This DC is actively vulnerable to PrintNightmare and other print spooler exploits."
                    }
                    elseif ($serviceStartMode -eq "Automatic" -or $serviceStartMode -eq "Auto") {
                        $riskLevel = "High"
                        $description += "Service is set to start automatically. DC will be vulnerable after next reboot."
                    }
                    else {
                        $description += "Service can be manually started, creating an attack vector."
                    }
                    
                    # Check if this is a specific DC role that might need printing (unlikely but possible)
                    $operationMasterRoles = $dc.OperationMasterRoles
                    if ($operationMasterRoles -and $operationMasterRoles.Count -gt 0) {
                        $description += " This DC holds FSMO roles: $($operationMasterRoles -join ', ')."
                    }
                    
                    $findings += @{
                        ObjectName = $dcName
                        ObjectType = "DomainController"
                        RiskLevel = $riskLevel
                        Description = $description
                        Remediation = "1. IMMEDIATELY disable the Print Spooler service: Stop-Service -Name Spooler; Set-Service -Name Spooler -StartupType Disabled. 2. Apply this via GPO to all DCs. 3. Install latest security updates. 4. Review why Print Spooler was enabled. 5. Check event logs for any exploitation attempts. 6. Domain Controllers should NEVER need the Print Spooler service."
                        AffectedAttributes = @("ServiceStatus", "ServiceStartMode", "SecurityVulnerability")
                    }
                }
            }
        }
        catch {
            $findings += @{
                ObjectName = $dcName
                ObjectType = "DomainController"
                RiskLevel = "Medium"
                Description = "Error checking Print Spooler service status: $_"
                Remediation = "1. Manually verify Print Spooler status on this DC. 2. Ensure proper permissions for service querying. 3. Disable Print Spooler if enabled."
                AffectedAttributes = @("ServiceStatus", "ErrorCondition")
            }
        }
    }
    
    # Calculate execution time
    $executionTime = ((Get-Date) - $startTime).TotalSeconds
    
    # Determine final score and status
    $score = 100  # Start with perfect score
    $status = "Success"
    $message = "Print Spooler service check completed on domain controllers."
    
    if ($dcWithSpooler -gt 0) {
        # Critical issue - Print Spooler should never be enabled on DCs
        $score = [Math]::Max(0, 100 - ($dcWithSpooler * 50))
        
        $criticalCount = @($findings | Where-Object { $_.RiskLevel -eq "Critical" }).Count
        if ($criticalCount -gt 0) {
            $score = 0  # Any running Print Spooler is critical
            $message = "CRITICAL: Print Spooler is RUNNING on $criticalCount domain controller(s)! Immediate action required to prevent PrintNightmare exploitation."
        }
        else {
            $message = "WARNING: Print Spooler is enabled (but not running) on $dcWithSpooler of $totalDCs domain controllers. These are vulnerable to exploitation."
        }
    }
    elseif ($dcUnavailable -gt 0) {
        $score = 75  # Can't verify all DCs
        $message = "Print Spooler check completed. $dcChecked of $totalDCs DCs verified clean. Unable to check $dcUnavailable DC(s)."
    }
    else {
        $message = "Excellent! Print Spooler service is properly disabled on all $totalDCs domain controllers."
    }
    
    return @{
        CheckId = "AD-T2-003"
        Timestamp = (Get-Date).ToString("o")
        Status = $status
        Score = $score
        Severity = "High"
        Category = "VulnerableConfiguration"
        Findings = $findings
        Message = $message
        AffectedObjects = $findings.Count
        IgnoredObjects = 0
        Metadata = @{
            Domain = $DomainName
            ExecutionTime = [Math]::Round($executionTime, 2)
            TotalDomainControllers = $totalDCs
            DCsChecked = $dcChecked
            DCsWithSpoolerEnabled = $dcWithSpooler
            DCsUnavailable = $dcUnavailable
        }
    }
}
catch {
    return @{
        CheckId = "AD-T2-003"
        Timestamp = (Get-Date).ToString("o")
        Status = "Error"
        Score = 0
        Severity = "High"
        Category = "VulnerableConfiguration"
        Findings = @()
        Message = "Error executing Print Spooler check: $_"
        AffectedObjects = 0
        IgnoredObjects = 0
        Metadata = @{
            Domain = $DomainName
            ExecutionTime = 0.0
            ErrorDetails = $_.Exception.Message
        }
    }
}