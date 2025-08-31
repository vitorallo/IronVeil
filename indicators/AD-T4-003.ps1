<#
.SYNOPSIS
Checks if Domain Controllers have sufficient event log retention periods

.METADATA
{
  "id": "AD-T4-003",
  "name": "Domain Controller Event Log Retention Too Short",
  "description": "Domain controllers have insufficient event log retention periods, limiting forensic and security monitoring capabilities",
  "category": "Logging",
  "severity": "Low",
  "weight": 3,
  "impact": 4,
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
    
    # Define minimum recommended sizes (in MB) and retention settings
    $minLogSizes = @{
        'Security' = 1024  # 1GB minimum for Security log
        'System' = 256     # 256MB minimum for System log
        'Application' = 256 # 256MB minimum for Application log
        'Directory Service' = 512 # 512MB minimum for Directory Service log
        'DNS Server' = 256  # 256MB minimum for DNS Server log
    }
    
    # Get all domain controllers
    $domainControllers = Get-ADDomainController -Filter * -Server $DomainName -ErrorAction Stop
    
    foreach ($dc in $domainControllers) {
        try {
            $dcName = $dc.HostName
            Write-Verbose "Checking event log configuration on $dcName"
            
            # Check each important event log
            foreach ($logName in $minLogSizes.Keys) {
                try {
                    # Get event log configuration using WMI
                    $log = Get-WmiObject -Class Win32_NTEventLogFile -ComputerName $dcName -Filter "LogFileName='$logName'" -ErrorAction Stop
                    
                    if ($log) {
                        $maxSizeMB = [Math]::Round($log.MaxFileSize / 1MB, 2)
                        $recommendedSize = $minLogSizes[$logName]
                        
                        # Check if log size is insufficient
                        if ($maxSizeMB -lt $recommendedSize) {
                            $findings += @{
                                ObjectName = "$dcName - $logName Log"
                                ObjectType = "EventLog"
                                RiskLevel = if ($logName -eq 'Security') { "Medium" } else { "Low" }
                                Description = "$logName event log on $dcName is only $maxSizeMB MB (recommended minimum: $recommendedSize MB)"
                                Remediation = "Increase $logName log maximum size using Event Viewer or GPO: Computer Configuration > Windows Settings > Security Settings > Event Log > Maximum $logName log size"
                                AffectedAttributes = @("MaxFileSize", "LogFileName")
                            }
                            $affectedCount++
                            $score -= if ($logName -eq 'Security') { 15 } else { 5 }
                        }
                        
                        # Check retention policy (OverWritePolicy: 0=OverwriteAsNeeded, 1=OverwriteOlder, 2=DoNotOverwrite)
                        if ($log.OverWritePolicy -eq "WhenNeeded" -or $log.OverWritePolicy -eq 0) {
                            $findings += @{
                                ObjectName = "$dcName - $logName Log"
                                ObjectType = "EventLog"
                                RiskLevel = "Low"
                                Description = "$logName log is set to overwrite events as needed, potentially losing important security events"
                                Remediation = "Configure log to 'Archive the log when full' or 'Overwrite events older than X days' via Group Policy"
                                AffectedAttributes = @("OverWritePolicy")
                            }
                            $affectedCount++
                            $score -= 5
                        }
                        
                        # Check if log is full or nearly full
                        if ($log.FileSize -and $log.MaxFileSize) {
                            $percentFull = ($log.FileSize / $log.MaxFileSize) * 100
                            if ($percentFull -gt 90) {
                                $findings += @{
                                    ObjectName = "$dcName - $logName Log"
                                    ObjectType = "EventLog"
                                    RiskLevel = "Low"
                                    Description = "$logName log is $([Math]::Round($percentFull, 1))% full on $dcName"
                                    Remediation = "Clear or archive the log, and increase maximum size or implement log forwarding to a SIEM"
                                    AffectedAttributes = @("FileSize", "MaxFileSize")
                                }
                                $affectedCount++
                                $score -= 3
                            }
                        }
                    }
                } catch {
                    # Try alternative method using Get-EventLog
                    try {
                        $eventLog = Get-EventLog -List -ComputerName $dcName | Where-Object { $_.Log -eq $logName }
                        if ($eventLog) {
                            $maxSizeMB = [Math]::Round($eventLog.MaximumKilobytes / 1024, 2)
                            $recommendedSize = $minLogSizes[$logName]
                            
                            if ($maxSizeMB -lt $recommendedSize) {
                                $findings += @{
                                    ObjectName = "$dcName - $logName Log"
                                    ObjectType = "EventLog"
                                    RiskLevel = if ($logName -eq 'Security') { "Medium" } else { "Low" }
                                    Description = "$logName event log on $dcName is only $maxSizeMB MB (recommended minimum: $recommendedSize MB)"
                                    Remediation = "Increase $logName log maximum size to at least $recommendedSize MB"
                                    AffectedAttributes = @("MaximumKilobytes")
                                }
                                $affectedCount++
                                $score -= if ($logName -eq 'Security') { 15 } else { 5 }
                            }
                        }
                    } catch {
                        Write-Verbose "Could not check $logName log on $dcName using alternative method"
                    }
                }
            }
            
            # Check for audit policy (advanced check)
            try {
                # Check if advanced audit policy is configured
                $auditPol = Invoke-Command -ComputerName $dcName -ScriptBlock {
                    auditpol /get /category:* 2>$null
                } -ErrorAction SilentlyContinue
                
                if (-not $auditPol -or $auditPol -match "No auditing") {
                    $findings += @{
                        ObjectName = $dcName
                        ObjectType = "DomainController"
                        RiskLevel = "Medium"
                        Description = "Advanced audit policies may not be properly configured on $dcName"
                        Remediation = "Configure Advanced Audit Policy via GPO: Computer Configuration > Windows Settings > Security Settings > Advanced Audit Policy Configuration"
                        AffectedAttributes = @("AuditPolicy")
                    }
                    $affectedCount++
                    $score -= 10
                }
            } catch {
                Write-Verbose "Could not check audit policy on $dcName"
            }
            
        } catch {
            $ignoredCount++
            Write-Warning "Could not check event logs on $dcName: $_"
        }
    }
    
    # Check for centralized logging
    $centralizedLogging = $false
    try {
        # Check if there's evidence of log forwarding (simplified check)
        $eventForwarding = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Forwarding/Operational'; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 1 -ErrorAction SilentlyContinue
        if ($eventForwarding) {
            $centralizedLogging = $true
            Write-Verbose "Event forwarding appears to be configured"
        }
    } catch {
        Write-Verbose "Could not determine if centralized logging is configured"
    }
    
    if (-not $centralizedLogging -and $domainControllers.Count -gt 1) {
        $findings += @{
            ObjectName = $domain.DNSRoot
            ObjectType = "Domain"
            RiskLevel = "Low"
            Description = "No evidence of centralized event log collection for domain controllers"
            Remediation = "Implement Windows Event Forwarding (WEF) or deploy a SIEM solution for centralized log collection and retention"
            AffectedAttributes = @("EventForwarding")
        }
        $score -= 10
    }
    
    # Ensure score doesn't go below 0
    $score = [Math]::Max(0, $score)
    
    # Determine overall status
    $status = if ($findings.Count -eq 0) { "Success" } 
              elseif ($score -lt 50) { "Failed" } 
              else { "Warning" }
    
    $message = if ($findings.Count -eq 0) {
        "All domain controllers have appropriate event log retention settings"
    } else {
        "Found $($findings.Count) event log retention issues across $affectedCount configurations"
    }
    
    $executionTime = (Get-Date) - $startTime
    
    return @{
        CheckId = "AD-T4-003"
        Timestamp = (Get-Date).ToString("o")
        Status = $status
        Score = $score
        Severity = "Low"
        Category = "Logging"
        Findings = $findings
        Message = $message
        AffectedObjects = $affectedCount
        IgnoredObjects = $ignoredCount
        Metadata = @{
            Domain = $DomainName
            ExecutionTime = $executionTime.TotalSeconds
            DomainControllersChecked = $domainControllers.Count
            CentralizedLogging = $centralizedLogging
        }
    }
    
} catch {
    return @{
        CheckId = "AD-T4-003"
        Timestamp = (Get-Date).ToString("o")
        Status = "Error"
        Score = 0
        Severity = "Low"
        Category = "Logging"
        Findings = @()
        Message = "Error checking event log retention: $_"
        AffectedObjects = 0
        IgnoredObjects = 0
        Metadata = @{
            Domain = $DomainName
            ExecutionTime = ((Get-Date) - $startTime).TotalSeconds
            Error = $_.Exception.Message
        }
    }
}