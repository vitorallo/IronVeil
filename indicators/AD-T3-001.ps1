<#
.SYNOPSIS
Checks if legacy authentication protocols like NTLM are enabled on domain controllers

.METADATA
{
  "id": "AD-T3-001",
  "name": "Legacy Authentication Protocols Enabled",
  "description": "Older authentication protocols like NTLM are less secure than Kerberos and can be exploited for credential relay attacks",
  "category": "Authentication",
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
    
    # Get domain controllers
    $domainControllers = Get-ADDomainController -Filter * -Server $DomainName -ErrorAction Stop
    
    foreach ($dc in $domainControllers) {
        try {
            # Check NTLM authentication settings via registry
            $ntlmSettings = @{
                LmCompatibilityLevel = $null
                RestrictNTLM = $null
                AuditNTLM = $null
            }
            
            # Check LmCompatibilityLevel (should be 5 for NTLMv2 only)
            $regPath = "\\$($dc.HostName)\HKLM\SYSTEM\CurrentControlSet\Control\Lsa"
            $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $dc.HostName)
            $key = $reg.OpenSubKey("SYSTEM\CurrentControlSet\Control\Lsa")
            
            if ($key) {
                $lmLevel = $key.GetValue("LmCompatibilityLevel")
                if ($null -eq $lmLevel -or $lmLevel -lt 3) {
                    $findings += @{
                        ObjectName = $dc.HostName
                        ObjectType = "DomainController"
                        RiskLevel = "Medium"
                        Description = "Domain Controller allows weak NTLM authentication (LmCompatibilityLevel: $($lmLevel ?? 'Not Set'))"
                        Remediation = "Set LmCompatibilityLevel to 5 (Send NTLMv2 response only, refuse LM & NTLM) via Group Policy"
                        AffectedAttributes = @("LmCompatibilityLevel")
                    }
                    $affectedCount++
                    $score -= 15
                }
                
                # Check RestrictSendingNTLMTraffic
                $restrictNTLM = $key.GetValue("RestrictSendingNTLMTraffic")
                if ($null -eq $restrictNTLM -or $restrictNTLM -eq 0) {
                    $findings += @{
                        ObjectName = $dc.HostName
                        ObjectType = "DomainController"
                        RiskLevel = "Medium"
                        Description = "Domain Controller does not restrict outgoing NTLM traffic"
                        Remediation = "Configure 'Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers' to 'Audit all' or 'Deny all'"
                        AffectedAttributes = @("RestrictSendingNTLMTraffic")
                    }
                    $affectedCount++
                    $score -= 10
                }
                
                $key.Close()
            }
            $reg.Close()
            
        } catch {
            $ignoredCount++
            Write-Warning "Could not check NTLM settings on $($dc.HostName): $_"
        }
    }
    
    # Check domain-wide NTLM authentication policies
    try {
        $domain = Get-ADDomain -Server $DomainName
        $domainDN = $domain.DistinguishedName
        
        # Check if NTLM is allowed for domain authentication
        $ntlmPolicy = Get-ADObject -Filter * -SearchBase "CN=Policies,CN=System,$domainDN" -Properties * |
            Where-Object { $_.Name -like "*NTLM*" }
        
        if (-not $ntlmPolicy) {
            $findings += @{
                ObjectName = $domain.DNSRoot
                ObjectType = "Domain"
                RiskLevel = "Medium"
                Description = "No explicit NTLM restriction policies found at domain level"
                Remediation = "Implement Group Policy to restrict NTLM authentication domain-wide"
                AffectedAttributes = @("NTLM Policy")
            }
            $affectedCount++
            $score -= 20
        }
    } catch {
        $ignoredCount++
        Write-Warning "Could not check domain NTLM policies: $_"
    }
    
    # Check for SMBv1 protocol (often associated with legacy auth)
    foreach ($dc in $domainControllers) {
        try {
            $smbv1Enabled = $false
            $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $dc.HostName)
            $key = $reg.OpenSubKey("SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters")
            
            if ($key) {
                $smb1 = $key.GetValue("SMB1")
                if ($null -eq $smb1 -or $smb1 -ne 0) {
                    $findings += @{
                        ObjectName = $dc.HostName
                        ObjectType = "DomainController"
                        RiskLevel = "High"
                        Description = "SMBv1 protocol may be enabled on Domain Controller"
                        Remediation = "Disable SMBv1 using 'Set-SmbServerConfiguration -EnableSMB1Protocol $false'"
                        AffectedAttributes = @("SMB1Protocol")
                    }
                    $affectedCount++
                    $score -= 15
                }
                $key.Close()
            }
            $reg.Close()
        } catch {
            $ignoredCount++
            Write-Warning "Could not check SMBv1 status on $($dc.HostName): $_"
        }
    }
    
    # Ensure score doesn't go below 0
    $score = [Math]::Max(0, $score)
    
    # Determine overall status
    $status = if ($findings.Count -eq 0) { "Success" } 
              elseif ($score -lt 50) { "Failed" } 
              else { "Warning" }
    
    $message = if ($findings.Count -eq 0) {
        "No legacy authentication protocol issues detected"
    } else {
        "Found $($findings.Count) legacy authentication protocol vulnerabilities across $affectedCount objects"
    }
    
    $executionTime = (Get-Date) - $startTime
    
    return @{
        CheckId = "AD-T3-001"
        Timestamp = (Get-Date).ToString("o")
        Status = $status
        Score = $score
        Severity = "Medium"
        Category = "Authentication"
        Findings = $findings
        Message = $message
        AffectedObjects = $affectedCount
        IgnoredObjects = $ignoredCount
        Metadata = @{
            Domain = $DomainName
            ExecutionTime = $executionTime.TotalSeconds
            DomainControllersChecked = $domainControllers.Count
        }
    }
    
} catch {
    return @{
        CheckId = "AD-T3-001"
        Timestamp = (Get-Date).ToString("o")
        Status = "Error"
        Score = 0
        Severity = "Medium"
        Category = "Authentication"
        Findings = @()
        Message = "Error checking legacy authentication protocols: $_"
        AffectedObjects = 0
        IgnoredObjects = 0
        Metadata = @{
            Domain = $DomainName
            ExecutionTime = ((Get-Date) - $startTime).TotalSeconds
            Error = $_.Exception.Message
        }
    }
}