<#
.SYNOPSIS
Checks if domain controllers have appropriate DNS configurations

.METADATA
{
  "id": "AD-T4-005",
  "name": "Domain Controller DNS Configuration Issues",
  "description": "Domain controllers have suboptimal DNS configurations that could affect authentication and replication",
  "category": "Configuration",
  "severity": "Low",
  "weight": 3,
  "impact": 3,
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
    
    # Get domain and forest information
    $domain = Get-ADDomain -Server $DomainName -ErrorAction Stop
    $forest = Get-ADForest -Server $DomainName -ErrorAction Stop
    
    # Get all domain controllers
    $domainControllers = Get-ADDomainController -Filter * -Server $DomainName -ErrorAction Stop
    
    # Build list of valid DNS servers (all DCs in the domain)
    $validDNSServers = $domainControllers | ForEach-Object { $_.IPv4Address }
    
    foreach ($dc in $domainControllers) {
        try {
            $dcName = $dc.HostName
            $dcIP = $dc.IPv4Address
            Write-Verbose "Checking DNS configuration on $dcName"
            
            # Get DNS client configuration
            $dnsConfig = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -ComputerName $dcName -Filter "IPEnabled = True" -ErrorAction Stop
            
            foreach ($adapter in $dnsConfig) {
                if ($adapter.DNSServerSearchOrder) {
                    $dnsServers = $adapter.DNSServerSearchOrder
                    
                    # Check 1: Primary DNS should be itself (127.0.0.1 or its own IP)
                    $primaryDNS = $dnsServers[0]
                    if ($primaryDNS -ne "127.0.0.1" -and $primaryDNS -ne "::1" -and $primaryDNS -ne $dcIP) {
                        # Check if it's pointing to another DC (acceptable but not optimal)
                        if ($primaryDNS -in $validDNSServers) {
                            $findings += @{
                                ObjectName = $dcName
                                ObjectType = "DomainController"
                                RiskLevel = "Low"
                                Description = "Domain Controller $dcName has primary DNS set to another DC ($primaryDNS) instead of itself. This can cause delays during DC boot"
                                Remediation = "Set primary DNS to 127.0.0.1 or $dcIP, and secondary DNS to another DC for optimal performance"
                                AffectedAttributes = @("DNSServerSearchOrder", "PrimaryDNS")
                            }
                            $affectedCount++
                            $score -= 5
                        } else {
                            # External or unknown DNS server
                            $findings += @{
                                ObjectName = $dcName
                                ObjectType = "DomainController"
                                RiskLevel = "Medium"
                                Description = "Domain Controller $dcName has primary DNS set to non-DC server ($primaryDNS)"
                                Remediation = "Domain Controllers should only use other DCs as DNS servers. Set primary DNS to 127.0.0.1 and secondary to another DC"
                                AffectedAttributes = @("DNSServerSearchOrder", "PrimaryDNS")
                            }
                            $affectedCount++
                            $score -= 15
                        }
                    }
                    
                    # Check 2: Secondary DNS should be another DC
                    if ($dnsServers.Count -gt 1) {
                        $secondaryDNS = $dnsServers[1]
                        if ($secondaryDNS -notin $validDNSServers -and $secondaryDNS -ne "127.0.0.1" -and $secondaryDNS -ne "::1") {
                            $findings += @{
                                ObjectName = $dcName
                                ObjectType = "DomainController"
                                RiskLevel = "Low"
                                Description = "Domain Controller $dcName has secondary DNS set to non-DC server ($secondaryDNS)"
                                Remediation = "Configure secondary DNS to point to another Domain Controller in the same site if available"
                                AffectedAttributes = @("DNSServerSearchOrder", "SecondaryDNS")
                            }
                            $affectedCount++
                            $score -= 10
                        }
                    } else {
                        # No secondary DNS configured
                        if ($domainControllers.Count -gt 1) {
                            $findings += @{
                                ObjectName = $dcName
                                ObjectType = "DomainController"
                                RiskLevel = "Low"
                                Description = "Domain Controller $dcName has no secondary DNS server configured"
                                Remediation = "Add a secondary DNS server pointing to another Domain Controller for redundancy"
                                AffectedAttributes = @("DNSServerSearchOrder")
                            }
                            $score -= 5
                        }
                    }
                    
                    # Check 3: DNS suffixes
                    $dnsSuffixes = $adapter.DNSDomainSuffixSearchOrder
                    if (-not $dnsSuffixes -or $domain.DNSRoot -notin $dnsSuffixes) {
                        $findings += @{
                            ObjectName = $dcName
                            ObjectType = "DomainController"
                            RiskLevel = "Low"
                            Description = "Domain Controller $dcName missing domain DNS suffix '$($domain.DNSRoot)' in search list"
                            Remediation = "Add '$($domain.DNSRoot)' to the DNS suffix search list for proper name resolution"
                            AffectedAttributes = @("DNSDomainSuffixSearchOrder")
                        }
                        $score -= 3
                    }
                }
            }
            
            # Check 4: DNS Server service configuration
            try {
                $dnsService = Get-Service -ComputerName $dcName -Name "DNS" -ErrorAction Stop
                if ($dnsService.Status -ne "Running") {
                    $findings += @{
                        ObjectName = $dcName
                        ObjectType = "DomainController"
                        RiskLevel = "High"
                        Description = "DNS Server service is not running on Domain Controller $dcName"
                        Remediation = "Start the DNS Server service and set it to Automatic startup"
                        AffectedAttributes = @("ServiceStatus")
                    }
                    $affectedCount++
                    $score -= 25
                }
            } catch {
                Write-Verbose "Could not check DNS service status on $dcName"
            }
            
            # Check 5: DNS forwarders configuration
            try {
                $dnsServer = Get-WmiObject -Namespace "root\MicrosoftDNS" -Class "MicrosoftDNS_Server" -ComputerName $dcName -ErrorAction Stop
                if ($dnsServer) {
                    $forwarders = $dnsServer.Forwarders
                    if (-not $forwarders -or $forwarders.Count -eq 0) {
                        $findings += @{
                            ObjectName = $dcName
                            ObjectType = "DomainController"
                            RiskLevel = "Low"
                            Description = "No DNS forwarders configured on $dcName for external name resolution"
                            Remediation = "Configure DNS forwarders to reliable external DNS servers (e.g., ISP, 8.8.8.8, 1.1.1.1) for internet name resolution"
                            AffectedAttributes = @("Forwarders")
                        }
                        $score -= 5
                    } elseif ($forwarders.Count -eq 1) {
                        $findings += @{
                            ObjectName = $dcName
                            ObjectType = "DomainController"
                            RiskLevel = "Low"
                            Description = "Only one DNS forwarder configured on $dcName (no redundancy)"
                            Remediation = "Add at least one additional DNS forwarder for redundancy"
                            AffectedAttributes = @("Forwarders")
                        }
                        $score -= 3
                    }
                }
            } catch {
                Write-Verbose "Could not check DNS forwarders on $dcName"
            }
            
            # Check 6: Root hints
            try {
                $rootHints = Get-WmiObject -Namespace "root\MicrosoftDNS" -Class "MicrosoftDNS_ResourceRecord" `
                    -ComputerName $dcName -Filter "ContainerName='.'" -ErrorAction SilentlyContinue
                if (-not $rootHints -or $rootHints.Count -lt 13) {
                    $findings += @{
                        ObjectName = $dcName
                        ObjectType = "DomainController"
                        RiskLevel = "Low"
                        Description = "Root hints may be missing or incomplete on $dcName"
                        Remediation = "Verify root hints are properly configured for DNS resolution when forwarders are unavailable"
                        AffectedAttributes = @("RootHints")
                    }
                    $score -= 2
                }
            } catch {
                Write-Verbose "Could not check root hints on $dcName"
            }
            
        } catch {
            $ignoredCount++
            Write-Warning "Could not check DNS configuration on ${dcName}: ${_}"
        }
    }
    
    # Check for DNS scavenging configuration
    try {
        $scavengingEnabled = $false
        foreach ($dc in $domainControllers) {
            try {
                $dnsZone = Get-WmiObject -Namespace "root\MicrosoftDNS" -Class "MicrosoftDNS_Zone" `
                    -ComputerName $dc.HostName -Filter "Name='$($domain.DNSRoot)'" -ErrorAction SilentlyContinue
                if ($dnsZone -and $dnsZone.Aging -eq $true) {
                    $scavengingEnabled = $true
                    break
                }
            } catch {
                continue
            }
        }
        
        if (-not $scavengingEnabled) {
            $findings += @{
                ObjectName = $domain.DNSRoot
                ObjectType = "DNSZone"
                RiskLevel = "Low"
                Description = "DNS scavenging is not enabled for zone '$($domain.DNSRoot)', which can lead to stale DNS records"
                Remediation = "Enable DNS scavenging on the zone and configure aging/scavenging properties appropriately"
                AffectedAttributes = @("Scavenging", "Aging")
            }
            $score -= 5
        }
    } catch {
        Write-Verbose "Could not check DNS scavenging configuration"
    }
    
    # Ensure score doesn't go below 0
    $score = [Math]::Max(0, $score)
    
    # Determine overall status
    $status = if ($findings.Count -eq 0) { "Success" } 
              elseif ($score -lt 50) { "Failed" } 
              else { "Warning" }
    
    $message = if ($findings.Count -eq 0) {
        "All domain controllers have optimal DNS configurations"
    } else {
        "Found $($findings.Count) DNS configuration issues across $affectedCount domain controllers"
    }
    
    $executionTime = (Get-Date) - $startTime
    
    return @{
        CheckId = "AD-T4-005"
        Timestamp = (Get-Date).ToString("o")
        Status = $status
        Score = $score
        Severity = "Low"
        Category = "Configuration"
        Findings = $findings
        Message = $message
        AffectedObjects = $affectedCount
        IgnoredObjects = $ignoredCount
        Metadata = @{
            Domain = $DomainName
            ExecutionTime = $executionTime.TotalSeconds
            DomainControllersChecked = $domainControllers.Count
            ValidDNSServers = $validDNSServers -join ", "
        }
    }
    
} catch {
    return @{
        CheckId = "AD-T4-005"
        Timestamp = (Get-Date).ToString("o")
        Status = "Error"
        Score = 0
        Severity = "Low"
        Category = "Configuration"
        Findings = @()
        Message = "Error checking DNS configuration: $_"
        AffectedObjects = 0
        IgnoredObjects = 0
        Metadata = @{
            Domain = $DomainName
            ExecutionTime = ((Get-Date) - $startTime).TotalSeconds
            Error = $_.Exception.Message
        }
    }
}