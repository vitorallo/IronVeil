<#
.SYNOPSIS
Verifies that domain controllers are configured to require LDAP signing

.METADATA
{
  "id": "AD-T3-004",
  "name": "LDAP Signing Not Required",
  "description": "If LDAP signing is not required, attackers can perform LDAP relay attacks and man-in-the-middle attacks",
  "category": "NetworkSecurity",
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
    
    # Get all domain controllers
    $domainControllers = Get-ADDomainController -Filter * -Server $DomainName -ErrorAction Stop
    
    foreach ($dc in $domainControllers) {
        try {
            $dcName = $dc.HostName
            
            # Check LDAP signing requirements via registry
            $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $dcName)
            $key = $reg.OpenSubKey("SYSTEM\CurrentControlSet\Services\NTDS\Parameters")
            
            if ($key) {
                # Check LDAPServerIntegrity (1 = None, 2 = Require signing)
                $ldapServerIntegrity = $key.GetValue("LDAPServerIntegrity")
                
                if ($null -eq $ldapServerIntegrity -or $ldapServerIntegrity -lt 2) {
                    $findings += @{
                        ObjectName = $dcName
                        ObjectType = "DomainController"
                        RiskLevel = "High"
                        Description = "Domain Controller does not require LDAP signing (LDAPServerIntegrity: $($ldapServerIntegrity ?? 'Not Set'))"
                        Remediation = "Set 'Domain controller: LDAP server signing requirements' to 'Require signing' via Group Policy"
                        AffectedAttributes = @("LDAPServerIntegrity")
                    }
                    $affectedCount++
                    $score -= 20
                }
                
                $key.Close()
            } else {
                $ignoredCount++
                Write-Warning "Could not access registry key for $dcName"
            }
            
            $reg.Close()
            
            # Also check LDAP client signing
            $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $dcName)
            $key = $reg.OpenSubKey("SYSTEM\CurrentControlSet\Services\ldap")
            
            if ($key) {
                # Check LDAPClientIntegrity (0 = None, 1 = Request signing, 2 = Require signing)
                $ldapClientIntegrity = $key.GetValue("LDAPClientIntegrity")
                
                if ($null -eq $ldapClientIntegrity -or $ldapClientIntegrity -eq 0) {
                    $findings += @{
                        ObjectName = $dcName
                        ObjectType = "DomainController"
                        RiskLevel = "Medium"
                        Description = "Domain Controller LDAP client does not negotiate signing (LDAPClientIntegrity: $($ldapClientIntegrity ?? 'Not Set'))"
                        Remediation = "Set 'Network security: LDAP client signing requirements' to 'Negotiate signing' or 'Require signing'"
                        AffectedAttributes = @("LDAPClientIntegrity")
                    }
                    $affectedCount++
                    $score -= 10
                }
                
                $key.Close()
            }
            
            $reg.Close()
            
        } catch {
            $ignoredCount++
            Write-Warning "Could not check LDAP signing on $($dc.HostName): $_"
        }
    }
    
    # Check for LDAP channel binding
    foreach ($dc in $domainControllers) {
        try {
            $dcName = $dc.HostName
            
            $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $dcName)
            $key = $reg.OpenSubKey("SYSTEM\CurrentControlSet\Services\NTDS\Parameters")
            
            if ($key) {
                # Check LdapEnforceChannelBinding (0 = Disabled, 1 = When supported, 2 = Always)
                $channelBinding = $key.GetValue("LdapEnforceChannelBinding")
                
                if ($null -eq $channelBinding -or $channelBinding -eq 0) {
                    $findings += @{
                        ObjectName = $dcName
                        ObjectType = "DomainController"
                        RiskLevel = "Medium"
                        Description = "LDAP channel binding is not enforced (vulnerable to relay attacks)"
                        Remediation = "Enable LDAP channel binding by setting LdapEnforceChannelBinding to 1 or 2"
                        AffectedAttributes = @("LdapEnforceChannelBinding")
                    }
                    $affectedCount++
                    $score -= 15
                }
                
                $key.Close()
            }
            
            $reg.Close()
            
        } catch {
            $ignoredCount++
            Write-Warning "Could not check LDAP channel binding on $($dc.HostName): $_"
        }
    }
    
    # Check for Extended Protection for Authentication
    foreach ($dc in $domainControllers) {
        try {
            $dcName = $dc.HostName
            
            $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $dcName)
            $key = $reg.OpenSubKey("SYSTEM\CurrentControlSet\Control\Lsa")
            
            if ($key) {
                # Check SuppressExtendedProtection (0 or not exist = EPA enabled, 1 = EPA disabled)
                $suppressEPA = $key.GetValue("SuppressExtendedProtection")
                
                if ($suppressEPA -eq 1) {
                    $findings += @{
                        ObjectName = $dcName
                        ObjectType = "DomainController"
                        RiskLevel = "Medium"
                        Description = "Extended Protection for Authentication is suppressed"
                        Remediation = "Enable Extended Protection for Authentication by removing or setting SuppressExtendedProtection to 0"
                        AffectedAttributes = @("SuppressExtendedProtection")
                    }
                    $affectedCount++
                    $score -= 10
                }
                
                $key.Close()
            }
            
            $reg.Close()
            
        } catch {
            $ignoredCount++
            Write-Warning "Could not check Extended Protection on $($dc.HostName): $_"
        }
    }
    
    # Check domain-wide LDAP policies
    try {
        $domain = Get-ADDomain -Server $DomainName
        $domainDN = $domain.DistinguishedName
        
        # Query for LDAP policies in the configuration partition
        $configDN = "CN=Configuration,$domainDN"
        $ldapPolicies = Get-ADObject -Filter * -SearchBase "CN=Query-Policies,CN=Directory Service,CN=Windows NT,CN=Services,$configDN" -Properties * -ErrorAction SilentlyContinue
        
        if ($ldapPolicies) {
            foreach ($policy in $ldapPolicies) {
                if ($policy.lDAPAdminLimits) {
                    # Check for insecure LDAP settings
                    $adminLimits = $policy.lDAPAdminLimits -join "`n"
                    if ($adminLimits -notmatch "RequireSecureProbing=1") {
                        $findings += @{
                            ObjectName = $policy.Name
                            ObjectType = "LDAPPolicy"
                            RiskLevel = "Low"
                            Description = "LDAP policy does not require secure probing"
                            Remediation = "Configure LDAP policies to require secure connections"
                            AffectedAttributes = @("lDAPAdminLimits")
                        }
                        $affectedCount++
                        $score -= 5
                    }
                }
            }
        }
    } catch {
        $ignoredCount++
        Write-Warning "Could not check domain LDAP policies: $_"
    }
    
    # Ensure score doesn't go below 0
    $score = [Math]::Max(0, $score)
    
    # Determine overall status
    $status = if ($findings.Count -eq 0) { "Success" } 
              elseif ($score -lt 50) { "Failed" } 
              else { "Warning" }
    
    $message = if ($findings.Count -eq 0) {
        "LDAP signing is properly configured on all domain controllers"
    } else {
        "Found $($findings.Count) LDAP signing configuration issues across $affectedCount objects"
    }
    
    $executionTime = (Get-Date) - $startTime
    
    return @{
        CheckId = "AD-T3-004"
        Timestamp = (Get-Date).ToString("o")
        Status = $status
        Score = $score
        Severity = "Medium"
        Category = "NetworkSecurity"
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
        CheckId = "AD-T3-004"
        Timestamp = (Get-Date).ToString("o")
        Status = "Error"
        Score = 0
        Severity = "Medium"
        Category = "NetworkSecurity"
        Findings = @()
        Message = "Error checking LDAP signing configuration: $_"
        AffectedObjects = 0
        IgnoredObjects = 0
        Metadata = @{
            Domain = $DomainName
            ExecutionTime = ((Get-Date) - $startTime).TotalSeconds
            Error = $_.Exception.Message
        }
    }
}