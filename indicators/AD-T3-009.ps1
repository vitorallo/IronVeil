<#
.SYNOPSIS
Verifies that domain controllers are configured to disallow RC4 encryption

.METADATA
{
  "id": "AD-T3-009",
  "name": "RC4 Encryption Type Supported by Domain Controllers",
  "description": "RC4 is a weaker encryption algorithm compared to AES and is vulnerable to various attacks",
  "category": "Cryptography",
  "severity": "Medium",
  "weight": 5,
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
    
    # Check domain functional level
    $domain = Get-ADDomain -Server $DomainName
    $domainFunctionalLevel = $domain.DomainMode
    
    # If domain is below 2008, RC4 cannot be disabled
    if ($domainFunctionalLevel -lt "Windows2008Domain") {
        $findings += @{
            ObjectName = $domain.DNSRoot
            ObjectType = "Domain"
            RiskLevel = "High"
            Description = "Domain functional level ($domainFunctionalLevel) is too low to disable RC4 encryption"
            Remediation = "Upgrade domain functional level to at least Windows Server 2008 to enable AES encryption"
            AffectedAttributes = @("DomainMode")
        }
        $affectedCount++
        $score -= 25
    }
    
    # Check Kerberos encryption types on domain controllers
    foreach ($dc in $domainControllers) {
        try {
            # Check supported encryption types via registry
            $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $dc.HostName)
            $key = $reg.OpenSubKey("SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters")
            
            $supportedEncTypes = $null
            if ($key) {
                $supportedEncTypes = $key.GetValue("SupportedEncryptionTypes")
                $key.Close()
            }
            $reg.Close()
            
            # If not set in policy, check default DC settings
            if ($null -eq $supportedEncTypes) {
                $dcComputer = Get-ADComputer -Identity $dc.ComputerObjectDN -Properties msDS-SupportedEncryptionTypes -Server $DomainName
                $supportedEncTypes = $dcComputer."msDS-SupportedEncryptionTypes"
            }
            
            # Default value if nothing is set (all encryption types enabled)
            if ($null -eq $supportedEncTypes) {
                $supportedEncTypes = 0x1F  # All types enabled by default
            }
            
            # Check if RC4 is enabled (bit 2 = 0x4)
            $rc4Enabled = ($supportedEncTypes -band 0x4) -ne 0
            $aesEnabled = (($supportedEncTypes -band 0x8) -ne 0) -or (($supportedEncTypes -band 0x10) -ne 0)
            $desEnabled = (($supportedEncTypes -band 0x1) -ne 0) -or (($supportedEncTypes -band 0x2) -ne 0)
            
            if ($rc4Enabled) {
                $findings += @{
                    ObjectName = $dc.HostName
                    ObjectType = "DomainController"
                    RiskLevel = if (-not $aesEnabled) { "High" } else { "Medium" }
                    Description = "Domain Controller supports RC4 encryption$(if (-not $aesEnabled) { ' and AES is NOT enabled' } else { '' })"
                    Remediation = "Configure Group Policy to disable RC4 and enable only AES encryption types"
                    AffectedAttributes = @("SupportedEncryptionTypes")
                }
                $affectedCount++
                $score -= if (-not $aesEnabled) { 20 } else { 10 }
            }
            
            if ($desEnabled) {
                $findings += @{
                    ObjectName = $dc.HostName
                    ObjectType = "DomainController"
                    RiskLevel = "High"
                    Description = "Domain Controller supports DES encryption (extremely weak and deprecated)"
                    Remediation = "Immediately disable DES encryption types via Group Policy"
                    AffectedAttributes = @("SupportedEncryptionTypes")
                }
                $affectedCount++
                $score -= 15
            }
            
        } catch {
            $ignoredCount++
            Write-Warning "Could not check encryption types on $($dc.HostName): $_"
        }
    }
    
    # Check for accounts with RC4 only encryption
    try {
        $accounts = Get-ADObject -Filter {msDS-SupportedEncryptionTypes -like "*"} `
            -Properties msDS-SupportedEncryptionTypes, ObjectClass, servicePrincipalName `
            -Server $DomainName -ErrorAction Stop
        
        foreach ($account in $accounts) {
            $encTypes = $account."msDS-SupportedEncryptionTypes"
            
            # Check if only RC4 is enabled
            $rc4Only = ($encTypes -eq 4) -or ($encTypes -eq 0x4)
            $hasWeakEncryption = ($encTypes -band 0x3) -ne 0  # DES enabled
            
            if ($rc4Only -or $hasWeakEncryption) {
                $accountType = $account.ObjectClass
                $accountName = $account.Name
                
                # Check if it's a service account
                $isServiceAccount = ($account.servicePrincipalName -ne $null -and $account.servicePrincipalName.Count -gt 0)
                
                $riskLevel = if ($hasWeakEncryption) { "High" }
                            elseif ($isServiceAccount) { "Medium" }
                            else { "Low" }
                
                $findings += @{
                    ObjectName = $accountName
                    ObjectType = $accountType
                    RiskLevel = $riskLevel
                    Description = if ($hasWeakEncryption) { "Account has DES encryption enabled (extremely weak)" }
                                 else { "Account is configured for RC4-only encryption$(if ($isServiceAccount) { ' (Service Account with SPNs)' })" }
                    Remediation = "Update account to support AES encryption types. For service accounts, ensure applications support AES"
                    AffectedAttributes = @("msDS-SupportedEncryptionTypes")
                }
                $affectedCount++
                $score -= if ($hasWeakEncryption) { 10 } elseif ($isServiceAccount) { 5 } else { 3 }
            }
        }
    } catch {
        $ignoredCount++
        Write-Warning "Could not check account encryption types: $_"
    }
    
    # Check Kerberos policy for encryption type restrictions
    try {
        # Get default domain policy
        $defaultPolicy = Get-GPO -Name "Default Domain Policy" -Domain $DomainName -ErrorAction Stop
        $policyReport = Get-GPOReport -Guid $defaultPolicy.Id -ReportType Xml -Domain $DomainName
        
        # Parse for Kerberos settings
        $xml = [xml]$policyReport
        $kerberosSettings = $xml.GPO.Computer.ExtensionData | Where-Object { $_.Name -like "*Kerberos*" }
        
        if (-not $kerberosSettings) {
            $findings += @{
                ObjectName = "Default Domain Policy"
                ObjectType = "GroupPolicy"
                RiskLevel = "Medium"
                Description = "Kerberos encryption types are not explicitly configured in Default Domain Policy"
                Remediation = "Configure 'Network security: Configure encryption types allowed for Kerberos' to use only AES"
                AffectedAttributes = @("Kerberos Policy")
            }
            $affectedCount++
            $score -= 10
        }
    } catch {
        $ignoredCount++
        Write-Warning "Could not check Kerberos policy: $_"
    }
    
    # Check for trust relationships using RC4
    try {
        $trusts = Get-ADTrust -Filter * -Server $DomainName -ErrorAction Stop
        
        foreach ($trust in $trusts) {
            # Check trust encryption types
            if ($trust.TrustAttributes -band 0x8) {  # RC4 encryption
                $findings += @{
                    ObjectName = $trust.Name
                    ObjectType = "Trust"
                    RiskLevel = "Medium"
                    Description = "Trust relationship with '$($trust.Target)' uses RC4 encryption"
                    Remediation = "Upgrade trust to use AES encryption if both domains support it"
                    AffectedAttributes = @("TrustAttributes")
                }
                $affectedCount++
                $score -= 8
            }
        }
    } catch {
        $ignoredCount++
        Write-Warning "Could not check trust encryption: $_"
    }
    
    # Ensure score doesn't go below 0
    $score = [Math]::Max(0, $score)
    
    # Determine overall status
    $status = if ($findings.Count -eq 0) { "Success" } 
              elseif ($score -lt 50) { "Failed" } 
              else { "Warning" }
    
    $message = if ($findings.Count -eq 0) {
        "RC4 encryption is properly disabled across the domain"
    } else {
        "Found $($findings.Count) instances where weak RC4/DES encryption is enabled"
    }
    
    $executionTime = (Get-Date) - $startTime
    
    return @{
        CheckId = "AD-T3-009"
        Timestamp = (Get-Date).ToString("o")
        Status = $status
        Score = $score
        Severity = "Medium"
        Category = "Cryptography"
        Findings = $findings
        Message = $message
        AffectedObjects = $affectedCount
        IgnoredObjects = $ignoredCount
        Metadata = @{
            Domain = $DomainName
            ExecutionTime = $executionTime.TotalSeconds
            DomainFunctionalLevel = $domainFunctionalLevel
            DomainControllersChecked = $domainControllers.Count
        }
    }
    
} catch {
    return @{
        CheckId = "AD-T3-009"
        Timestamp = (Get-Date).ToString("o")
        Status = "Error"
        Score = 0
        Severity = "Medium"
        Category = "Cryptography"
        Findings = @()
        Message = "Error checking RC4 encryption configuration: $_"
        AffectedObjects = 0
        IgnoredObjects = 0
        Metadata = @{
            Domain = $DomainName
            ExecutionTime = ((Get-Date) - $startTime).TotalSeconds
            Error = $_.Exception.Message
        }
    }
}