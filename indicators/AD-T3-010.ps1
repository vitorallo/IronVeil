<#
.SYNOPSIS
Scans for certificates with weak cryptographic parameters

.METADATA
{
  "id": "AD-T3-010",
  "name": "Weak Certificate Cryptography",
  "description": "Certificates with weak key sizes (<2048 bits) or outdated algorithms pose security risks",
  "category": "Cryptography",
  "severity": "Medium",
  "weight": 5,
  "impact": 5,
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
    
    # Get Certificate Authority information
    try {
        $configContext = ([ADSI]"LDAP://RootDSE").ConfigurationNamingContext
        $caContainer = [ADSI]"LDAP://CN=Enrollment Services,CN=Public Key Services,CN=Services,$configContext"
        
        $certificateAuthorities = @()
        foreach ($ca in $caContainer.Children) {
            $certificateAuthorities += @{
                Name = $ca.Properties["cn"].Value
                DN = $ca.Properties["distinguishedName"].Value
                DNSName = $ca.Properties["dNSHostName"].Value
            }
        }
    } catch {
        $ignoredCount++
        Write-Warning "Could not enumerate Certificate Authorities: $_"
    }
    
    # Check certificate templates for weak settings
    try {
        $templateContainer = [ADSI]"LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,$configContext"
        
        foreach ($template in $templateContainer.Children) {
            $templateName = $template.Properties["cn"].Value
            $minKeySize = $template.Properties["msPKI-Minimal-Key-Size"].Value
            $hashAlgorithm = $template.Properties["msPKI-Hash-Algorithm"].Value
            $enrollmentFlag = $template.Properties["msPKI-Enrollment-Flag"].Value
            $nameFlag = $template.Properties["msPKI-Certificate-Name-Flag"].Value
            $ekus = $template.Properties["pKIExtendedKeyUsage"].Value
            
            $weaknesses = @()
            
            # Check minimum key size
            if ($minKeySize -and $minKeySize -lt 2048) {
                $weaknesses += "weak key size ($minKeySize bits)"
            }
            
            # Check for weak hash algorithms
            if ($hashAlgorithm) {
                $hashOID = $hashAlgorithm
                # Common weak hash OIDs
                $weakHashes = @{
                    "1.2.840.113549.1.1.4" = "MD5"
                    "1.3.14.3.2.26" = "SHA1"
                    "1.2.840.113549.1.1.5" = "SHA1withRSA"
                }
                
                if ($weakHashes.ContainsKey($hashOID)) {
                    $weaknesses += "weak hash algorithm ($($weakHashes[$hashOID]))"
                }
            }
            
            # Check for dangerous enrollment settings
            $isDangerous = $false
            if ($enrollmentFlag) {
                # Check if subject can be supplied in request
                if ($enrollmentFlag -band 0x1) {
                    $weaknesses += "allows requester to specify subject"
                    $isDangerous = $true
                }
            }
            
            if ($nameFlag) {
                # Check if SAN can be supplied in request
                if ($nameFlag -band 0x1) {
                    $weaknesses += "allows requester to specify Subject Alternative Name"
                    $isDangerous = $true
                }
            }
            
            # Check for authentication EKUs with weak settings
            $hasAuthEKU = $false
            if ($ekus) {
                $authEKUs = @(
                    "1.3.6.1.5.5.7.3.2",  # Client Authentication
                    "1.3.6.1.5.5.7.3.1",  # Server Authentication
                    "1.3.6.1.4.1.311.20.2.2", # Smart Card Logon
                    "2.5.29.37.0"  # Any Purpose
                )
                
                foreach ($eku in $ekus) {
                    if ($eku -in $authEKUs) {
                        $hasAuthEKU = $true
                        break
                    }
                }
            }
            
            if ($weaknesses.Count -gt 0) {
                $riskLevel = if ($isDangerous -and $hasAuthEKU) { "High" }
                            elseif ($weaknesses -match "weak key size.*1024" -or $weaknesses -match "MD5") { "High" }
                            elseif ($isDangerous -or $hasAuthEKU) { "Medium" }
                            else { "Low" }
                
                $findings += @{
                    ObjectName = $templateName
                    ObjectType = "CertificateTemplate"
                    RiskLevel = $riskLevel
                    Description = "Certificate template has weaknesses: $($weaknesses -join ', ')$(if ($hasAuthEKU) { ' (has authentication EKU)' })"
                    Remediation = "Update template to use minimum 2048-bit keys, SHA256 or stronger hash, and restrict enrollment settings"
                    AffectedAttributes = @("msPKI-Minimal-Key-Size", "msPKI-Hash-Algorithm", "msPKI-Enrollment-Flag")
                }
                $affectedCount++
                
                if ($riskLevel -eq "High") {
                    $score -= 15
                } elseif ($riskLevel -eq "Medium") {
                    $score -= 10
                } else {
                    $score -= 5
                }
            }
        }
    } catch {
        $ignoredCount++
        Write-Warning "Could not check certificate templates: $_"
    }
    
    # Check domain controller certificates
    foreach ($dc in (Get-ADDomainController -Filter * -Server $DomainName)) {
        try {
            # Check local certificate store on DC
            $certs = Invoke-Command -ComputerName $dc.HostName -ScriptBlock {
                Get-ChildItem -Path Cert:\LocalMachine\My
            } -ErrorAction Stop
            
            foreach ($cert in $certs) {
                $weaknesses = @()
                
                # Check key size
                if ($cert.PublicKey.Key.KeySize -lt 2048) {
                    $weaknesses += "weak key size ($($cert.PublicKey.Key.KeySize) bits)"
                }
                
                # Check signature algorithm
                if ($cert.SignatureAlgorithm.FriendlyName -match "MD5|SHA1") {
                    $weaknesses += "weak signature algorithm ($($cert.SignatureAlgorithm.FriendlyName))"
                }
                
                # Check expiration
                if ($cert.NotAfter -lt (Get-Date)) {
                    $weaknesses += "certificate expired"
                } elseif ($cert.NotAfter -lt (Get-Date).AddDays(30)) {
                    $weaknesses += "certificate expiring soon"
                }
                
                # Check for self-signed certificates
                if ($cert.Issuer -eq $cert.Subject) {
                    $weaknesses += "self-signed certificate"
                }
                
                if ($weaknesses.Count -gt 0) {
                    $riskLevel = if ($weaknesses -match "expired|weak key size.*1024") { "High" }
                                elseif ($weaknesses -match "weak") { "Medium" }
                                else { "Low" }
                    
                    $findings += @{
                        ObjectName = "$($dc.HostName):$($cert.Thumbprint.Substring(0,8))"
                        ObjectType = "Certificate"
                        RiskLevel = $riskLevel
                        Description = "Domain Controller certificate has issues: $($weaknesses -join ', '). Subject: $($cert.Subject)"
                        Remediation = "Replace certificate with one using 2048-bit or larger keys and SHA256 or stronger hash"
                        AffectedAttributes = @("Certificate")
                    }
                    $affectedCount++
                    
                    if ($riskLevel -eq "High") {
                        $score -= 12
                    } elseif ($riskLevel -eq "Medium") {
                        $score -= 8
                    } else {
                        $score -= 4
                    }
                }
            }
        } catch {
            $ignoredCount++
            Write-Warning "Could not check certificates on $($dc.HostName): $_"
        }
    }
    
    # Check for certificates in Active Directory
    try {
        $users = Get-ADUser -Filter {userCertificate -like "*"} -Properties userCertificate -Server $DomainName -ErrorAction Stop | 
            Select-Object -First 100  # Limit for performance
        
        foreach ($user in $users) {
            foreach ($certBytes in $user.userCertificate) {
                try {
                    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(,$certBytes)
                    
                    $weaknesses = @()
                    
                    # Check key size
                    if ($cert.PublicKey.Key.KeySize -lt 2048) {
                        $weaknesses += "weak key size ($($cert.PublicKey.Key.KeySize) bits)"
                    }
                    
                    # Check if expired
                    if ($cert.NotAfter -lt (Get-Date)) {
                        $weaknesses += "expired certificate"
                    }
                    
                    if ($weaknesses.Count -gt 0) {
                        $findings += @{
                            ObjectName = $user.SamAccountName
                            ObjectType = "User"
                            RiskLevel = if ($weaknesses -match "expired") { "Medium" } else { "Low" }
                            Description = "User has certificate with issues: $($weaknesses -join ', ')"
                            Remediation = "Update or remove weak/expired certificates from user objects"
                            AffectedAttributes = @("userCertificate")
                        }
                        $affectedCount++
                        $score -= 3
                    }
                } catch {
                    # Could not parse certificate
                }
            }
        }
    } catch {
        $ignoredCount++
        Write-Warning "Could not check user certificates: $_"
    }
    
    # Ensure score doesn't go below 0
    $score = [Math]::Max(0, $score)
    
    # Determine overall status
    $status = if ($findings.Count -eq 0) { "Success" } 
              elseif ($score -lt 50) { "Failed" } 
              else { "Warning" }
    
    $message = if ($findings.Count -eq 0) {
        "No weak certificate cryptography detected"
    } else {
        "Found $($findings.Count) certificates or templates with weak cryptographic parameters"
    }
    
    $executionTime = (Get-Date) - $startTime
    
    return @{
        CheckId = "AD-T3-010"
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
            CertificateAuthorities = $certificateAuthorities.Count
        }
    }
    
} catch {
    return @{
        CheckId = "AD-T3-010"
        Timestamp = (Get-Date).ToString("o")
        Status = "Error"
        Score = 0
        Severity = "Medium"
        Category = "Cryptography"
        Findings = @()
        Message = "Error checking certificate cryptography: $_"
        AffectedObjects = 0
        IgnoredObjects = 0
        Metadata = @{
            Domain = $DomainName
            ExecutionTime = ((Get-Date) - $startTime).TotalSeconds
            Error = $_.Exception.Message
        }
    }
}