<#
.SYNOPSIS
Detects certificate templates with insecure configurations that could allow privilege escalation

.METADATA
{
  "id": "AD-T2-002",
  "name": "Certificate Templates with Insecure Configurations",
  "description": "Misconfigured certificate templates can allow attackers to enroll for certificates that grant elevated privileges. This check identifies templates with dangerous settings like allowing subjectAltName specification, weak enrollment permissions, or manager approval bypass.",
  "category": "PrivilegeEscalation",
  "severity": "High",
  "weight": 8,
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
    
    # Get domain information
    $domain = Get-ADDomain -Identity $DomainName
    $domainDN = $domain.DistinguishedName
    $configDN = "CN=Configuration,$domainDN"
    
    # Get all certificate templates
    $templateContainer = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configDN"
    
    try {
        $templates = Get-ADObject -SearchBase $templateContainer -Filter {objectClass -eq "pKICertificateTemplate"} -Properties *
    }
    catch {
        # Certificate Services might not be installed
        return @{
            CheckId = "AD-T2-002"
            Timestamp = (Get-Date).ToString("o")
            Status = "Success"
            Score = 100
            Severity = "High"
            Category = "PrivilegeEscalation"
            Findings = @()
            Message = "No certificate templates found. Certificate Services may not be installed in this domain."
            AffectedObjects = 0
            IgnoredObjects = 0
            Metadata = @{
                Domain = $DomainName
                ExecutionTime = [Math]::Round(((Get-Date) - $startTime).TotalSeconds, 2)
                CertificateServicesInstalled = $false
            }
        }
    }
    
    # Define flags for msPKI-Certificate-Name-Flag
    $ENROLLEE_SUPPLIES_SUBJECT = 0x00000001
    $ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME = 0x00010000
    
    # Define flags for msPKI-Enrollment-Flag
    $INCLUDE_SYMMETRIC_ALGORITHMS = 0x00000001
    $PEND_ALL_REQUESTS = 0x00000002
    $PUBLISH_TO_KRA_CONTAINER = 0x00000004
    $PUBLISH_TO_DS = 0x00000008
    $AUTO_ENROLLMENT = 0x00000020
    $CT_FLAG_MACHINE_TYPE = 0x00000040
    $CT_FLAG_IS_CA = 0x00000080
    $CT_FLAG_ADD_EMAIL = 0x00000100
    $CT_FLAG_ADD_OBJ_GUID = 0x00000200
    $CT_FLAG_PUBLISH_TO_DS = 0x00000400
    $AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE = 0x00000800
    $NO_SECURITY_EXTENSION = 0x00080000
    
    foreach ($template in $templates) {
        $templateName = $template.Name
        $issues = @()
        $riskLevel = "Low"
        
        # Check 1: Can enrollee supply subject?
        $nameFlag = $template.'msPKI-Certificate-Name-Flag'
        if ($nameFlag) {
            if ($nameFlag -band $ENROLLEE_SUPPLIES_SUBJECT) {
                $issues += "Enrollee can supply subject name (ESC1 vulnerability)"
                $riskLevel = "High"
            }
            if ($nameFlag -band $ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME) {
                $issues += "Enrollee can supply subject alternative name (ESC1 vulnerability)"
                $riskLevel = "High"
            }
        }
        
        # Check 2: Does template have dangerous EKU?
        $ekus = $template.'pKIExtendedKeyUsage'
        $dangerousEKUs = @(
            "2.5.29.37.0",  # Any Purpose
            "1.3.6.1.5.5.7.3.2",  # Client Authentication
            "1.3.6.1.5.2.3.4",  # PKINIT Client Authentication
            "1.3.6.1.4.1.311.20.2.2",  # Smart Card Logon
            "1.3.6.1.5.2.3.5"  # KDC Authentication
        )
        
        if ($ekus) {
            foreach ($eku in $ekus) {
                if ($eku -in $dangerousEKUs) {
                    $issues += "Template has authentication EKU: $eku"
                    if ($riskLevel -eq "Low") {
                        $riskLevel = "Medium"
                    }
                }
            }
        }
        
        # Check 3: No manager approval required?
        $enrollmentFlag = $template.'msPKI-Enrollment-Flag'
        if ($enrollmentFlag) {
            if (-not ($enrollmentFlag -band $PEND_ALL_REQUESTS)) {
                if ($issues.Count -gt 0) {
                    $issues += "No manager approval required for enrollment"
                }
            }
            
            if ($enrollmentFlag -band $NO_SECURITY_EXTENSION) {
                $issues += "No security extension (vulnerable to ESC2)"
                if ($riskLevel -ne "High") {
                    $riskLevel = "Medium"
                }
            }
        }
        
        # Check 4: Who can enroll?
        $templateACL = Get-Acl "AD:\$($template.DistinguishedName)"
        $enrollmentRights = @()
        $autoEnrollmentRights = @()
        
        foreach ($ace in $templateACL.Access) {
            if ($ace.AccessControlType -eq "Allow") {
                # Check for enrollment permissions
                if ($ace.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) {
                    # Check specific extended rights
                    $rightGuid = $ace.ObjectType
                    
                    # Enrollment right GUID
                    if ($rightGuid -eq "0e10c968-78fb-11d2-90d4-00c04f79dc55" -or $rightGuid -eq "00000000-0000-0000-0000-000000000000") {
                        $enrollmentRights += $ace.IdentityReference.Value
                    }
                    
                    # AutoEnrollment right GUID
                    if ($rightGuid -eq "a05b8cc2-17bc-4802-a710-e7c15ab866a2") {
                        $autoEnrollmentRights += $ace.IdentityReference.Value
                    }
                }
                
                # Check for GenericAll
                if ($ace.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericAll) {
                    $enrollmentRights += $ace.IdentityReference.Value
                }
            }
        }
        
        # Check if Domain Users or Authenticated Users can enroll
        $broadGroups = @("Domain Users", "Authenticated Users", "Everyone", "Anonymous")
        foreach ($principal in $enrollmentRights) {
            foreach ($broadGroup in $broadGroups) {
                if ($principal -like "*$broadGroup*") {
                    $issues += "$broadGroup can enroll in this template"
                    if ($riskLevel -ne "High") {
                        $riskLevel = "Medium"
                    }
                }
            }
        }
        
        # Check 5: Is template enabled?
        $templateOID = $template.'msPKI-Cert-Template-OID'
        
        # Check 6: Certificate validity period
        $validityPeriod = $template.'pKIExpirationPeriod'
        $overlapPeriod = $template.'pKIOverlapPeriod'
        
        # Check 7: Check for ESC3 - Certificate Request Agent
        if ($ekus -contains "1.3.6.1.4.1.311.20.2.1") {  # Certificate Request Agent
            $issues += "Template allows Certificate Request Agent (ESC3 vulnerability)"
            $riskLevel = "High"
        }
        
        # Check 8: Check if domain controller authentication is enabled
        if ($ekus -contains "1.3.6.1.5.2.3.5") {  # KDC Authentication
            $issues += "Template allows domain controller authentication"
            $riskLevel = "High"
        }
        
        # Only report templates with issues
        if ($issues.Count -gt 0) {
            # Determine final risk level based on combination of issues
            if ($issues.Count -ge 3 -and $riskLevel -eq "Medium") {
                $riskLevel = "High"
            }
            
            $remediationSteps = @(
                "1. Review the certificate template configuration"
                "2. Remove 'Enrollee Supplies Subject' flag if not required"
                "3. Require manager approval for enrollment"
                "4. Restrict enrollment permissions to specific groups"
                "5. Remove authentication EKUs if not needed"
                "6. Consider disabling the template if not in use"
            )
            
            $findings += @{
                ObjectName = $templateName
                ObjectType = "CertificateTemplate"
                RiskLevel = $riskLevel
                Description = "Certificate template has insecure configuration: $($issues -join '; '). This could allow attackers to obtain certificates for authentication or privilege escalation."
                Remediation = $remediationSteps -join ". "
                AffectedAttributes = @("msPKI-Certificate-Name-Flag", "pKIExtendedKeyUsage", "msPKI-Enrollment-Flag", "nTSecurityDescriptor")
            }
        }
    }
    
    # Check for published Certificate Authorities
    $caContainer = "CN=Enrollment Services,CN=Public Key Services,CN=Services,$configDN"
    try {
        $cas = Get-ADObject -SearchBase $caContainer -Filter {objectClass -eq "pKIEnrollmentService"} -Properties *
        
        foreach ($ca in $cas) {
            # Check if CA has insecure flags
            $caFlags = $ca.flags
            if ($caFlags) {
                $caIssues = @()
                
                # Check various CA flags for security issues
                if ($caFlags -band 0x00000001) {  # NO_TEMPLATE_SUPPORT
                    $caIssues += "CA does not enforce template settings"
                }
                
                if ($caIssues.Count -gt 0) {
                    $findings += @{
                        ObjectName = $ca.Name
                        ObjectType = "CertificateAuthority"
                        RiskLevel = "Medium"
                        Description = "Certificate Authority has insecure configuration: $($caIssues -join '; ')"
                        Remediation = "Review CA configuration and ensure template enforcement is enabled."
                        AffectedAttributes = @("flags", "cACertificate")
                    }
                }
            }
        }
    }
    catch {
        # CAs might not be accessible
    }
    
    # Calculate execution time
    $executionTime = ((Get-Date) - $startTime).TotalSeconds
    
    # Determine final score and status
    $score = 100  # Start with perfect score
    $status = "Success"
    $message = "Certificate template security assessment completed."
    
    if ($findings.Count -gt 0) {
        $highRiskCount = @($findings | Where-Object { $_.RiskLevel -eq "High" }).Count
        $mediumRiskCount = @($findings | Where-Object { $_.RiskLevel -eq "Medium" }).Count
        
        # Calculate score based on findings
        $score = [Math]::Max(0, 100 - ($highRiskCount * 30) - ($mediumRiskCount * 15))
        
        if ($highRiskCount -gt 0) {
            $message = "CRITICAL: Found $highRiskCount high-risk and $mediumRiskCount medium-risk certificate template vulnerabilities. These could allow privilege escalation."
        }
        else {
            $message = "WARNING: Found $mediumRiskCount medium-risk certificate template configurations requiring review."
        }
    }
    else {
        $message = "No insecure certificate templates detected. All templates appear properly configured."
    }
    
    return @{
        CheckId = "AD-T2-002"
        Timestamp = (Get-Date).ToString("o")
        Status = $status
        Score = $score
        Severity = "High"
        Category = "PrivilegeEscalation"
        Findings = $findings
        Message = $message
        AffectedObjects = $findings.Count
        IgnoredObjects = 0
        Metadata = @{
            Domain = $DomainName
            ExecutionTime = [Math]::Round($executionTime, 2)
            TotalTemplatesChecked = $templates.Count
            CertificateAuthoritiesFound = if ($cas) { $cas.Count } else { 0 }
        }
    }
}
catch {
    return @{
        CheckId = "AD-T2-002"
        Timestamp = (Get-Date).ToString("o")
        Status = "Error"
        Score = 0
        Severity = "High"
        Category = "PrivilegeEscalation"
        Findings = @()
        Message = "Error executing certificate template assessment: $_"
        AffectedObjects = 0
        IgnoredObjects = 0
        Metadata = @{
            Domain = $DomainName
            ExecutionTime = 0.0
            ErrorDetails = $_.Exception.Message
        }
    }
}