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
    
    # Import ADSI helper functions
    $helperPath = Join-Path $PSScriptRoot "IronVeil-ADSIHelper.ps1"
    . $helperPath
    
    if (-not $DomainName) {
        throw "Domain name could not be determined"
    }
    
    # Get domain information using ADSI
    $domainInfo = Get-IVDomainInfo -DomainName $DomainName
    $domainDN = $domainInfo.DistinguishedName
    $configDN = $domainInfo.ConfigurationNamingContext
    
    # Get all certificate templates using ADSI
    $templates = Get-IVCertificateTemplates -ConfigurationDN $configDN
    
    if ($templates.Count -eq 0) {
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
        $templateName = if ($template.cn) { 
            if ($template.cn -is [Array]) { $template.cn[0] } else { $template.cn }
        } else { "Unknown" }
        
        $issues = @()
        $riskLevel = "Low"
        
        # Check 1: Can enrollee supply subject?
        $nameFlag = if ($template.'mspki-certificate-name-flag') {
            if ($template.'mspki-certificate-name-flag' -is [Array]) { 
                $template.'mspki-certificate-name-flag'[0] 
            } else { 
                $template.'mspki-certificate-name-flag' 
            }
        } else { 0 }
        
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
        $ekus = if ($template.'pkiextendedkeyusage') {
            if ($template.'pkiextendedkeyusage' -is [Array]) { 
                $template.'pkiextendedkeyusage'
            } else { 
                @($template.'pkiextendedkeyusage')
            }
        } else { @() }
        
        $dangerousEKUs = @(
            "2.5.29.37.0",  # Any Purpose
            "1.3.6.1.5.5.7.3.2",  # Client Authentication
            "1.3.6.1.5.2.3.4",  # PKINIT Client Authentication
            "1.3.6.1.4.1.311.20.2.2",  # Smart Card Logon
            "1.3.6.1.5.2.3.5"  # KDC Authentication
        )
        
        foreach ($eku in $ekus) {
            if ($eku -in $dangerousEKUs) {
                $issues += "Template has authentication EKU: $eku"
                if ($riskLevel -eq "Low") {
                    $riskLevel = "Medium"
                }
            }
        }
        
        # Check 3: No manager approval required?
        $enrollmentFlag = if ($template.'mspki-enrollment-flag') {
            if ($template.'mspki-enrollment-flag' -is [Array]) { 
                $template.'mspki-enrollment-flag'[0] 
            } else { 
                $template.'mspki-enrollment-flag' 
            }
        } else { 0 }
        
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
        $templateDN = if ($template.distinguishedname) {
            if ($template.distinguishedname -is [Array]) { 
                $template.distinguishedname[0] 
            } else { 
                $template.distinguishedname 
            }
        } else { "" }
        
        if ($templateDN) {
            try {
                $templateACL = Get-IVTemplateACL -TemplateDN $templateDN
                $enrollmentRights = @()
                $autoEnrollmentRights = @()
                
                foreach ($ace in $templateACL.Access) {
                    if ($ace.AccessControlType -eq "Allow") {
                        # Check for enrollment permissions
                        if ($ace.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) {
                            # Check specific extended rights
                            $rightGuid = $ace.ObjectType
                            
                            # Enrollment right GUID
                            if ($rightGuid -eq [guid]"0e10c968-78fb-11d2-90d4-00c04f79dc55" -or 
                                $rightGuid -eq [guid]"00000000-0000-0000-0000-000000000000") {
                                $enrollmentRights += $ace.IdentityReference.Value
                            }
                            
                            # AutoEnrollment right GUID
                            if ($rightGuid -eq [guid]"a05b8cc2-17bc-4802-a710-e7c15ab866a2") {
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
            }
            catch {
                # Unable to get ACL
            }
        }
        
        # Check 5: Certificate validity period
        $templateOID = if ($template.'mspki-cert-template-oid') {
            if ($template.'mspki-cert-template-oid' -is [Array]) { 
                $template.'mspki-cert-template-oid'[0] 
            } else { 
                $template.'mspki-cert-template-oid' 
            }
        } else { "" }
        
        # Check 6: Check for ESC3 - Certificate Request Agent
        if ($ekus -contains "1.3.6.1.4.1.311.20.2.1") {  # Certificate Request Agent
            $issues += "Template allows Certificate Request Agent (ESC3 vulnerability)"
            $riskLevel = "High"
        }
        
        # Check 7: Check if domain controller authentication is enabled
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
    
    # Check for published Certificate Authorities using ADSI
    $caContainer = "CN=Enrollment Services,CN=Public Key Services,CN=Services,$configDN"
    try {
        $filter = "(objectClass=pKIEnrollmentService)"
        $cas = Search-IVADObjects -Filter $filter -SearchBase $caContainer -Properties @('cn', 'flags', 'cACertificate')
        
        foreach ($ca in $cas) {
            # Check if CA has insecure flags
            $caFlags = if ($ca.flags) {
                if ($ca.flags -is [Array]) { $ca.flags[0] } else { $ca.flags }
            } else { 0 }
            
            if ($caFlags) {
                $caIssues = @()
                
                # Check various CA flags for security issues
                if ($caFlags -band 0x00000001) {  # NO_TEMPLATE_SUPPORT
                    $caIssues += "CA does not enforce template settings"
                }
                
                if ($caIssues.Count -gt 0) {
                    $caName = if ($ca.cn) { 
                        if ($ca.cn -is [Array]) { $ca.cn[0] } else { $ca.cn }
                    } else { "Unknown CA" }
                    
                    $findings += @{
                        ObjectName = $caName
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
        $cas = @()
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