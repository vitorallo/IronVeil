<#
.SYNOPSIS
Detects if Entra ID Password Protection for on-premises Active Directory is not configured

.METADATA
{
  "id": "EID-T4-003",
  "name": "Password Protection Not Configured",
  "description": "Entra ID Password Protection for on-premises Active Directory is not configured. This feature helps prevent weak passwords by evaluating password changes against Microsoft's global banned password list and custom banned passwords, significantly improving password security across hybrid environments.",
  "category": "Authentication",
  "severity": "Low",
  "weight": 3,
  "impact": 4,
  "frameworks": ["MITRE", "NIST"],
  "targets": ["EntraID"]
}
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$TenantId
)

try {
    $startTime = Get-Date
    $findings = @()
    
    # Check if Microsoft.Graph module is available
    $graphModuleAvailable = $null -ne (Get-Module -ListAvailable -Name Microsoft.Graph)
    
    if ($graphModuleAvailable) {
        # Import required modules
        Import-Module Microsoft.Graph.Identity.DirectoryManagement -ErrorAction SilentlyContinue
        Import-Module Microsoft.Graph.Identity.SignIns -ErrorAction SilentlyContinue
        Import-Module Microsoft.Graph.Beta.Identity.DirectoryManagement -ErrorAction SilentlyContinue
        
        # Check if already connected
        $context = Get-MgContext -ErrorAction SilentlyContinue
        
        if (-not $context) {
            # Need to connect - for automated scenarios, this would need pre-configured auth
            throw "Not connected to Microsoft Graph. Please run Connect-MgGraph first with appropriate permissions (Directory.Read.All, Policy.Read.All)"
        }
        
        # Use provided TenantId or get from context
        if (-not $TenantId) {
            $TenantId = $context.TenantId
        }
        
        # Get Azure AD Password Protection settings
        # Note: This requires beta endpoint for some settings
        $passwordProtectionConfigured = $false
        $customBannedPasswordsConfigured = $false
        $customBannedPasswordList = @()
        $enableBannedPasswordCheck = $false
        $enableBannedPasswordCheckOnPremises = $false
        $lockoutThreshold = 0
        $lockoutDuration = 0
        
        # Try to get directory settings related to password protection
        try {
            # Get banned password settings
            $directorySettings = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/settings" -ErrorAction SilentlyContinue
            
            if ($directorySettings -and $directorySettings.value) {
                foreach ($setting in $directorySettings.value) {
                    if ($setting.displayName -eq "Password Rule Settings" -or 
                        $setting.templateId -eq "5cf42378-d67d-4f36-ba46-e8b86229381d") {
                        
                        foreach ($value in $setting.values) {
                            switch ($value.name) {
                                "BannedPasswordCheckOnPremisesMode" {
                                    # Enforced or Audit mode
                                    $enableBannedPasswordCheckOnPremises = $value.value -ne "Disabled"
                                }
                                "EnableBannedPasswordCheck" {
                                    $enableBannedPasswordCheck = [System.Convert]::ToBoolean($value.value)
                                }
                                "BannedPasswordList" {
                                    if (![string]::IsNullOrWhiteSpace($value.value)) {
                                        $customBannedPasswordList = $value.value -split ","
                                        $customBannedPasswordsConfigured = $customBannedPasswordList.Count -gt 0
                                    }
                                }
                                "LockoutThreshold" {
                                    $lockoutThreshold = [int]$value.value
                                }
                                "LockoutDurationInSeconds" {
                                    $lockoutDuration = [int]$value.value
                                }
                            }
                        }
                        $passwordProtectionConfigured = $true
                    }
                }
            }
        }
        catch {
            # Settings might not be accessible or configured
            Write-Verbose "Could not retrieve password protection settings: $_"
        }
        
        # Check authentication methods policy for password settings
        try {
            $authMethodsPolicy = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/policies/authenticationMethodsPolicy" -ErrorAction SilentlyContinue
            
            if ($authMethodsPolicy) {
                # Check if password method is configured with complexity requirements
                foreach ($method in $authMethodsPolicy.authenticationMethodConfigurations) {
                    if ($method.'@odata.type' -eq "#microsoft.graph.passwordAuthenticationMethodConfiguration") {
                        # Additional password protection settings might be here
                        if ($method.state -eq "enabled") {
                            # Password authentication is enabled
                        }
                    }
                }
            }
        }
        catch {
            Write-Verbose "Could not retrieve authentication methods policy: $_"
        }
        
        # Check if Azure AD Connect is configured (indicates hybrid environment)
        $isHybridEnvironment = $false
        try {
            # Check for sync status
            $organization = Get-MgOrganization -ErrorAction SilentlyContinue
            if ($organization) {
                $isHybridEnvironment = $organization.OnPremisesSyncEnabled -eq $true
            }
        }
        catch {
            Write-Verbose "Could not determine hybrid status: $_"
        }
        
        # Finding 1: Password Protection not enabled for on-premises
        if ($isHybridEnvironment -and -not $enableBannedPasswordCheckOnPremises) {
            $findings += @{
                ObjectName = "Azure AD Password Protection"
                ObjectType = "TenantSettings"
                RiskLevel = "Low"
                Description = "Azure AD Password Protection is not enabled for on-premises Active Directory in this hybrid environment. Users can set weak passwords that would be blocked in cloud-only scenarios, creating inconsistent security between cloud and on-premises."
                Remediation = "1. Deploy Azure AD Password Protection proxy service on servers in your on-premises environment. " +
                             "2. Install Azure AD Password Protection DC agents on all domain controllers. " +
                             "3. Configure the service to connect to your Azure AD tenant. " +
                             "4. Set BannedPasswordCheckOnPremisesMode to 'Audit' initially to monitor impact. " +
                             "5. Review audit logs to understand password change patterns. " +
                             "6. Switch to 'Enforced' mode after validation period. " +
                             "7. Configure custom banned password list for organization-specific terms. " +
                             "8. Monitor password protection events in DC agent event logs."
                AffectedAttributes = @("BannedPasswordCheckOnPremisesMode", "EnableBannedPasswordCheck")
            }
        }
        
        # Finding 2: Custom banned passwords not configured
        if (-not $customBannedPasswordsConfigured -or $customBannedPasswordList.Count -eq 0) {
            $findings += @{
                ObjectName = "Custom Banned Password List"
                ObjectType = "TenantSettings"
                RiskLevel = "Low"
                Description = "No custom banned passwords are configured. Without organization-specific banned terms, users can create passwords using company name, products, or other predictable terms that are targeted by attackers."
                Remediation = "1. Navigate to Azure AD > Security > Authentication methods > Password protection. " +
                             "2. Add organization-specific terms to custom banned password list: " +
                             "   - Company name and variations " +
                             "   - Product names and acronyms " +
                             "   - Local sports teams or landmarks " +
                             "   - Industry-specific terminology " +
                             "3. Include common variations (with numbers, special characters). " +
                             "4. Limit list to most important terms (max 1000 entries). " +
                             "5. Test impact in audit mode before enforcement. " +
                             "6. Regularly review and update the list."
                AffectedAttributes = @("BannedPasswordList", "CustomBannedPasswords")
            }
        }
        
        # Finding 3: Password protection not enabled at all
        if (-not $enableBannedPasswordCheck) {
            $findings += @{
                ObjectName = "Global Banned Password Check"
                ObjectType = "TenantSettings"
                RiskLevel = "Low"
                Description = "Global banned password checking is not enabled. Microsoft's constantly updated list of commonly used and compromised passwords is not being enforced, allowing users to set weak passwords."
                Remediation = "1. Enable banned password check in Azure AD password protection settings. " +
                             "2. This automatically applies Microsoft's global banned password list. " +
                             "3. The list is continuously updated based on real-world password breaches. " +
                             "4. No additional configuration needed for basic protection. " +
                             "5. Combines with custom banned list for comprehensive protection. " +
                             "6. Monitor sign-in risk events related to password compromise."
                AffectedAttributes = @("EnableBannedPasswordCheck", "GlobalBannedPasswordList")
            }
        }
        
        # Finding 4: Weak lockout settings
        if ($passwordProtectionConfigured -and $lockoutThreshold -lt 3) {
            $findings += @{
                ObjectName = "Smart Lockout Configuration"
                ObjectType = "TenantSettings"
                RiskLevel = "Low"
                Description = "Smart lockout threshold is set to $lockoutThreshold attempts, which may not provide adequate protection against password spray attacks. A higher threshold balances security with user experience."
                Remediation = "1. Set smart lockout threshold to 5-10 failed attempts. " +
                             "2. Configure lockout duration of at least 60 seconds. " +
                             "3. Enable familiar location detection to reduce false positives. " +
                             "4. Monitor lockout events for attack patterns. " +
                             "5. Consider implementing risk-based authentication. " +
                             "6. Use Conditional Access for additional protection."
                AffectedAttributes = @("LockoutThreshold", "LockoutDuration")
            }
        }
        
        # Finding 5: No password protection configuration found
        if (-not $passwordProtectionConfigured) {
            $findings += @{
                ObjectName = "Password Protection Settings"
                ObjectType = "TenantSettings"
                RiskLevel = "Low"
                Description = "Password protection settings are not configured or accessible. Default settings may apply, but explicit configuration ensures consistent password security policies across the organization."
                Remediation = "1. Configure password protection settings explicitly: " +
                             "   - Enable banned password check globally " +
                             "   - Add custom banned passwords " +
                             "   - Configure smart lockout settings " +
                             "2. For hybrid environments, deploy on-premises components. " +
                             "3. Set up monitoring and alerting for password-related events. " +
                             "4. Implement password expiration policies if required. " +
                             "5. Consider passwordless authentication methods. " +
                             "6. Regular security awareness training on password hygiene."
                AffectedAttributes = @("PasswordProtection", "Configuration")
            }
        }
        
        # Finding 6: Check for weak password policies in general
        if ($customBannedPasswordList.Count -gt 0 -and $customBannedPasswordList.Count -lt 10) {
            $findings += @{
                ObjectName = "Custom Banned Password List Size"
                ObjectType = "Configuration"
                RiskLevel = "Low"
                Description = "Only $($customBannedPasswordList.Count) custom banned passwords are configured. This minimal list may not adequately prevent organization-specific weak passwords."
                Remediation = "1. Expand custom banned password list to include: " +
                             "   - Company name variations (min 5-10) " +
                             "   - Major products/services (10-20) " +
                             "   - Location-based terms (5-10) " +
                             "   - Department names and acronyms " +
                             "2. Include number and special character variations. " +
                             "3. Add seasonal terms that might be used (Summer2024, etc.). " +
                             "4. Review password reset tickets for commonly attempted passwords. " +
                             "5. Benchmark against industry standards for your sector."
                AffectedAttributes = @("BannedPasswordList", "ListSize")
            }
        }
    }
    else {
        # Fallback method using Azure AD PowerShell or direct API calls
        throw "Microsoft.Graph module not available. Please install with: Install-Module Microsoft.Graph -Scope CurrentUser"
    }
    
    # Calculate execution time
    $executionTime = ((Get-Date) - $startTime).TotalSeconds
    
    # Determine final score and status
    $score = 100  # Start with perfect score
    $status = "Success"
    $message = "Password protection configuration analysis completed successfully."
    
    if ($findings.Count -gt 0) {
        $score = 75  # Low-risk findings
        $message = "Found $($findings.Count) password protection configuration issues that should be addressed to improve security."
    }
    else {
        $message = "Password protection is properly configured. Both global and custom banned passwords are enforced."
    }
    
    return @{
        CheckId = "EID-T4-003"
        Timestamp = (Get-Date).ToString("o")
        Status = $status
        Score = $score
        Severity = "Low"
        Category = "Authentication"
        Findings = $findings
        Message = $message
        AffectedObjects = $findings.Count
        IgnoredObjects = 0
        Metadata = @{
            TenantId = $TenantId
            ExecutionTime = [Math]::Round($executionTime, 2)
            IsHybridEnvironment = $isHybridEnvironment
            PasswordProtectionConfigured = $passwordProtectionConfigured
            CustomBannedPasswordCount = $customBannedPasswordList.Count
            OnPremisesProtectionEnabled = $enableBannedPasswordCheckOnPremises
        }
    }
}
catch {
    return @{
        CheckId = "EID-T4-003"
        Timestamp = (Get-Date).ToString("o")
        Status = "Error"
        Score = 0
        Severity = "Low"
        Category = "Authentication"
        Findings = @()
        Message = "Error analyzing password protection configuration: $_"
        AffectedObjects = 0
        IgnoredObjects = 0
        Metadata = @{
            TenantId = $TenantId
            ExecutionTime = 0.0
            ErrorDetails = $_.Exception.Message
        }
    }
}