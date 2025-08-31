<#
.SYNOPSIS
Detects if Security Defaults are not enabled in Entra ID tenant settings

.METADATA
{
  "id": "EID-T3-002",
  "name": "Security Defaults Not Enabled",
  "description": "Microsoft's Security Defaults provide a baseline level of security for Entra ID tenants by enforcing MFA for administrative roles, blocking legacy authentication, and requiring MFA for all users. This check verifies that Security Defaults are enabled unless replaced by equivalent Conditional Access policies.",
  "category": "Authentication",
  "severity": "Medium",
  "weight": 6,
  "impact": 6,
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
        Import-Module Microsoft.Graph.Reports -ErrorAction SilentlyContinue
        
        # Check if already connected
        $context = Get-MgContext -ErrorAction SilentlyContinue
        
        if (-not $context) {
            # Need to connect - for automated scenarios, this would need pre-configured auth
            throw "Not connected to Microsoft Graph. Please run Connect-MgGraph first with appropriate permissions (Policy.Read.All, SecurityEvents.Read.All, Directory.Read.All)"
        }
        
        # Use provided TenantId or get from context
        if (-not $TenantId) {
            $TenantId = $context.TenantId
        }
        
        # Get Security Defaults status
        $securityDefaultsEnabled = $false
        $securityDefaultsStatus = "Unknown"
        
        try {
            # Get the organization settings for security defaults
            $orgSettings = Get-MgOrganization -OrganizationId $TenantId -Property SecurityComplianceNotificationPhones,SecurityComplianceNotificationMails,TechnicalNotificationMails,AssignedPlans,Id,DisplayName
            
            # Check for security defaults policy
            $defaultPolicy = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy -ErrorAction SilentlyContinue
            if ($defaultPolicy) {
                $securityDefaultsEnabled = $defaultPolicy.IsEnabled
                $securityDefaultsStatus = if ($defaultPolicy.IsEnabled) { "Enabled" } else { "Disabled" }
            }
        }
        catch {
            # Try alternative method
            $securityDefaultsStatus = "Unable to determine"
        }
        
        # Get Conditional Access policies to check for equivalent protection
        $caPolicies = @()
        $equivalentProtection = $false
        $protectionGaps = @()
        
        try {
            $caPolicies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction SilentlyContinue
            
            # Check for policies that provide equivalent protection to Security Defaults
            $hasMfaForAdmins = $false
            $hasMfaForAllUsers = $false
            $hasLegacyAuthBlock = $false
            $hasRiskBasedMfa = $false
            $hasAzureManagementMfa = $false
            
            foreach ($policy in $caPolicies) {
                if ($policy.State -ne "enabled") {
                    continue
                }
                
                # Check for MFA requirement
                $requiresMfa = $policy.GrantControls.BuiltInControls -contains "mfa"
                
                # Check for admin MFA
                if ($requiresMfa -and $policy.Conditions.Users.IncludeRoles.Count -gt 0) {
                    $hasMfaForAdmins = $true
                }
                
                # Check for all users MFA
                if ($requiresMfa -and ($policy.Conditions.Users.IncludeUsers -contains "All" -or 
                    $policy.Conditions.Users.IncludeGroups -contains "All")) {
                    $hasMfaForAllUsers = $true
                }
                
                # Check for legacy auth blocking
                if ($policy.Conditions.ClientAppTypes -contains "exchangeActiveSync" -or
                    $policy.Conditions.ClientAppTypes -contains "other") {
                    if ($policy.GrantControls.BuiltInControls -contains "block") {
                        $hasLegacyAuthBlock = $true
                    }
                }
                
                # Check for risk-based policies
                if ($policy.Conditions.UserRiskLevels.Count -gt 0 -or 
                    $policy.Conditions.SignInRiskLevels.Count -gt 0) {
                    $hasRiskBasedMfa = $true
                }
                
                # Check for Azure Management protection
                if ($policy.Conditions.Applications.IncludeApplications -contains "797f4846-ba00-4fd7-ba43-dac1f8f63013") {
                    if ($requiresMfa) {
                        $hasAzureManagementMfa = $true
                    }
                }
            }
            
            # Determine if CA policies provide equivalent protection
            if ($hasMfaForAdmins -and $hasLegacyAuthBlock) {
                $equivalentProtection = $true
            }
            
            # Track protection gaps
            if (-not $hasMfaForAdmins) {
                $protectionGaps += "No MFA requirement for administrative roles"
            }
            if (-not $hasMfaForAllUsers -and -not $hasRiskBasedMfa) {
                $protectionGaps += "No MFA requirement for all users or risk-based MFA"
            }
            if (-not $hasLegacyAuthBlock) {
                $protectionGaps += "Legacy authentication protocols not blocked"
            }
            if (-not $hasAzureManagementMfa) {
                $protectionGaps += "Azure Management not protected with MFA"
            }
        }
        catch {
            # Unable to check Conditional Access policies
            $protectionGaps += "Unable to verify Conditional Access policies"
        }
        
        # Get authentication method statistics
        $authMethodStats = @{
            MfaCapable = 0
            MfaRegistered = 0
            PasswordlessCapable = 0
            TotalUsers = 0
        }
        
        try {
            $authMethodsReport = Get-MgReportAuthenticationMethodUserRegistrationDetail -All -ErrorAction SilentlyContinue
            $authMethodStats.TotalUsers = @($authMethodsReport).Count
            $authMethodStats.MfaCapable = @($authMethodsReport | Where-Object { $_.IsMfaCapable }).Count
            $authMethodStats.MfaRegistered = @($authMethodsReport | Where-Object { $_.IsMfaRegistered }).Count
            $authMethodStats.PasswordlessCapable = @($authMethodsReport | Where-Object { $_.IsPasswordlessCapable }).Count
        }
        catch {
            # Unable to get authentication method statistics
        }
        
        # Calculate MFA coverage percentage
        $mfaCoverage = if ($authMethodStats.TotalUsers -gt 0) {
            [Math]::Round(($authMethodStats.MfaRegistered / $authMethodStats.TotalUsers) * 100, 2)
        } else { 0 }
        
        # Finding 1: Security Defaults disabled without equivalent CA policies
        if (-not $securityDefaultsEnabled -and -not $equivalentProtection) {
            $gapDescription = if ($protectionGaps.Count -gt 0) {
                "Protection gaps identified: " + ($protectionGaps -join "; ")
            } else {
                "No Conditional Access policies found providing baseline security"
            }
            
            $findings += @{
                ObjectName = "Security Defaults"
                ObjectType = "TenantSettings"
                RiskLevel = "Medium"
                Description = "Security Defaults are disabled and no equivalent Conditional Access policies are in place. $gapDescription. This leaves the tenant vulnerable to common identity attacks."
                Remediation = "1. Enable Security Defaults immediately for baseline protection. " +
                             "2. Navigate to Azure Active Directory > Properties > Manage Security defaults. " +
                             "3. Set 'Enable Security defaults' to 'Yes'. " +
                             "4. OR create comprehensive Conditional Access policies that: " +
                             "   - Require MFA for all administrators " +
                             "   - Block legacy authentication protocols " +
                             "   - Require MFA for Azure Management " +
                             "   - Implement risk-based MFA for all users " +
                             "5. Monitor authentication logs for blocked legacy auth attempts. " +
                             "6. Communicate changes to users and provide MFA enrollment guidance."
                AffectedAttributes = @("SecurityDefaults", "ConditionalAccessPolicies", "MfaRequirements")
            }
        }
        # Finding 2: Security Defaults disabled with partial CA coverage
        elseif (-not $securityDefaultsEnabled -and $equivalentProtection -and $protectionGaps.Count -gt 0) {
            $findings += @{
                ObjectName = "Security Configuration"
                ObjectType = "TenantSettings"
                RiskLevel = "Low"
                Description = "Security Defaults are disabled and replaced with Conditional Access policies, but some protection gaps exist: $($protectionGaps -join '; '). Consider addressing these gaps for comprehensive security."
                Remediation = "1. Review and enhance existing Conditional Access policies. " +
                             "2. Address identified protection gaps: " +
                             "   - Ensure MFA is required for all users or implement risk-based MFA " +
                             "   - Block all legacy authentication protocols " +
                             "   - Protect Azure Management with MFA requirement " +
                             "3. Consider implementing additional security measures: " +
                             "   - Password protection policies " +
                             "   - Identity Protection risk policies " +
                             "   - Privileged Identity Management (PIM)"
                AffectedAttributes = @("ConditionalAccessPolicies", "ProtectionGaps")
            }
        }
        
        # Finding 3: Low MFA registration despite security policies
        if (($securityDefaultsEnabled -or $equivalentProtection) -and $mfaCoverage -lt 80) {
            $findings += @{
                ObjectName = "MFA Registration Coverage"
                ObjectType = "AuthenticationMethods"
                RiskLevel = "Medium"
                Description = "Only $mfaCoverage% of users have registered for MFA despite security policies being in place. $($authMethodStats.TotalUsers - $authMethodStats.MfaRegistered) users have not completed MFA registration."
                Remediation = "1. Launch MFA registration campaign for all users. " +
                             "2. Set up registration nudges and reminders. " +
                             "3. Provide clear MFA setup documentation and support. " +
                             "4. Use Conditional Access to require MFA registration. " +
                             "5. Monitor registration progress through authentication methods reports. " +
                             "6. Consider implementing temporary access passes for initial setup. " +
                             "7. Target users without MFA with specific communications."
                AffectedAttributes = @("MfaRegistration", "UserCompliance")
            }
        }
        
        # Finding 4: Security Defaults enabled but should use CA for advanced scenarios
        if ($securityDefaultsEnabled -and $authMethodStats.TotalUsers -gt 500) {
            $findings += @{
                ObjectName = "Security Policy Configuration"
                ObjectType = "TenantSettings"
                RiskLevel = "Low"
                Description = "Security Defaults are enabled for a tenant with $($authMethodStats.TotalUsers) users. For organizations of this size, Conditional Access policies provide more granular control and advanced security features."
                Remediation = "1. Plan migration from Security Defaults to Conditional Access. " +
                             "2. Design CA policies that match your organization's needs: " +
                             "   - Different policies for different user groups " +
                             "   - Location-based access controls " +
                             "   - Device compliance requirements " +
                             "   - Application-specific policies " +
                             "3. Test CA policies with pilot groups before full deployment. " +
                             "4. Maintain Security Defaults until CA policies are fully tested. " +
                             "5. Document the security policy framework."
                AffectedAttributes = @("PolicyGranularity", "AdvancedFeatures")
            }
        }
        
        # Finding 5: Check for specific vulnerable configurations
        if (-not $securityDefaultsEnabled -and $caPolicies.Count -gt 0) {
            # Check for report-only policies that should be enforced
            $reportOnlyPolicies = @($caPolicies | Where-Object { $_.State -eq "enabledForReportingButNotEnforced" })
            if ($reportOnlyPolicies.Count -gt 2) {
                $findings += @{
                    ObjectName = "Conditional Access Policies"
                    ObjectType = "PolicyConfiguration"
                    RiskLevel = "Low"
                    Description = "$($reportOnlyPolicies.Count) Conditional Access policies are in report-only mode and not enforcing security. These policies: $($reportOnlyPolicies.DisplayName -join ', ') should be reviewed for production deployment."
                    Remediation = "1. Review report-only policy insights and impact analysis. " +
                                 "2. Address any issues identified during report-only period. " +
                                 "3. Gradually enable policies for production use. " +
                                 "4. Monitor for user impact and adjust as needed. " +
                                 "5. Set timeline for moving all policies to enabled state."
                    AffectedAttributes = @("PolicyEnforcement", "ReportOnlyPolicies")
                }
            }
            
            # Check for disabled policies
            $disabledPolicies = @($caPolicies | Where-Object { $_.State -eq "disabled" })
            if ($disabledPolicies.Count -gt 5) {
                $findings += @{
                    ObjectName = "Disabled Security Policies"
                    ObjectType = "PolicyConfiguration"
                    RiskLevel = "Low"
                    Description = "$($disabledPolicies.Count) Conditional Access policies are disabled, creating policy sprawl and confusion. Consider removing or consolidating unused policies."
                    Remediation = "1. Review all disabled policies for relevance. " +
                                 "2. Delete policies that are no longer needed. " +
                                 "3. Document why certain policies remain disabled. " +
                                 "4. Consider archiving policy configurations before deletion. " +
                                 "5. Implement policy lifecycle management process."
                    AffectedAttributes = @("PolicyManagement", "DisabledPolicies")
                }
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
    $message = "Security Defaults and baseline protection analysis completed successfully."
    
    if ($findings.Count -gt 0) {
        $mediumCount = @($findings | Where-Object { $_.RiskLevel -eq "Medium" }).Count
        $lowCount = @($findings | Where-Object { $_.RiskLevel -eq "Low" }).Count
        
        if ($mediumCount -gt 0) {
            $score = 50  # Medium findings
            $message = "Found $mediumCount medium-risk issues with security baseline configuration. Tenant lacks proper baseline security protection."
        }
        else {
            $score = 75  # Only low-risk findings
            $message = "Found $lowCount low-risk security configuration improvements. Baseline protection is present but could be enhanced."
        }
    }
    else {
        if ($securityDefaultsEnabled) {
            $message = "Security Defaults are enabled, providing baseline protection for the tenant."
        }
        else {
            $message = "Security Defaults are disabled but comprehensive Conditional Access policies provide equivalent or better protection."
        }
    }
    
    return @{
        CheckId = "EID-T3-002"
        Timestamp = (Get-Date).ToString("o")
        Status = $status
        Score = $score
        Severity = "Medium"
        Category = "Authentication"
        Findings = $findings
        Message = $message
        AffectedObjects = $findings.Count
        IgnoredObjects = 0
        Metadata = @{
            TenantId = $TenantId
            ExecutionTime = [Math]::Round($executionTime, 2)
            SecurityDefaultsEnabled = $securityDefaultsEnabled
            ConditionalAccessPolicyCount = $caPolicies.Count
            EquivalentProtection = $equivalentProtection
            ProtectionGaps = $protectionGaps
            MfaCoveragePercentage = $mfaCoverage
            TotalUsers = $authMethodStats.TotalUsers
            MfaRegisteredUsers = $authMethodStats.MfaRegistered
        }
    }
}
catch {
    return @{
        CheckId = "EID-T3-002"
        Timestamp = (Get-Date).ToString("o")
        Status = "Error"
        Score = 0
        Severity = "Medium"
        Category = "Authentication"
        Findings = @()
        Message = "Error analyzing Security Defaults configuration: $_"
        AffectedObjects = 0
        IgnoredObjects = 0
        Metadata = @{
            TenantId = $TenantId
            ExecutionTime = 0.0
            ErrorDetails = $_.Exception.Message
        }
    }
}