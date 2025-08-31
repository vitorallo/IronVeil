<#
.SYNOPSIS
Detects unrestricted user consent for applications in Entra ID

.METADATA
{
  "id": "EID-T2-002",
  "name": "Unrestricted User Consent for Applications",
  "description": "If unrestricted user consent is allowed, users can grant permissions to malicious applications to access company data. This check examines Entra ID user consent settings to determine if users are allowed to consent to applications from unverified publishers.",
  "category": "Authorization",
  "severity": "High",
  "weight": 7,
  "impact": 8,
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
        Import-Module Microsoft.Graph.Applications -ErrorAction SilentlyContinue
        Import-Module Microsoft.Graph.Identity.SignIns -ErrorAction SilentlyContinue
        
        # Check if already connected
        $context = Get-MgContext -ErrorAction SilentlyContinue
        
        if (-not $context) {
            # Need to connect - for automated scenarios, this would need pre-configured auth
            throw "Not connected to Microsoft Graph. Please run Connect-MgGraph first with appropriate permissions (Policy.Read.All, Application.Read.All, Directory.Read.All)"
        }
        
        # Use provided TenantId or get from context
        if (-not $TenantId) {
            $TenantId = $context.TenantId
        }
        
        # Get authorization policy (contains consent settings)
        $authPolicy = Get-MgPolicyAuthorizationPolicy -ErrorAction SilentlyContinue
        
        $consentRiskLevel = "Low"
        $consentIssues = @()
        $allowUserConsent = $false
        $allowedToCreateApps = $false
        $allowedGroupIds = @()
        
        if ($authPolicy) {
            # Check default user role permissions
            $defaultUserRole = $authPolicy.DefaultUserRolePermissions
            
            if ($defaultUserRole) {
                # Check if users can create applications
                if ($defaultUserRole.AllowedToCreateApps) {
                    $allowedToCreateApps = $true
                    $consentIssues += "Users are allowed to register/create applications"
                }
                
                # Check if users can create security groups
                if ($defaultUserRole.AllowedToCreateSecurityGroups) {
                    $consentIssues += "Users are allowed to create security groups"
                }
                
                # Check user consent permissions
                $permissionGrantPolicy = $defaultUserRole.PermissionGrantPoliciesAssigned
                
                if ($permissionGrantPolicy) {
                    foreach ($policyId in $permissionGrantPolicy) {
                        if ($policyId -eq "microsoft-user-default-legacy") {
                            # Legacy policy - users can consent to any app
                            $allowUserConsent = $true
                            $consentRiskLevel = "Critical"
                            $consentIssues += "CRITICAL: Legacy user consent policy active - users can consent to ANY application"
                        }
                        elseif ($policyId -eq "microsoft-user-default-low") {
                            # Users can consent to low-risk permissions
                            $allowUserConsent = $true
                            $consentRiskLevel = "Medium"
                            $consentIssues += "Users can consent to applications with low-risk permissions"
                        }
                        elseif ($policyId -eq "microsoft-user-default-recommended") {
                            # Recommended - users can consent to verified publishers only
                            $allowUserConsent = $true
                            $consentRiskLevel = "Low"
                            $consentIssues += "Users can consent to applications from verified publishers only (recommended setting)"
                        }
                        elseif ($policyId -like "ManagePermissionGrantsForSelf.*") {
                            $allowUserConsent = $true
                            $consentRiskLevel = "High"
                            $consentIssues += "Users can manage their own consent permissions"
                        }
                    }
                }
            }
        }
        
        # Check for custom permission grant policies
        try {
            $permissionGrantPolicies = Get-MgPolicyPermissionGrantPolicy -All -ErrorAction SilentlyContinue
            
            foreach ($policy in $permissionGrantPolicies) {
                if ($policy.Id -notlike "microsoft-*") {
                    # Custom policy found
                    $conditions = $policy.Conditions
                    $includes = $policy.Includes
                    
                    $policyRisk = "Medium"
                    $policyDetails = "Custom permission grant policy: $($policy.DisplayName)"
                    
                    if ($includes) {
                        foreach ($include in $includes) {
                            if ($include.PermissionType -eq "application") {
                                # Application permissions (more dangerous)
                                $policyRisk = "High"
                                $policyDetails += ". Allows application permissions"
                            }
                            
                            if ($include.ClientApplicationIds -contains "*" -or 
                                $include.ClientApplicationIds.Count -eq 0) {
                                # Applies to all applications
                                $policyRisk = "High"
                                $policyDetails += ". Applies to all applications"
                            }
                        }
                    }
                    
                    if ($policyRisk -eq "High" -and $consentRiskLevel -ne "Critical") {
                        $consentRiskLevel = "High"
                    }
                    
                    $consentIssues += $policyDetails
                }
            }
        }
        catch {
            # Unable to enumerate custom policies
        }
        
        # Check consent requests and admin consent workflow
        $adminConsentWorkflow = $false
        try {
            # Check if admin consent request settings exist
            $adminConsentRequestPolicy = Get-MgPolicyAdminConsentRequestPolicy -ErrorAction SilentlyContinue
            
            if ($adminConsentRequestPolicy) {
                if ($adminConsentRequestPolicy.IsEnabled) {
                    $adminConsentWorkflow = $true
                    $consentIssues += "Admin consent workflow is enabled (good practice)"
                }
                else {
                    $consentIssues += "Admin consent workflow is disabled - users cannot request admin review"
                }
            }
        }
        catch {
            # Unable to check admin consent workflow
        }
        
        # Analyze recently consented applications
        $riskyConsentedApps = @()
        try {
            # Get OAuth2 permission grants (delegated permissions)
            $oauth2Grants = Get-MgOauth2PermissionGrant -All -ErrorAction SilentlyContinue
            
            # Group by client application
            $appConsents = @{}
            foreach ($grant in $oauth2Grants) {
                $clientId = $grant.ClientId
                if (-not $appConsents.ContainsKey($clientId)) {
                    $appConsents[$clientId] = @{
                        Scopes = @()
                        ConsentType = $grant.ConsentType
                        PrincipalId = $grant.PrincipalId
                    }
                }
                $appConsents[$clientId].Scopes += $grant.Scope -split " "
            }
            
            # Check each consented application
            foreach ($clientId in $appConsents.Keys) {
                $consent = $appConsents[$clientId]
                $sp = Get-MgServicePrincipal -ServicePrincipalId $clientId -ErrorAction SilentlyContinue
                
                if ($sp) {
                    $appRisk = "Low"
                    $riskFactors = @()
                    
                    # Check if app is from verified publisher
                    if (-not $sp.VerifiedPublisher -or -not $sp.VerifiedPublisher.VerifiedPublisherId) {
                        $appRisk = "Medium"
                        $riskFactors += "Unverified publisher"
                    }
                    
                    # Check for risky scopes
                    $riskyScopes = @("Mail.ReadWrite", "Files.ReadWrite.All", "Sites.FullControl.All", 
                                    "Directory.ReadWrite.All", "User.ReadWrite.All", "Group.ReadWrite.All")
                    
                    $grantedRiskyScopes = @($consent.Scopes | Where-Object { $riskyScopes -contains $_ })
                    if ($grantedRiskyScopes.Count -gt 0) {
                        $appRisk = "High"
                        $riskFactors += "High-risk permissions: $($grantedRiskyScopes -join ', ')"
                    }
                    
                    # Check consent type
                    if ($consent.ConsentType -eq "AllPrincipals") {
                        $appRisk = "High"
                        $riskFactors += "Admin consented for all users"
                    }
                    
                    # Check app age
                    if ($sp.CreatedDateTime) {
                        $appAge = (Get-Date) - $sp.CreatedDateTime
                        if ($appAge.Days -lt 30) {
                            $riskFactors += "Recently created app (< 30 days)"
                        }
                    }
                    
                    if ($appRisk -ne "Low") {
                        $riskyConsentedApps += @{
                            AppName = $sp.DisplayName
                            AppId = $sp.AppId
                            Risk = $appRisk
                            Factors = $riskFactors -join ". "
                        }
                    }
                }
            }
        }
        catch {
            # Unable to analyze consented applications
        }
        
        # Create findings based on analysis
        if ($allowUserConsent -and $consentRiskLevel -in @("Critical", "High")) {
            $remediation = if ($consentRiskLevel -eq "Critical") {
                "1. IMMEDIATE ACTION REQUIRED: Disable user consent immediately in Azure AD. " +
                "2. Navigate to Enterprise applications > User settings > Users can consent to apps. " +
                "3. Set to 'Do not allow user consent' or 'Allow for verified publishers only'. " +
                "4. Enable admin consent workflow for user requests. " +
                "5. Review all recently consented applications for suspicious activity. " +
                "6. Revoke consent for unnecessary applications. " +
                "7. Implement application governance policies."
            }
            else {
                "1. Restrict user consent to verified publishers only. " +
                "2. Enable admin consent workflow for review process. " +
                "3. Configure permission grant policies appropriately. " +
                "4. Review and audit existing application consents. " +
                "5. Educate users about consent phishing attacks."
            }
            
            $findings += @{
                ObjectName = "User Consent Configuration"
                ObjectType = "Policy"
                RiskLevel = $consentRiskLevel
                Description = "User consent settings allow risky application permissions. Issues: $($consentIssues -join '. ')"
                Remediation = $remediation
                AffectedAttributes = @("DefaultUserRolePermissions", "PermissionGrantPolicies", "ConsentSettings")
            }
        }
        
        # Add finding for app registration if allowed
        if ($allowedToCreateApps) {
            $findings += @{
                ObjectName = "Application Registration Settings"
                ObjectType = "Policy"
                RiskLevel = "Medium"
                Description = "Users are allowed to register/create applications. This could lead to shadow IT and unmanaged applications accessing corporate data."
                Remediation = "1. Restrict application registration to administrators only. " +
                            "2. Navigate to Azure AD > User settings > App registrations. " +
                            "3. Set 'Users can register applications' to No. " +
                            "4. Implement a formal application registration process. " +
                            "5. Regular audit of registered applications."
                AffectedAttributes = @("AllowedToCreateApps", "ApplicationRegistration")
            }
        }
        
        # Add finding if admin consent workflow is disabled
        if (-not $adminConsentWorkflow -and $allowUserConsent) {
            $findings += @{
                ObjectName = "Admin Consent Workflow"
                ObjectType = "Policy"
                RiskLevel = "Medium"
                Description = "Admin consent workflow is not enabled. Users cannot request admin review for applications they need, which may lead to shadow IT or security bypasses."
                Remediation = "1. Enable admin consent workflow in Azure AD. " +
                            "2. Navigate to Enterprise applications > Admin consent settings. " +
                            "3. Configure reviewers and enable the workflow. " +
                            "4. Set up notifications for consent requests. " +
                            "5. Establish SLA for reviewing requests."
                AffectedAttributes = @("AdminConsentRequestPolicy", "ConsentWorkflow")
            }
        }
        
        # Add findings for risky consented applications
        foreach ($riskyApp in $riskyConsentedApps) {
            if ($riskyApp.Risk -eq "High") {
                $findings += @{
                    ObjectName = $riskyApp.AppName
                    ObjectType = "Application"
                    RiskLevel = "High"
                    Description = "Application with risky consent detected. AppId: $($riskyApp.AppId). Risk factors: $($riskyApp.Factors)"
                    Remediation = "1. Review this application's necessity and legitimacy. " +
                                "2. Audit the application's recent activity in sign-in logs. " +
                                "3. Consider revoking consent if not business-critical. " +
                                "4. Verify the publisher and application purpose. " +
                                "5. Check for any data access or suspicious behavior."
                    AffectedAttributes = @("OAuth2PermissionGrants", "ConsentedScopes", "VerifiedPublisher")
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
    $message = "User consent configuration analysis completed successfully."
    
    if ($findings.Count -gt 0) {
        $criticalCount = @($findings | Where-Object { $_.RiskLevel -eq "Critical" }).Count
        $highCount = @($findings | Where-Object { $_.RiskLevel -eq "High" }).Count
        $mediumCount = @($findings | Where-Object { $_.RiskLevel -eq "Medium" }).Count
        
        if ($criticalCount -gt 0) {
            $score = 10  # Critical consent issues
            $message = "CRITICAL: Unrestricted user consent detected! Found $criticalCount critical issues allowing users to grant dangerous permissions to any application."
        }
        elseif ($highCount -gt 0) {
            $score = 25  # High-risk findings
            $message = "WARNING: Found $highCount high-risk consent configurations and $mediumCount medium-risk issues requiring immediate attention."
        }
        else {
            $score = 50  # Medium-risk findings
            $message = "Found $mediumCount medium-risk consent configuration issues that should be reviewed."
        }
    }
    else {
        $message = "User consent is properly restricted. No risky consent configurations detected."
    }
    
    return @{
        CheckId = "EID-T2-002"
        Timestamp = (Get-Date).ToString("o")
        Status = $status
        Score = $score
        Severity = "High"
        Category = "Authorization"
        Findings = $findings
        Message = $message
        AffectedObjects = $findings.Count
        IgnoredObjects = 0
        Metadata = @{
            TenantId = $TenantId
            ExecutionTime = [Math]::Round($executionTime, 2)
            AllowUserConsent = $allowUserConsent
            AllowedToCreateApps = $allowedToCreateApps
            AdminConsentWorkflowEnabled = $adminConsentWorkflow
            RiskyConsentedAppsCount = $riskyConsentedApps.Count
            ConsentRiskLevel = $consentRiskLevel
        }
    }
}
catch {
    return @{
        CheckId = "EID-T2-002"
        Timestamp = (Get-Date).ToString("o")
        Status = "Error"
        Score = 0
        Severity = "High"
        Category = "Authorization"
        Findings = @()
        Message = "Error analyzing user consent configuration: $_"
        AffectedObjects = 0
        IgnoredObjects = 0
        Metadata = @{
            TenantId = $TenantId
            ExecutionTime = 0.0
            ErrorDetails = $_.Exception.Message
        }
    }
}