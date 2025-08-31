<#
.SYNOPSIS
Detects if non-administrative users can register applications in Entra ID

.METADATA
{
  "id": "EID-T3-004",
  "name": "Non-Admin Users Can Register Applications",
  "description": "If non-administrative users can register applications, it opens a potential attack vector where malicious applications can be registered. This check verifies Entra ID user settings to determine if non-administrative users are allowed to register applications.",
  "category": "Authorization",
  "severity": "Medium",
  "weight": 6,
  "impact": 5,
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
        Import-Module Microsoft.Graph.Users -ErrorAction SilentlyContinue
        
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
        
        # Get authorization policy to check user settings
        $authorizationPolicy = Get-MgPolicyAuthorizationPolicy -ErrorAction SilentlyContinue
        
        # Check if users can register applications
        $usersCanRegisterApps = $true  # Default value if not explicitly set
        $usersCanConsentToApps = $true  # Default value
        $defaultUserRolePermissions = $authorizationPolicy.DefaultUserRolePermissions
        
        if ($defaultUserRolePermissions) {
            # Check specific permissions
            $usersCanRegisterApps = $defaultUserRolePermissions.AllowedToCreateApps
            $usersCanConsentToApps = $defaultUserRolePermissions.PermissionGrantPoliciesAssigned.Count -gt 0
            
            # Additional permission checks
            $canCreateSecurityGroups = $defaultUserRolePermissions.AllowedToCreateSecurityGroups
            $canReadOtherUsers = $defaultUserRolePermissions.AllowedToReadOtherUsers
            $canCreateTenants = $defaultUserRolePermissions.AllowedToCreateTenants
        }
        
        # Get application registration statistics
        $allApplications = Get-MgApplication -All -Property Id,DisplayName,CreatedDateTime,SignInAudience,PublisherDomain,VerifiedPublisher,AppId,RequiredResourceAccess,PasswordCredentials,KeyCredentials
        $recentAppsThreshold = (Get-Date).AddDays(-90)
        $recentApps = @($allApplications | Where-Object { $_.CreatedDateTime -gt $recentAppsThreshold })
        
        # Categorize applications
        $multiTenantApps = @($allApplications | Where-Object { 
            $_.SignInAudience -in @("AzureADMultipleOrgs", "AzureADandPersonalMicrosoftAccount") 
        })
        $unverifiedApps = @($allApplications | Where-Object { 
            -not $_.VerifiedPublisher -or $_.VerifiedPublisher.VerifiedPublisherId -eq $null 
        })
        $appsWithSecrets = @($allApplications | Where-Object { 
            ($_.PasswordCredentials -and $_.PasswordCredentials.Count -gt 0) -or
            ($_.KeyCredentials -and $_.KeyCredentials.Count -gt 0)
        })
        
        # Check for high-privilege permissions requested by apps
        $riskyPermissions = @(
            "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9",  # Application.ReadWrite.All
            "06b708a9-e830-4db3-a914-8e69da51d44f",  # AppRoleAssignment.ReadWrite.All
            "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8",  # RoleManagement.ReadWrite.Directory
            "62a82d76-70ea-41e2-9197-370581804d09",  # Group.ReadWrite.All
            "741f803b-c850-494e-b5df-cde7c675a1ca"   # User.ReadWrite.All
        )
        
        $appsWithRiskyPermissions = @()
        foreach ($app in $allApplications) {
            $hasRiskyPermission = $false
            foreach ($resource in $app.RequiredResourceAccess) {
                foreach ($permission in $resource.ResourceAccess) {
                    if ($riskyPermissions -contains $permission.Id) {
                        $hasRiskyPermission = $true
                        break
                    }
                }
                if ($hasRiskyPermission) { break }
            }
            if ($hasRiskyPermission) {
                $appsWithRiskyPermissions += $app
            }
        }
        
        # Get service principals to check for actual consent
        $servicePrincipals = Get-MgServicePrincipal -All -Property Id,AppId,DisplayName,AppRoleAssignments,OAuth2PermissionGrants
        $spWithDelegatedPermissions = @($servicePrincipals | Where-Object { 
            $_.OAuth2PermissionGrants -and $_.OAuth2PermissionGrants.Count -gt 0 
        })
        $spWithAppPermissions = @($servicePrincipals | Where-Object { 
            $_.AppRoleAssignments -and $_.AppRoleAssignments.Count -gt 0 
        })
        
        # Calculate risk metrics
        $appRegistrationRate = if ($allApplications.Count -gt 0) {
            [Math]::Round(($recentApps.Count / $allApplications.Count) * 100, 2)
        } else { 0 }
        
        # Finding 1: Non-admins can register applications
        if ($usersCanRegisterApps) {
            $riskLevel = if ($appsWithRiskyPermissions.Count -gt 5) { "High" } else { "Medium" }
            
            $findings += @{
                ObjectName = "User Application Registration"
                ObjectType = "TenantSettings"
                RiskLevel = $riskLevel
                Description = "Non-administrative users are allowed to register applications. Currently $($allApplications.Count) applications exist with $($recentApps.Count) created in the last 90 days. $($appsWithRiskyPermissions.Count) apps request high-privilege permissions. This setting allows potential malicious app registration."
                Remediation = "1. Disable application registration for non-admin users immediately. " +
                             "2. Navigate to User settings > App registrations. " +
                             "3. Set 'Users can register applications' to 'No'. " +
                             "4. Create a controlled process for app registration requests. " +
                             "5. Assign Application Developer role only to trusted users. " +
                             "6. Audit all existing applications for legitimacy. " +
                             "7. Remove unnecessary or suspicious applications. " +
                             "8. Implement app governance policies and monitoring."
                AffectedAttributes = @("AllowedToCreateApps", "DefaultUserRolePermissions", "AppRegistration")
            }
        }
        
        # Finding 2: Users can consent to apps
        if ($usersCanConsentToApps -and $usersCanRegisterApps) {
            $findings += @{
                ObjectName = "User Consent Settings"
                ObjectType = "TenantSettings"
                RiskLevel = "Medium"
                Description = "Users can both register and consent to applications. $($spWithDelegatedPermissions.Count) apps have delegated permissions and $($spWithAppPermissions.Count) have application permissions. This combination enables data exfiltration and phishing attacks."
                Remediation = "1. Configure admin consent workflow for all app permissions. " +
                             "2. Navigate to Enterprise applications > Consent and permissions. " +
                             "3. Configure 'User consent settings' to restrict or disable consent. " +
                             "4. Set up admin consent requests workflow. " +
                             "5. Review and revoke inappropriate consent grants. " +
                             "6. Enable consent audit logs and monitoring. " +
                             "7. Train users on app consent risks."
                AffectedAttributes = @("UserConsent", "PermissionGrants", "ConsentPolicies")
            }
        }
        
        # Finding 3: Multi-tenant applications registered
        if ($multiTenantApps.Count -gt 5) {
            $multiTenantPercentage = [Math]::Round(($multiTenantApps.Count / $allApplications.Count) * 100, 2)
            
            $findings += @{
                ObjectName = "Multi-Tenant Applications"
                ObjectType = "Applications"
                RiskLevel = "Medium"
                Description = "$($multiTenantApps.Count) multi-tenant applications ($multiTenantPercentage% of all apps) are registered. These apps can be accessed from other tenants, potentially exposing data. Apps: $($multiTenantApps[0..4].DisplayName -join ', ')$(if($multiTenantApps.Count -gt 5){'...'})"
                Remediation = "1. Review all multi-tenant applications for business justification. " +
                             "2. Convert unnecessary multi-tenant apps to single-tenant. " +
                             "3. Implement publisher verification for all multi-tenant apps. " +
                             "4. Require admin consent for multi-tenant applications. " +
                             "5. Monitor sign-ins from external tenants. " +
                             "6. Configure Conditional Access for multi-tenant apps. " +
                             "7. Regularly audit multi-tenant app permissions."
                AffectedAttributes = @("SignInAudience", "MultiTenancy", "ExternalAccess")
            }
        }
        
        # Finding 4: Unverified applications
        if ($unverifiedApps.Count -gt 10) {
            $unverifiedPercentage = [Math]::Round(($unverifiedApps.Count / $allApplications.Count) * 100, 2)
            
            $findings += @{
                ObjectName = "Unverified Applications"
                ObjectType = "Applications"
                RiskLevel = "Low"
                Description = "$($unverifiedApps.Count) applications ($unverifiedPercentage% of all apps) lack publisher verification. Unverified apps may be less trustworthy or professionally managed."
                Remediation = "1. Require publisher verification for all production applications. " +
                             "2. Complete publisher verification for internal apps. " +
                             "3. Review and remove unnecessary unverified applications. " +
                             "4. Document business justification for unverified apps. " +
                             "5. Implement additional monitoring for unverified apps. " +
                             "6. Consider replacing unverified apps with verified alternatives."
                AffectedAttributes = @("PublisherVerification", "AppTrust")
            }
        }
        
        # Finding 5: Applications with credentials
        if ($appsWithSecrets.Count -gt 20) {
            $secretsPercentage = [Math]::Round(($appsWithSecrets.Count / $allApplications.Count) * 100, 2)
            
            # Check for expired credentials
            $appsWithExpiredCreds = @()
            $appsExpiringCreds = @()
            $currentDate = Get-Date
            $expirationWarning = $currentDate.AddDays(30)
            
            foreach ($app in $appsWithSecrets) {
                $hasExpired = $false
                $hasExpiring = $false
                
                foreach ($cred in $app.PasswordCredentials) {
                    if ($cred.EndDateTime -lt $currentDate) {
                        $hasExpired = $true
                    }
                    elseif ($cred.EndDateTime -lt $expirationWarning) {
                        $hasExpiring = $true
                    }
                }
                
                foreach ($cred in $app.KeyCredentials) {
                    if ($cred.EndDateTime -lt $currentDate) {
                        $hasExpired = $true
                    }
                    elseif ($cred.EndDateTime -lt $expirationWarning) {
                        $hasExpiring = $true
                    }
                }
                
                if ($hasExpired) { $appsWithExpiredCreds += $app }
                if ($hasExpiring) { $appsExpiringCreds += $app }
            }
            
            $findings += @{
                ObjectName = "Application Credentials"
                ObjectType = "Applications"
                RiskLevel = "Low"
                Description = "$($appsWithSecrets.Count) applications ($secretsPercentage%) have passwords or certificates. $($appsWithExpiredCreds.Count) have expired credentials and $($appsExpiringCreds.Count) have credentials expiring soon."
                Remediation = "1. Rotate application credentials regularly. " +
                             "2. Remove expired credentials immediately. " +
                             "3. Implement managed identities where possible. " +
                             "4. Use certificate-based authentication over passwords. " +
                             "5. Set up credential expiration monitoring. " +
                             "6. Document credential rotation procedures. " +
                             "7. Use Azure Key Vault for credential management."
                AffectedAttributes = @("PasswordCredentials", "KeyCredentials", "CredentialManagement")
            }
        }
        
        # Finding 6: High-privilege permission grants
        if ($appsWithRiskyPermissions.Count -gt 0) {
            $riskyAppNames = $appsWithRiskyPermissions[0..2] | ForEach-Object { $_.DisplayName }
            
            $findings += @{
                ObjectName = "High-Privilege Application Permissions"
                ObjectType = "Applications"
                RiskLevel = "Medium"
                Description = "$($appsWithRiskyPermissions.Count) applications request high-privilege permissions (User.ReadWrite.All, Group.ReadWrite.All, etc.). Apps include: $($riskyAppNames -join ', ')$(if($appsWithRiskyPermissions.Count -gt 3){'...'})"
                Remediation = "1. Review all high-privilege permission requests. " +
                             "2. Apply principle of least privilege to app permissions. " +
                             "3. Replace broad permissions with specific scopes. " +
                             "4. Require admin approval for high-privilege permissions. " +
                             "5. Implement Conditional Access for privileged apps. " +
                             "6. Monitor usage of high-privilege permissions. " +
                             "7. Consider using application permissions policies."
                AffectedAttributes = @("RequiredResourceAccess", "PrivilegedPermissions", "APIPermissions")
            }
        }
        
        # Finding 7: Rapid application growth
        if ($appRegistrationRate -gt 25 -and $allApplications.Count -gt 50) {
            $findings += @{
                ObjectName = "Application Registration Growth"
                ObjectType = "TenantMetrics"
                RiskLevel = "Low"
                Description = "$appRegistrationRate% of applications were registered in the last 90 days ($($recentApps.Count) new apps). This rapid growth may indicate uncontrolled app sprawl."
                Remediation = "1. Implement application governance framework. " +
                             "2. Require business justification for new apps. " +
                             "3. Establish app lifecycle management process. " +
                             "4. Regular review and cleanup of unused apps. " +
                             "5. Consolidate duplicate or similar applications. " +
                             "6. Set up quarterly app inventory reviews. " +
                             "7. Monitor application usage analytics."
                AffectedAttributes = @("AppGrowth", "AppGovernance", "RegistrationRate")
            }
        }
        
        # Finding 8: Users can create security groups
        if ($canCreateSecurityGroups -and $usersCanRegisterApps) {
            $findings += @{
                ObjectName = "Security Group Creation"
                ObjectType = "TenantSettings"
                RiskLevel = "Low"
                Description = "Users can create both applications and security groups. This combination allows users to grant their apps permissions through group membership."
                Remediation = "1. Restrict security group creation to administrators. " +
                             "2. Navigate to Groups > General settings. " +
                             "3. Set security group creation to admin-only. " +
                             "4. Implement group naming policies. " +
                             "5. Set up group expiration policies. " +
                             "6. Monitor group creation and membership changes."
                AffectedAttributes = @("AllowedToCreateSecurityGroups", "GroupManagement")
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
    $message = "Application registration settings analysis completed successfully."
    
    if ($findings.Count -gt 0) {
        $highCount = @($findings | Where-Object { $_.RiskLevel -eq "High" }).Count
        $mediumCount = @($findings | Where-Object { $_.RiskLevel -eq "Medium" }).Count
        $lowCount = @($findings | Where-Object { $_.RiskLevel -eq "Low" }).Count
        
        if ($highCount -gt 0) {
            $score = 25  # High findings
            $message = "Found $highCount high-risk and $mediumCount medium-risk issues with application registration settings. Immediate action required."
        }
        elseif ($mediumCount -gt 0) {
            $score = 50  # Medium findings
            $message = "Found $mediumCount medium-risk issues with application registration. Users have excessive permissions to register and manage applications."
        }
        else {
            $score = 75  # Only low-risk findings
            $message = "Found $lowCount low-risk application management improvements."
        }
    }
    else {
        $message = "Application registration is properly restricted to administrators. App governance appears well-controlled."
    }
    
    return @{
        CheckId = "EID-T3-004"
        Timestamp = (Get-Date).ToString("o")
        Status = $status
        Score = $score
        Severity = "Medium"
        Category = "Authorization"
        Findings = $findings
        Message = $message
        AffectedObjects = $findings.Count
        IgnoredObjects = 0
        Metadata = @{
            TenantId = $TenantId
            ExecutionTime = [Math]::Round($executionTime, 2)
            UsersCanRegisterApps = $usersCanRegisterApps
            UsersCanConsentToApps = $usersCanConsentToApps
            TotalApplications = $allApplications.Count
            RecentApplications = $recentApps.Count
            MultiTenantApps = $multiTenantApps.Count
            UnverifiedApps = $unverifiedApps.Count
            AppsWithSecrets = $appsWithSecrets.Count
            AppsWithRiskyPermissions = $appsWithRiskyPermissions.Count
            AppRegistrationRatePercent = $appRegistrationRate
        }
    }
}
catch {
    return @{
        CheckId = "EID-T3-004"
        Timestamp = (Get-Date).ToString("o")
        Status = "Error"
        Score = 0
        Severity = "Medium"
        Category = "Authorization"
        Findings = @()
        Message = "Error analyzing application registration settings: $_"
        AffectedObjects = 0
        IgnoredObjects = 0
        Metadata = @{
            TenantId = $TenantId
            ExecutionTime = 0.0
            ErrorDetails = $_.Exception.Message
        }
    }
}