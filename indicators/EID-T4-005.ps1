<#
.SYNOPSIS
Detects if LinkedIn account connections are enabled for users in Entra ID

.METADATA
{
  "id": "EID-T4-005",
  "name": "LinkedIn Account Connections Enabled",
  "description": "Users are allowed to connect their LinkedIn accounts to their work profiles. While this can enhance professional networking, it may expose organizational structure, employee information, and create data privacy concerns, especially in regulated industries.",
  "category": "Privacy",
  "severity": "Low",
  "weight": 3,
  "impact": 3,
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
        Import-Module Microsoft.Graph.Users -ErrorAction SilentlyContinue
        
        # Check if already connected
        $context = Get-MgContext -ErrorAction SilentlyContinue
        
        if (-not $context) {
            # Need to connect - for automated scenarios, this would need pre-configured auth
            throw "Not connected to Microsoft Graph. Please run Connect-MgGraph first with appropriate permissions (Directory.Read.All, User.Read.All)"
        }
        
        # Use provided TenantId or get from context
        if (-not $TenantId) {
            $TenantId = $context.TenantId
        }
        
        # Initialize LinkedIn settings variables
        $linkedInEnabled = $false
        $linkedInAccountConnectionsEnabled = $false
        $showLinkedInFeatures = $false
        $allowLinkedInProfileData = $false
        $settingsFound = $false
        
        # Get organization settings including LinkedIn integration
        try {
            # Try to get LinkedIn settings from directory settings
            $directorySettings = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/settings" -ErrorAction SilentlyContinue
            
            if ($directorySettings -and $directorySettings.value) {
                foreach ($setting in $directorySettings.value) {
                    # Look for LinkedIn integration settings
                    if ($setting.displayName -eq "LinkedIn Integration" -or 
                        $setting.displayName -eq "Consent Policy Settings" -or
                        $setting.templateId -eq "4bc7f740-180d-4655-97b9-8fa07e6f2f6c") {
                        
                        $settingsFound = $true
                        foreach ($value in $setting.values) {
                            switch ($value.name) {
                                "EnableLinkedInAppFamily" {
                                    $linkedInEnabled = [System.Convert]::ToBoolean($value.value)
                                }
                                "AllowLinkedInAccountConnections" {
                                    $linkedInAccountConnectionsEnabled = [System.Convert]::ToBoolean($value.value)
                                }
                                "ShowLinkedInFeatures" {
                                    $showLinkedInFeatures = [System.Convert]::ToBoolean($value.value)
                                }
                                "AllowLinkedInProfileData" {
                                    $allowLinkedInProfileData = [System.Convert]::ToBoolean($value.value)
                                }
                            }
                        }
                    }
                }
            }
            
            # Alternative: Check organization properties
            $organization = Get-MgOrganization -ErrorAction SilentlyContinue
            if ($organization) {
                # Check privacy profile settings
                if ($organization.PrivacyProfile) {
                    $privacyContactEmail = $organization.PrivacyProfile.ContactEmail
                    $privacyStatementUrl = $organization.PrivacyProfile.StatementUrl
                }
            }
            
            # Try to get user consent settings
            $userConsentSettings = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/policies/authorizationPolicy" -ErrorAction SilentlyContinue
            
            if ($userConsentSettings) {
                # Check if users can consent to apps
                $userCanConsent = $userConsentSettings.defaultUserRolePermissions.allowedToCreateApps
                $permissionGrantPolicy = $userConsentSettings.permissionGrantPolicyIdsAssignedToDefaultUserRole
            }
        }
        catch {
            Write-Verbose "Could not retrieve LinkedIn integration settings: $_"
        }
        
        # Check for LinkedIn-related enterprise applications
        $linkedInApps = @()
        try {
            # Look for LinkedIn applications in the tenant
            $servicePrincipals = Get-MgServicePrincipal -Filter "startswith(displayName, 'LinkedIn')" -ErrorAction SilentlyContinue
            
            if ($servicePrincipals) {
                foreach ($sp in $servicePrincipals) {
                    $linkedInApps += @{
                        Name = $sp.DisplayName
                        AppId = $sp.AppId
                        Enabled = $sp.AccountEnabled
                        CreatedDateTime = $sp.AdditionalProperties.createdDateTime
                    }
                }
            }
        }
        catch {
            Write-Verbose "Could not check for LinkedIn applications: $_"
        }
        
        # Check how many users might have LinkedIn connections
        $usersWithLinkedIn = 0
        try {
            # This would require checking user profiles for LinkedIn-related attributes
            # In practice, this might be visible in extended attributes or profile data
            $sampleUsers = Get-MgUser -Top 100 -Property "id,displayName,mail,otherMails" -ErrorAction SilentlyContinue
            
            # Check for LinkedIn-related email domains in otherMails
            foreach ($user in $sampleUsers) {
                if ($user.OtherMails) {
                    foreach ($email in $user.OtherMails) {
                        if ($email -match "@linkedin\.com") {
                            $usersWithLinkedIn++
                            break
                        }
                    }
                }
            }
        }
        catch {
            Write-Verbose "Could not check user LinkedIn connections: $_"
        }
        
        # Finding 1: LinkedIn account connections are enabled
        if ($linkedInAccountConnectionsEnabled -or ($linkedInEnabled -and -not $settingsFound)) {
            $findings += @{
                ObjectName = "LinkedIn Account Connections"
                ObjectType = "TenantSettings"
                RiskLevel = "Low"
                Description = "LinkedIn account connections are enabled, allowing users to connect their work and LinkedIn profiles. This may expose organizational structure, employee roles, and create data privacy concerns, especially for sensitive positions or regulated industries."
                Remediation = "1. Review organizational data privacy requirements. " +
                             "2. Consider disabling LinkedIn integration if: " +
                             "   - Operating in regulated industries (finance, healthcare) " +
                             "   - Handling sensitive government contracts " +
                             "   - Concerned about organizational structure exposure " +
                             "3. To disable: Azure AD > User settings > LinkedIn account connections. " +
                             "4. Set 'Users can connect LinkedIn accounts' to No. " +
                             "5. Communicate change to users before disabling. " +
                             "6. Consider alternative professional networking solutions. " +
                             "7. Review and update data privacy policies."
                AffectedAttributes = @("AllowLinkedInAccountConnections", "EnableLinkedInAppFamily")
            }
        }
        
        # Finding 2: LinkedIn features shown in Microsoft apps
        if ($showLinkedInFeatures) {
            $findings += @{
                ObjectName = "LinkedIn Features in Microsoft Apps"
                ObjectType = "TenantSettings"
                RiskLevel = "Low"
                Description = "LinkedIn features are displayed within Microsoft applications. This integration shares data between Microsoft and LinkedIn services, which may conflict with data residency or privacy requirements."
                Remediation = "1. Review data sharing implications with legal/compliance team. " +
                             "2. Assess if LinkedIn data sharing aligns with privacy policies. " +
                             "3. Consider impact on GDPR or other privacy regulations. " +
                             "4. Disable if data residency requirements prohibit sharing. " +
                             "5. Update user consent and privacy notices if keeping enabled. " +
                             "6. Monitor Microsoft-LinkedIn data sharing announcements."
                AffectedAttributes = @("ShowLinkedInFeatures", "DataSharing")
            }
        }
        
        # Finding 3: LinkedIn profile data access allowed
        if ($allowLinkedInProfileData) {
            $findings += @{
                ObjectName = "LinkedIn Profile Data Access"
                ObjectType = "TenantSettings"
                RiskLevel = "Low"
                Description = "Microsoft applications can access LinkedIn profile data for connected accounts. This bi-directional data flow may expose professional information beyond organizational control."
                Remediation = "1. Evaluate what LinkedIn data is accessible to Microsoft apps. " +
                             "2. Review employee privacy expectations and rights. " +
                             "3. Consider industry-specific privacy requirements. " +
                             "4. Implement data handling procedures for LinkedIn information. " +
                             "5. Train HR and managers on appropriate use of LinkedIn data. " +
                             "6. Establish policies for LinkedIn data in recruitment/evaluation."
                AffectedAttributes = @("AllowLinkedInProfileData", "ProfileAccess")
            }
        }
        
        # Finding 4: LinkedIn applications detected in tenant
        if ($linkedInApps.Count -gt 0) {
            $appNames = ($linkedInApps | ForEach-Object { $_.Name }) -join ", "
            $findings += @{
                ObjectName = "LinkedIn Enterprise Applications"
                ObjectType = "Applications"
                RiskLevel = "Low"
                Description = "Found $($linkedInApps.Count) LinkedIn-related application(s) registered in the tenant: $appNames. These applications may have permissions to access organizational data."
                Remediation = "1. Review permissions granted to LinkedIn applications. " +
                             "2. Audit what organizational data these apps can access. " +
                             "3. Check user consent records for these applications. " +
                             "4. Consider removing unnecessary LinkedIn applications. " +
                             "5. Implement application governance policies. " +
                             "6. Regular review of third-party application permissions."
                AffectedAttributes = @("ServicePrincipals", "AppPermissions")
            }
        }
        
        # Finding 5: No privacy profile configured but LinkedIn enabled
        if (($linkedInEnabled -or $linkedInAccountConnectionsEnabled) -and 
            ([string]::IsNullOrWhiteSpace($privacyContactEmail) -or [string]::IsNullOrWhiteSpace($privacyStatementUrl))) {
            $findings += @{
                ObjectName = "Privacy Profile Configuration"
                ObjectType = "OrganizationSettings"
                RiskLevel = "Low"
                Description = "LinkedIn integration is enabled but organization privacy profile is incomplete. Users cannot make informed decisions about data sharing without clear privacy information."
                Remediation = "1. Configure organization privacy profile: " +
                             "   - Set privacy contact email address " +
                             "   - Provide privacy statement URL " +
                             "2. Update privacy statement to cover LinkedIn data sharing. " +
                             "3. Include LinkedIn integration in data processing notices. " +
                             "4. Ensure compliance with privacy regulations. " +
                             "5. Make privacy information easily accessible to users."
                AffectedAttributes = @("PrivacyProfile", "PrivacyStatement")
            }
        }
        
        # Finding 6: Settings not explicitly configured
        if (-not $settingsFound) {
            $findings += @{
                ObjectName = "LinkedIn Integration Settings"
                ObjectType = "Configuration"
                RiskLevel = "Low"
                Description = "LinkedIn integration settings are not explicitly configured. Default settings may apply, potentially allowing data sharing without organizational review."
                Remediation = "1. Explicitly configure LinkedIn integration settings. " +
                             "2. Make conscious decision about each setting: " +
                             "   - Account connections " +
                             "   - Feature display " +
                             "   - Profile data access " +
                             "3. Document rationale for configuration choices. " +
                             "4. Align settings with organizational privacy stance. " +
                             "5. Communicate settings to users and stakeholders."
                AffectedAttributes = @("LinkedInSettings", "DefaultConfiguration")
            }
        }
        
        # Finding 7: Industry-specific concerns
        $organization = Get-MgOrganization -ErrorAction SilentlyContinue
        if ($organization -and $linkedInAccountConnectionsEnabled) {
            # Check for common regulated industry keywords in organization name
            $orgName = $organization.DisplayName.ToLower()
            $regulatedKeywords = @("bank", "financial", "healthcare", "health", "medical", "insurance", "government", "defense", "federal")
            
            $isRegulated = $false
            foreach ($keyword in $regulatedKeywords) {
                if ($orgName -match $keyword) {
                    $isRegulated = $true
                    break
                }
            }
            
            if ($isRegulated) {
                $findings += @{
                    ObjectName = "Regulated Industry Concern"
                    ObjectType = "Compliance"
                    RiskLevel = "Low"
                    Description = "Organization appears to be in a regulated industry based on name '$($organization.DisplayName)'. LinkedIn integration may conflict with industry-specific privacy or security requirements."
                    Remediation = "1. Consult with compliance team about LinkedIn integration. " +
                                 "2. Review industry-specific regulations: " +
                                 "   - Financial: SOC2, PCI-DSS requirements " +
                                 "   - Healthcare: HIPAA privacy rules " +
                                 "   - Government: Security clearance implications " +
                                 "3. Perform risk assessment for LinkedIn data sharing. " +
                                 "4. Consider disabling for high-security roles. " +
                                 "5. Implement role-based LinkedIn access policies."
                    AffectedAttributes = @("IndustryCompliance", "RegulatoryRequirements")
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
    $message = "LinkedIn account connections analysis completed successfully."
    
    if ($findings.Count -gt 0) {
        $score = 75  # Low-risk findings
        $message = "Found $($findings.Count) LinkedIn integration concerns that should be reviewed for privacy and security implications."
    }
    else {
        $message = "LinkedIn account connections are properly managed or disabled according to organizational needs."
    }
    
    return @{
        CheckId = "EID-T4-005"
        Timestamp = (Get-Date).ToString("o")
        Status = $status
        Score = $score
        Severity = "Low"
        Category = "Privacy"
        Findings = $findings
        Message = $message
        AffectedObjects = $findings.Count
        IgnoredObjects = 0
        Metadata = @{
            TenantId = $TenantId
            ExecutionTime = [Math]::Round($executionTime, 2)
            LinkedInEnabled = $linkedInEnabled
            LinkedInAccountConnectionsEnabled = $linkedInAccountConnectionsEnabled
            ShowLinkedInFeatures = $showLinkedInFeatures
            LinkedInAppsFound = $linkedInApps.Count
            SettingsExplicitlyConfigured = $settingsFound
        }
    }
}
catch {
    return @{
        CheckId = "EID-T4-005"
        Timestamp = (Get-Date).ToString("o")
        Status = "Error"
        Score = 0
        Severity = "Low"
        Category = "Privacy"
        Findings = @()
        Message = "Error analyzing LinkedIn account connections settings: $_"
        AffectedObjects = 0
        IgnoredObjects = 0
        Metadata = @{
            TenantId = $TenantId
            ExecutionTime = 0.0
            ErrorDetails = $_.Exception.Message
        }
    }
}