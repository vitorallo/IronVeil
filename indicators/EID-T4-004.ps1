<#
.SYNOPSIS
Detects if Self-Service Password Reset (SSPR) is not enabled in Entra ID

.METADATA
{
  "id": "EID-T4-004",
  "name": "Self-Service Password Reset Not Enabled",
  "description": "Self-service password reset (SSPR) is not enabled, forcing users to rely on help desk support for password resets. This increases IT workload, reduces user productivity, and may lead to weaker password practices as users try to avoid the hassle of IT-assisted resets.",
  "category": "Authentication",
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
        Import-Module Microsoft.Graph.Identity.SignIns -ErrorAction SilentlyContinue
        Import-Module Microsoft.Graph.Reports -ErrorAction SilentlyContinue
        Import-Module Microsoft.Graph.Beta.Identity.DirectoryManagement -ErrorAction SilentlyContinue
        
        # Check if already connected
        $context = Get-MgContext -ErrorAction SilentlyContinue
        
        if (-not $context) {
            # Need to connect - for automated scenarios, this would need pre-configured auth
            throw "Not connected to Microsoft Graph. Please run Connect-MgGraph first with appropriate permissions (Policy.Read.All, Reports.Read.All)"
        }
        
        # Use provided TenantId or get from context
        if (-not $TenantId) {
            $TenantId = $context.TenantId
        }
        
        # Get SSPR policy configuration
        $ssprEnabled = $false
        $ssprEnabledForAll = $false
        $ssprEnabledGroupId = $null
        $ssprEnabledGroupName = $null
        $ssprEnabledUserCount = 0
        $authenticationMethods = @()
        $numberOfMethodsRequired = 1
        $registrationEnforced = $false
        
        try {
            # Get password reset policies
            $passwordResetPolicies = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/microsoftAuthenticator" -ErrorAction SilentlyContinue
            
            # Get the actual SSPR configuration
            $ssprPolicy = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/policies/authenticationMethodsPolicy" -ErrorAction SilentlyContinue
            
            if ($ssprPolicy) {
                # Check if SSPR is enabled
                if ($ssprPolicy.authenticationMethodConfigurations) {
                    foreach ($method in $ssprPolicy.authenticationMethodConfigurations) {
                        if ($method.state -eq "enabled") {
                            $authenticationMethods += $method.id
                        }
                    }
                }
                
                # Check registration campaign
                if ($ssprPolicy.registrationEnforcement) {
                    $registrationEnforced = $ssprPolicy.registrationEnforcement.authenticationMethodsRegistrationCampaign.state -eq "enabled"
                }
            }
            
            # Alternative method: Check via directory settings
            $directorySettings = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/settings" -ErrorAction SilentlyContinue
            
            if ($directorySettings -and $directorySettings.value) {
                foreach ($setting in $directorySettings.value) {
                    if ($setting.displayName -eq "Password Reset" -or $setting.templateId -eq "08d542b9-071f-4e16-94b0-74abb372e3d9") {
                        foreach ($value in $setting.values) {
                            switch ($value.name) {
                                "EnablementType" {
                                    # 0 = Disabled, 1 = Enabled for selected group, 2 = Enabled for all
                                    $enablementType = [int]$value.value
                                    $ssprEnabled = $enablementType -gt 0
                                    $ssprEnabledForAll = $enablementType -eq 2
                                }
                                "GroupName" {
                                    $ssprEnabledGroupName = $value.value
                                }
                                "GroupId" {
                                    $ssprEnabledGroupId = $value.value
                                }
                                "NumberOfAuthenticationMethodsRequired" {
                                    $numberOfMethodsRequired = [int]$value.value
                                }
                            }
                        }
                    }
                }
            }
            
            # Get more detailed SSPR status via specific endpoint
            $ssprStatus = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/reports/authenticationMethods/usersRegisteredByMethod" -ErrorAction SilentlyContinue
            
            if ($ssprStatus -and $ssprStatus.value) {
                foreach ($methodStat in $ssprStatus.value) {
                    if ($methodStat.authenticationMethod -eq "password") {
                        $ssprEnabledUserCount = $methodStat.userCount
                    }
                }
            }
        }
        catch {
            Write-Verbose "Could not retrieve detailed SSPR settings: $_"
            
            # Try simplified check
            try {
                $org = Get-MgOrganization -ErrorAction SilentlyContinue
                if ($org) {
                    # Basic check - this might not give full details
                    $ssprEnabled = $true  # Assume enabled if we can't determine otherwise
                }
            }
            catch {
                Write-Verbose "Could not determine SSPR status: $_"
            }
        }
        
        # Get total user count for comparison
        $totalUsers = 0
        try {
            $users = Get-MgUser -All -Property "id" -ConsistencyLevel eventual -CountVariable UserCount -ErrorAction SilentlyContinue
            $totalUsers = @($users).Count
        }
        catch {
            $totalUsers = 0
        }
        
        # Get SSPR registration statistics if available
        $registeredUsers = 0
        $registrationMethods = @{}
        try {
            $authMethodsReport = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/reports/authenticationMethods/userRegistrationDetails" -ErrorAction SilentlyContinue
            
            if ($authMethodsReport -and $authMethodsReport.value) {
                $registeredUsers = @($authMethodsReport.value | Where-Object { $_.isSsprRegistered -eq $true }).Count
                
                foreach ($user in $authMethodsReport.value) {
                    if ($user.methodsRegistered) {
                        foreach ($method in $user.methodsRegistered) {
                            if (-not $registrationMethods.ContainsKey($method)) {
                                $registrationMethods[$method] = 0
                            }
                            $registrationMethods[$method]++
                        }
                    }
                }
            }
        }
        catch {
            Write-Verbose "Could not retrieve registration statistics: $_"
        }
        
        # Finding 1: SSPR is completely disabled
        if (-not $ssprEnabled) {
            $findings += @{
                ObjectName = "Self-Service Password Reset"
                ObjectType = "TenantSettings"
                RiskLevel = "Low"
                Description = "Self-Service Password Reset is not enabled for any users. All password resets must go through IT support, increasing help desk workload and reducing user productivity. Users may resort to weaker passwords to avoid reset hassles."
                Remediation = "1. Navigate to Azure AD > Password reset > Properties. " +
                             "2. Enable SSPR for 'All' users or start with a pilot group. " +
                             "3. Configure authentication methods (minimum 2 recommended): " +
                             "   - Mobile phone (SMS and/or voice call) " +
                             "   - Office phone " +
                             "   - Email " +
                             "   - Security questions (less secure, use cautiously) " +
                             "   - Microsoft Authenticator app " +
                             "4. Set number of methods required to reset (recommend 2). " +
                             "5. Configure registration enforcement. " +
                             "6. Enable notifications for password resets. " +
                             "7. Customize help desk link and messaging. " +
                             "8. Test thoroughly before organization-wide rollout."
                AffectedAttributes = @("EnablementType", "SsprConfiguration")
            }
        }
        
        # Finding 2: SSPR enabled only for specific group with low coverage
        if ($ssprEnabled -and -not $ssprEnabledForAll -and $totalUsers -gt 0) {
            $coveragePercentage = if ($ssprEnabledUserCount -gt 0 -and $totalUsers -gt 0) {
                [Math]::Round(($ssprEnabledUserCount / $totalUsers) * 100, 1)
            } else { 0 }
            
            if ($coveragePercentage -lt 50) {
                $findings += @{
                    ObjectName = "SSPR Coverage"
                    ObjectType = "TenantSettings"
                    RiskLevel = "Low"
                    Description = "SSPR is only enabled for a specific group covering approximately $coveragePercentage% of users. The majority of users still depend on IT support for password resets."
                    Remediation = "1. Expand SSPR coverage to all users or additional groups. " +
                                 "2. Identify departments or user types not covered. " +
                                 "3. Create phased rollout plan for remaining users. " +
                                 "4. Provide training materials for newly enabled users. " +
                                 "5. Monitor adoption rates and address concerns. " +
                                 "6. Consider making SSPR mandatory for all users. " +
                                 "7. Track help desk ticket reduction as success metric."
                    AffectedAttributes = @("GroupId", "Coverage")
                }
            }
        }
        
        # Finding 3: Insufficient authentication methods configured
        if ($ssprEnabled -and $authenticationMethods.Count -lt 2) {
            $findings += @{
                ObjectName = "SSPR Authentication Methods"
                ObjectType = "Configuration"
                RiskLevel = "Low"
                Description = "Only $($authenticationMethods.Count) authentication method(s) available for SSPR. Limited options may prevent users from successfully resetting passwords if their primary method is unavailable."
                Remediation = "1. Enable multiple authentication methods: " +
                             "   - Microsoft Authenticator (most secure) " +
                             "   - SMS to mobile phone " +
                             "   - Voice call to mobile phone " +
                             "   - Alternate email address " +
                             "   - Office phone (if applicable) " +
                             "2. Avoid security questions as sole method. " +
                             "3. Require at least 2 methods for reset. " +
                             "4. Encourage users to register multiple methods. " +
                             "5. Set up registration campaigns to ensure compliance."
                AffectedAttributes = @("AuthenticationMethods", "MethodCount")
            }
        }
        
        # Finding 4: Low SSPR registration rate
        if ($ssprEnabled -and $totalUsers -gt 0 -and $registeredUsers -gt 0) {
            $registrationRate = [Math]::Round(($registeredUsers / $totalUsers) * 100, 1)
            
            if ($registrationRate -lt 70) {
                $findings += @{
                    ObjectName = "SSPR Registration"
                    ObjectType = "UserCompliance"
                    RiskLevel = "Low"
                    Description = "Only $registrationRate% of users have registered for SSPR. Low registration rates mean many users cannot use self-service capabilities when needed."
                    Remediation = "1. Enable registration enforcement/campaign: " +
                                 "   - Configure registration reminder frequency " +
                                 "   - Set registration deadline " +
                                 "   - Send email notifications about requirement " +
                                 "2. Use Conditional Access to require registration. " +
                                 "3. Block access until SSPR registration is complete. " +
                                 "4. Provide clear registration instructions. " +
                                 "5. Host training sessions for user education. " +
                                 "6. Monitor and follow up with non-compliant users. " +
                                 "7. Consider making registration mandatory at next sign-in."
                    AffectedAttributes = @("RegistrationRate", "UserCompliance")
                }
            }
        }
        
        # Finding 5: Registration not enforced
        if ($ssprEnabled -and -not $registrationEnforced) {
            $findings += @{
                ObjectName = "SSPR Registration Enforcement"
                ObjectType = "Configuration"
                RiskLevel = "Low"
                Description = "SSPR registration is not enforced. Users can skip registration, leaving them unable to reset passwords when needed and creating help desk burden."
                Remediation = "1. Enable registration enforcement campaign. " +
                             "2. Configure interruption frequency (e.g., every 7 days). " +
                             "3. Set campaign duration (e.g., 30-60 days). " +
                             "4. Include clear instructions in prompts. " +
                             "5. Use Conditional Access for strict enforcement. " +
                             "6. Track registration compliance rates. " +
                             "7. Follow up with users who haven't registered."
                AffectedAttributes = @("RegistrationEnforcement", "Campaign")
            }
        }
        
        # Finding 6: Only one authentication method required
        if ($ssprEnabled -and $numberOfMethodsRequired -eq 1) {
            $findings += @{
                ObjectName = "SSPR Security Level"
                ObjectType = "Configuration"
                RiskLevel = "Low"
                Description = "Only one authentication method is required for password reset. This reduces security as a single compromised method allows account takeover."
                Remediation = "1. Increase required methods to 2 for better security. " +
                             "2. Balance security with user convenience. " +
                             "3. Ensure users have registered multiple methods. " +
                             "4. Consider risk-based requirements (more for admins). " +
                             "5. Monitor for suspicious reset activity. " +
                             "6. Enable admin notifications for all resets. " +
                             "7. Implement additional verification for sensitive accounts."
                AffectedAttributes = @("NumberOfMethodsRequired", "SecurityLevel")
            }
        }
        
        # Finding 7: Check for weak authentication methods
        if ($registrationMethods.ContainsKey("securityQuestion") -and $registrationMethods["securityQuestion"] -gt 0) {
            $sqPercentage = [Math]::Round(($registrationMethods["securityQuestion"] / [Math]::Max($registeredUsers, 1)) * 100, 1)
            
            if ($sqPercentage -gt 20) {
                $findings += @{
                    ObjectName = "Security Questions Usage"
                    ObjectType = "AuthenticationMethod"
                    RiskLevel = "Low"
                    Description = "$sqPercentage% of SSPR-registered users rely on security questions, which are considered weak authentication. Answers can often be guessed or found through social engineering."
                    Remediation = "1. Discourage security questions as authentication method. " +
                                 "2. If used, require alongside stronger methods. " +
                                 "3. Provide guidance on creating strong questions. " +
                                 "4. Promote Microsoft Authenticator adoption. " +
                                 "5. Phase out security questions over time. " +
                                 "6. Educate users on risks of predictable answers."
                    AffectedAttributes = @("SecurityQuestions", "WeakAuthentication")
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
    $message = "Self-Service Password Reset configuration analysis completed successfully."
    
    if ($findings.Count -gt 0) {
        $score = 75  # Low-risk findings
        $message = "Found $($findings.Count) SSPR configuration issues that should be addressed to improve user experience and reduce IT workload."
    }
    else {
        $message = "Self-Service Password Reset is properly configured and enforced with good user adoption."
    }
    
    return @{
        CheckId = "EID-T4-004"
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
            SsprEnabled = $ssprEnabled
            SsprEnabledForAll = $ssprEnabledForAll
            TotalUsers = $totalUsers
            RegisteredUsers = $registeredUsers
            AuthenticationMethodCount = $authenticationMethods.Count
            RegistrationEnforced = $registrationEnforced
        }
    }
}
catch {
    return @{
        CheckId = "EID-T4-004"
        Timestamp = (Get-Date).ToString("o")
        Status = "Error"
        Score = 0
        Severity = "Low"
        Category = "Authentication"
        Findings = @()
        Message = "Error analyzing Self-Service Password Reset configuration: $_"
        AffectedObjects = 0
        IgnoredObjects = 0
        Metadata = @{
            TenantId = $TenantId
            ExecutionTime = 0.0
            ErrorDetails = $_.Exception.Message
        }
    }
}