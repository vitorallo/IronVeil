<#
.SYNOPSIS
Detects if legacy authentication protocols are allowed in Entra ID

.METADATA
{
  "id": "EID-T2-003",
  "name": "Legacy Authentication Protocols Allowed",
  "description": "Legacy authentication protocols (POP3, IMAP, SMTP, older Exchange ActiveSync) do not support MFA and are commonly exploited. This check verifies Entra ID tenant settings and Conditional Access policies to ensure legacy authentication protocols are blocked.",
  "category": "Authentication",
  "severity": "High",
  "weight": 8,
  "impact": 7,
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
    
    # Legacy authentication protocols to check
    $legacyProtocols = @(
        "Exchange ActiveSync",
        "IMAP4",
        "POP3",
        "SMTP",
        "Authenticated SMTP",
        "Other clients",
        "Outlook 2010 or earlier",
        "Exchange Online PowerShell",
        "Reporting Web Services",
        "MAPI over HTTP",
        "Offline Address Book",
        "Exchange Web Services",
        "PowerShell"
    )
    
    # Check if Microsoft.Graph module is available
    $graphModuleAvailable = $null -ne (Get-Module -ListAvailable -Name Microsoft.Graph)
    
    if ($graphModuleAvailable) {
        # Import required modules
        Import-Module Microsoft.Graph.Identity.SignIns -ErrorAction SilentlyContinue
        Import-Module Microsoft.Graph.Reports -ErrorAction SilentlyContinue
        Import-Module Microsoft.Graph.Identity.DirectoryManagement -ErrorAction SilentlyContinue
        
        # Check if already connected
        $context = Get-MgContext -ErrorAction SilentlyContinue
        
        if (-not $context) {
            # Need to connect - for automated scenarios, this would need pre-configured auth
            throw "Not connected to Microsoft Graph. Please run Connect-MgGraph first with appropriate permissions (Policy.Read.All, Reports.Read.All, AuditLog.Read.All)"
        }
        
        # Use provided TenantId or get from context
        if (-not $TenantId) {
            $TenantId = $context.TenantId
        }
        
        # Check Conditional Access policies for legacy authentication blocking
        $legacyAuthBlocked = $false
        $blockingPolicies = @()
        $allowingPolicies = @()
        $partialBlockPolicies = @()
        
        try {
            $caPolicies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction SilentlyContinue
            
            foreach ($policy in $caPolicies) {
                if ($policy.State -eq "enabled") {
                    $conditions = $policy.Conditions
                    $grantControls = $policy.GrantControls
                    
                    # Check if policy targets legacy authentication
                    $targetsLegacyAuth = $false
                    $blockAction = $false
                    
                    # Check client app types
                    if ($conditions.ClientAppTypes) {
                        $legacyTypes = @("exchangeActiveSync", "other")
                        $hasLegacyType = $false
                        
                        foreach ($appType in $conditions.ClientAppTypes) {
                            if ($legacyTypes -contains $appType) {
                                $hasLegacyType = $true
                                $targetsLegacyAuth = $true
                                break
                            }
                        }
                    }
                    
                    # Check if policy blocks access
                    if ($grantControls) {
                        if ($grantControls.BuiltInControls -contains "block") {
                            $blockAction = $true
                        }
                        elseif ($grantControls.BuiltInControls -contains "mfa") {
                            # MFA requirement effectively blocks legacy auth
                            $blockAction = $true
                        }
                    }
                    
                    # Categorize the policy
                    if ($targetsLegacyAuth -and $blockAction) {
                        # Check scope of users
                        $userScope = "Unknown"
                        if ($conditions.Users) {
                            if ($conditions.Users.IncludeUsers -contains "All") {
                                $userScope = "All users"
                                $legacyAuthBlocked = $true
                            }
                            elseif ($conditions.Users.IncludeGroups.Count -gt 0) {
                                $userScope = "Specific groups"
                            }
                            elseif ($conditions.Users.IncludeRoles.Count -gt 0) {
                                $userScope = "Specific roles"
                            }
                            
                            # Check for exclusions
                            if ($conditions.Users.ExcludeUsers.Count -gt 0 -or 
                                $conditions.Users.ExcludeGroups.Count -gt 0) {
                                $userScope += " (with exclusions)"
                                $partialBlockPolicies += $policy.DisplayName
                            }
                            else {
                                $blockingPolicies += $policy.DisplayName
                            }
                        }
                    }
                    elseif ($targetsLegacyAuth -and -not $blockAction) {
                        # Policy targets legacy auth but doesn't block
                        $allowingPolicies += $policy.DisplayName
                    }
                }
            }
        }
        catch {
            # Unable to enumerate Conditional Access policies
            $findings += @{
                ObjectName = "Conditional Access Enumeration"
                ObjectType = "Configuration"
                RiskLevel = "Medium"
                Description = "Unable to enumerate Conditional Access policies. Cannot verify if legacy authentication is blocked."
                Remediation = "1. Ensure the service account has Policy.Read.All permissions. " +
                            "2. Manually verify Conditional Access policies block legacy authentication. " +
                            "3. Check Azure AD sign-in logs for legacy authentication usage."
                AffectedAttributes = @("ConditionalAccessPolicies")
            }
        }
        
        # Check recent sign-ins for legacy authentication usage
        $legacyAuthUsage = @()
        $recentLegacySignIns = 0
        
        try {
            # Get sign-in logs from the last 7 days
            $sevenDaysAgo = (Get-Date).AddDays(-7).ToString("yyyy-MM-ddTHH:mm:ssZ")
            $filter = "createdDateTime ge $sevenDaysAgo and clientAppUsed ne 'Browser' and clientAppUsed ne 'Mobile Apps and Desktop clients'"
            
            $signIns = Get-MgAuditLogSignIn -Filter $filter -Top 1000 -ErrorAction SilentlyContinue
            
            # Group by client app and user
            $legacySignInsByApp = @{}
            
            foreach ($signIn in $signIns) {
                $clientApp = $signIn.ClientAppUsed
                
                # Check if it's a legacy protocol
                if ($legacyProtocols -contains $clientApp -or 
                    $clientApp -like "*ActiveSync*" -or 
                    $clientApp -like "*POP*" -or 
                    $clientApp -like "*IMAP*" -or
                    $clientApp -like "*SMTP*" -or
                    $clientApp -eq "Other clients") {
                    
                    $recentLegacySignIns++
                    
                    if (-not $legacySignInsByApp.ContainsKey($clientApp)) {
                        $legacySignInsByApp[$clientApp] = @{
                            Count = 0
                            Users = @{}
                            LastSignIn = $signIn.CreatedDateTime
                            SuccessCount = 0
                            FailureCount = 0
                        }
                    }
                    
                    $legacySignInsByApp[$clientApp].Count++
                    $legacySignInsByApp[$clientApp].Users[$signIn.UserPrincipalName] = $true
                    
                    if ($signIn.Status.ErrorCode -eq 0) {
                        $legacySignInsByApp[$clientApp].SuccessCount++
                    }
                    else {
                        $legacySignInsByApp[$clientApp].FailureCount++
                    }
                    
                    # Update last sign-in time
                    if ($signIn.CreatedDateTime -gt $legacySignInsByApp[$clientApp].LastSignIn) {
                        $legacySignInsByApp[$clientApp].LastSignIn = $signIn.CreatedDateTime
                    }
                }
            }
            
            # Create usage summary
            foreach ($app in $legacySignInsByApp.Keys) {
                $appData = $legacySignInsByApp[$app]
                $daysSinceLastUse = (Get-Date) - $appData.LastSignIn
                
                $legacyAuthUsage += @{
                    Protocol = $app
                    SignInCount = $appData.Count
                    UniqueUsers = $appData.Users.Count
                    SuccessRate = if ($appData.Count -gt 0) { 
                        [Math]::Round(($appData.SuccessCount / $appData.Count) * 100, 2) 
                    } else { 0 }
                    LastUsed = "$([int]$daysSinceLastUse.TotalHours) hours ago"
                }
            }
        }
        catch {
            # Unable to check sign-in logs
        }
        
        # Check Security Defaults status
        $securityDefaultsEnabled = $false
        try {
            $securityDefaults = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy -ErrorAction SilentlyContinue
            if ($securityDefaults -and $securityDefaults.IsEnabled) {
                $securityDefaultsEnabled = $true
                # Security Defaults blocks legacy authentication by default
                if (-not $legacyAuthBlocked) {
                    $legacyAuthBlocked = $true
                    $blockingPolicies += "Security Defaults (Enabled)"
                }
            }
        }
        catch {
            # Unable to check Security Defaults
        }
        
        # Create findings based on analysis
        if (-not $legacyAuthBlocked) {
            $riskLevel = if ($recentLegacySignIns -gt 0) { "Critical" } else { "High" }
            
            $remediation = if ($riskLevel -eq "Critical") {
                "1. IMMEDIATE ACTION REQUIRED: Legacy authentication is actively being used and not blocked. " +
                "2. Create a Conditional Access policy to block legacy authentication immediately. " +
                "3. Target all users and all cloud apps with client app filter for legacy protocols. " +
                "4. Set grant control to 'Block access'. " +
                "5. Monitor sign-in logs for failed legacy auth attempts. " +
                "6. Communicate changes to users and provide modern auth alternatives. " +
                "7. Consider enabling Security Defaults if no custom CA policies exist."
            }
            else {
                "1. Create a Conditional Access policy to block legacy authentication. " +
                "2. Include all users and applications in the policy scope. " +
                "3. Configure client app types to target legacy protocols. " +
                "4. Test with a pilot group before organization-wide deployment. " +
                "5. Enable Security Defaults as an alternative quick fix."
            }
            
            $findings += @{
                ObjectName = "Legacy Authentication Configuration"
                ObjectType = "Policy"
                RiskLevel = $riskLevel
                Description = "Legacy authentication protocols are not blocked. Found $recentLegacySignIns legacy auth sign-ins in the last 7 days. Security Defaults: $(if($securityDefaultsEnabled){'Enabled'}else{'Disabled'})"
                Remediation = $remediation
                AffectedAttributes = @("ConditionalAccessPolicies", "SecurityDefaults", "ClientAppTypes")
            }
        }
        
        # Add findings for partial blocking
        if ($partialBlockPolicies.Count -gt 0) {
            $findings += @{
                ObjectName = "Partial Legacy Auth Blocking"
                ObjectType = "Policy"
                RiskLevel = "Medium"
                Description = "Legacy authentication is only partially blocked with exclusions. Policies with exclusions: $($partialBlockPolicies -join ', '). This creates security gaps."
                Remediation = "1. Review exclusions in Conditional Access policies. " +
                            "2. Remove unnecessary exclusions from legacy auth blocking policies. " +
                            "3. Document and justify any required exclusions. " +
                            "4. Implement compensating controls for excluded users/groups. " +
                            "5. Regular review of exclusion necessity (monthly)."
                AffectedAttributes = @("PolicyExclusions", "ConditionalAccess")
            }
        }
        
        # Add findings for each actively used legacy protocol
        foreach ($usage in $legacyAuthUsage) {
            if ($usage.SignInCount -gt 10) {  # Only report protocols with significant usage
                $riskLevel = if ($usage.SuccessRate -gt 50) { "High" } else { "Medium" }
                
                $findings += @{
                    ObjectName = $usage.Protocol
                    ObjectType = "Protocol"
                    RiskLevel = $riskLevel
                    Description = "Legacy protocol actively used: $($usage.SignInCount) sign-ins by $($usage.UniqueUsers) users. Success rate: $($usage.SuccessRate)%. Last used: $($usage.LastUsed)"
                    Remediation = "1. Identify users using this legacy protocol. " +
                                "2. Migrate users to modern authentication methods. " +
                                "3. For Exchange protocols, ensure Outlook clients are updated. " +
                                "4. Disable basic authentication in Exchange Online. " +
                                "5. Block this specific protocol via Conditional Access."
                    AffectedAttributes = @("ClientAppUsed", "AuthenticationProtocol")
                }
            }
        }
        
        # Add finding if policies allow legacy auth
        if ($allowingPolicies.Count -gt 0) {
            $findings += @{
                ObjectName = "Conflicting Policies"
                ObjectType = "Policy"
                RiskLevel = "High"
                Description = "Conditional Access policies exist that allow legacy authentication: $($allowingPolicies -join ', '). These policies may override blocking attempts."
                Remediation = "1. Review and modify policies that allow legacy authentication. " +
                            "2. Ensure no grant controls permit access without MFA for legacy clients. " +
                            "3. Check policy priority and potential conflicts. " +
                            "4. Test policy effectiveness with What If tool. " +
                            "5. Consider consolidating authentication policies."
                AffectedAttributes = @("ConditionalAccessPolicies", "GrantControls")
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
    $message = "Legacy authentication analysis completed successfully."
    
    if ($findings.Count -gt 0) {
        $criticalCount = @($findings | Where-Object { $_.RiskLevel -eq "Critical" }).Count
        $highCount = @($findings | Where-Object { $_.RiskLevel -eq "High" }).Count
        $mediumCount = @($findings | Where-Object { $_.RiskLevel -eq "Medium" }).Count
        
        if ($criticalCount -gt 0) {
            $score = 10  # Critical - legacy auth actively used and not blocked
            $message = "CRITICAL: Legacy authentication is not blocked and actively being used! Found $recentLegacySignIns recent legacy auth sign-ins."
        }
        elseif ($highCount -gt 0) {
            $score = 25  # High-risk findings
            $message = "WARNING: Legacy authentication is not properly blocked. Found $highCount high-risk issues."
        }
        else {
            $score = 50  # Medium-risk findings
            $message = "Legacy authentication is partially blocked but $mediumCount medium-risk issues found."
        }
    }
    else {
        if ($legacyAuthBlocked) {
            $message = "Legacy authentication is properly blocked. No legacy auth usage detected in recent sign-ins."
        }
        else {
            $score = 75
            $message = "No recent legacy authentication usage detected, but blocking policies should be implemented as prevention."
        }
    }
    
    return @{
        CheckId = "EID-T2-003"
        Timestamp = (Get-Date).ToString("o")
        Status = $status
        Score = $score
        Severity = "High"
        Category = "Authentication"
        Findings = $findings
        Message = $message
        AffectedObjects = $findings.Count
        IgnoredObjects = 0
        Metadata = @{
            TenantId = $TenantId
            ExecutionTime = [Math]::Round($executionTime, 2)
            LegacyAuthBlocked = $legacyAuthBlocked
            SecurityDefaultsEnabled = $securityDefaultsEnabled
            BlockingPoliciesCount = $blockingPolicies.Count
            RecentLegacySignIns = $recentLegacySignIns
            LegacyProtocolsInUse = $legacyAuthUsage.Count
        }
    }
}
catch {
    return @{
        CheckId = "EID-T2-003"
        Timestamp = (Get-Date).ToString("o")
        Status = "Error"
        Score = 0
        Severity = "High"
        Category = "Authentication"
        Findings = @()
        Message = "Error analyzing legacy authentication configuration: $_"
        AffectedObjects = 0
        IgnoredObjects = 0
        Metadata = @{
            TenantId = $TenantId
            ExecutionTime = 0.0
            ErrorDetails = $_.Exception.Message
        }
    }
}