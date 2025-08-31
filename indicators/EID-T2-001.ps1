<#
.SYNOPSIS
Detects lack of Multi-Factor Authentication (MFA) for privileged accounts in Entra ID

.METADATA
{
  "id": "EID-T2-001",
  "name": "Lack of Multi-Factor Authentication for Privileged Accounts",
  "description": "Privileged accounts (Global Admins, User Administrators) without MFA are highly susceptible to credential theft. This check identifies privileged Entra ID roles assigned to users and verifies if MFA is enforced through Conditional Access policies or per-user settings.",
  "category": "Authentication",
  "severity": "High",
  "weight": 8,
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
    
    # Critical privileged roles that must have MFA
    $criticalRoles = @(
        "62e90394-69f5-4237-9190-012177145e10",  # Global Administrator
        "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",  # Application Administrator
        "194ae4cb-b126-40b2-bd5b-6091b380977d",  # Security Administrator
        "f28a1f50-f6e7-4571-818b-6a12f2af6b6c",  # SharePoint Administrator
        "29232cdf-9323-42fd-ade2-1d097af3e4de",  # Exchange Administrator
        "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9",  # Conditional Access Administrator
        "7be44c8a-adaf-4e2a-84d6-ab2649e08a13",  # Privileged Authentication Administrator
        "e8611ab8-c189-46e8-94e1-60213ab1f814",  # Privileged Role Administrator
        "fe930be7-5e62-47db-91af-98c3a49a38b1",  # User Administrator
        "158c047a-c907-4556-b7ef-446551a6b5f7",  # Cloud Application Administrator
        "966707d0-3269-4727-9be2-8c3a10f19b9d",  # Password Administrator
        "7698a772-787b-4ac8-901f-60d6b08affd2",  # Cloud Device Administrator
        "17315797-102d-40b4-93e0-432062caca18",  # Compliance Administrator
        "b0f54661-2d74-4c50-afa3-1ec803f12efe",  # Billing Administrator
        "729827e3-9c14-49f7-bb1b-9608f156bbb8"   # Helpdesk Administrator
    )
    
    # Additional high-privilege roles
    $highPrivilegeRoles = @(
        "69091246-20e8-4a56-aa4d-066075b2a7a8",  # Teams Administrator
        "baf37b3a-610e-45da-9e62-d9d1e5e8914b",  # Priority Account Administrator
        "e00e864a-17c5-4a4b-9c06-f5b95a8d5bd8",  # Partner Tier2 Support
        "4d6ac14f-3453-41d0-bef9-a3e0c569773a",  # License Administrator
        "38a96431-2bdf-4b4c-8b6e-5d3d8abac1a4",  # Desktop Analytics Administrator
        "892c5842-a9a6-463a-8041-72aa08ca3cf6",  # Azure AD Joined Device Local Administrator
        "3a2c62db-5318-420d-8d74-23affee5d9d5"   # Intune Administrator
    )
    
    # Check if Microsoft.Graph module is available
    $graphModuleAvailable = $null -ne (Get-Module -ListAvailable -Name Microsoft.Graph)
    
    if ($graphModuleAvailable) {
        # Import required modules
        Import-Module Microsoft.Graph.Identity.DirectoryManagement -ErrorAction SilentlyContinue
        Import-Module Microsoft.Graph.Users -ErrorAction SilentlyContinue
        Import-Module Microsoft.Graph.Identity.SignIns -ErrorAction SilentlyContinue
        
        # Check if already connected
        $context = Get-MgContext -ErrorAction SilentlyContinue
        
        if (-not $context) {
            # Need to connect - for automated scenarios, this would need pre-configured auth
            throw "Not connected to Microsoft Graph. Please run Connect-MgGraph first with appropriate permissions (Directory.Read.All, UserAuthenticationMethod.Read.All, Policy.Read.All)"
        }
        
        # Use provided TenantId or get from context
        if (-not $TenantId) {
            $TenantId = $context.TenantId
        }
        
        # Get all directory role assignments
        $allRoles = $criticalRoles + $highPrivilegeRoles
        $privilegedUsers = @{}
        
        foreach ($roleId in $allRoles) {
            try {
                # Get role details
                $role = Get-MgDirectoryRole -Filter "roleTemplateId eq '$roleId'" -ErrorAction SilentlyContinue
                if ($role) {
                    $roleName = $role.DisplayName
                    
                    # Get members of this role
                    $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All
                    
                    foreach ($member in $members) {
                        if ($member.AdditionalProperties["@odata.type"] -eq "#microsoft.graph.user") {
                            $userId = $member.Id
                            
                            if (-not $privilegedUsers.ContainsKey($userId)) {
                                # Get user details
                                $user = Get-MgUser -UserId $userId -Property Id,DisplayName,UserPrincipalName,AccountEnabled,UserType,CreatedDateTime
                                
                                $privilegedUsers[$userId] = @{
                                    User = $user
                                    Roles = @()
                                    IsCritical = $false
                                    IsHighPrivilege = $false
                                }
                            }
                            
                            $privilegedUsers[$userId].Roles += $roleName
                            
                            if ($criticalRoles -contains $roleId) {
                                $privilegedUsers[$userId].IsCritical = $true
                            }
                            if ($highPrivilegeRoles -contains $roleId) {
                                $privilegedUsers[$userId].IsHighPrivilege = $true
                            }
                        }
                    }
                }
            }
            catch {
                # Continue with next role if this one fails
                continue
            }
        }
        
        # Check MFA status for each privileged user
        foreach ($userId in $privilegedUsers.Keys) {
            $userInfo = $privilegedUsers[$userId]
            $user = $userInfo.User
            $hasMFA = $false
            $mfaDetails = @()
            
            try {
                # Get authentication methods for the user
                $authMethods = Get-MgUserAuthenticationMethod -UserId $userId -ErrorAction SilentlyContinue
                
                # Check for strong authentication methods
                $strongAuthMethods = @()
                foreach ($method in $authMethods) {
                    $methodType = $method.AdditionalProperties["@odata.type"]
                    
                    switch ($methodType) {
                        "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod" {
                            $strongAuthMethods += "Microsoft Authenticator"
                            $hasMFA = $true
                        }
                        "#microsoft.graph.phoneAuthenticationMethod" {
                            $strongAuthMethods += "Phone (SMS/Call)"
                            $hasMFA = $true
                        }
                        "#microsoft.graph.fido2AuthenticationMethod" {
                            $strongAuthMethods += "FIDO2 Security Key"
                            $hasMFA = $true
                        }
                        "#microsoft.graph.windowsHelloForBusinessAuthenticationMethod" {
                            $strongAuthMethods += "Windows Hello for Business"
                            $hasMFA = $true
                        }
                        "#microsoft.graph.emailAuthenticationMethod" {
                            # Email is not considered strong MFA
                            $mfaDetails += "Email (weak method)"
                        }
                    }
                }
                
                if ($strongAuthMethods.Count -gt 0) {
                    $mfaDetails = $strongAuthMethods
                }
                
                # Check user's MFA registration state
                $userRegistrationDetails = Get-MgReportAuthenticationMethodUserRegistrationDetail -Filter "userPrincipalName eq '$($user.UserPrincipalName)'" -ErrorAction SilentlyContinue
                if ($userRegistrationDetails) {
                    if ($userRegistrationDetails.IsMfaRegistered) {
                        $hasMFA = $true
                        if ($mfaDetails.Count -eq 0) {
                            $mfaDetails += "MFA Registered (method unknown)"
                        }
                    }
                }
            }
            catch {
                # Unable to get authentication methods, mark as unknown
                $mfaDetails += "Unable to determine MFA status"
            }
            
            # If no MFA or only weak methods, add to findings
            if (-not $hasMFA -or $mfaDetails.Count -eq 0) {
                $daysSinceCreation = (Get-Date) - $user.CreatedDateTime
                $riskLevel = if ($userInfo.IsCritical) { "Critical" } else { "High" }
                
                # Build remediation based on risk level
                $remediation = if ($userInfo.IsCritical) {
                    "1. IMMEDIATE ACTION REQUIRED: This account has critical administrative privileges without MFA protection. " +
                    "2. Enable MFA immediately using Microsoft Authenticator or FIDO2 security key. " +
                    "3. Configure Conditional Access policy to require MFA for all admin roles. " +
                    "4. Set up Azure AD Identity Protection risk-based policies. " +
                    "5. Enable Privileged Identity Management (PIM) for just-in-time access. " +
                    "6. Review all recent sign-in activity for this account. " +
                    "7. Consider implementing passwordless authentication methods."
                }
                else {
                    "1. Enable MFA for this privileged account immediately. " +
                    "2. Use Microsoft Authenticator app or hardware security key. " +
                    "3. Configure Conditional Access to enforce MFA for administrative actions. " +
                    "4. Enable Azure AD Identity Protection policies. " +
                    "5. Consider implementing Privileged Identity Management (PIM)."
                }
                
                $accountType = if ($user.UserType -eq "Guest") { "Guest" } else { "Member" }
                $accountStatus = if ($user.AccountEnabled) { "Enabled" } else { "Disabled" }
                
                $findings += @{
                    ObjectName = $user.UserPrincipalName
                    ObjectType = "User"
                    RiskLevel = $riskLevel
                    Description = "$accountType account with $($userInfo.Roles.Count) privileged role(s) has no MFA or only weak authentication methods. Roles: $($userInfo.Roles -join ', '). Account is $accountStatus. Created $([int]$daysSinceCreation.Days) days ago."
                    Remediation = $remediation
                    AffectedAttributes = @("authenticationMethods", "strongAuthenticationRequirements", "roles")
                }
            }
        }
        
        # Also check for Conditional Access policies that might enforce MFA
        $mfaPoliciesExist = $false
        try {
            $caPolicies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction SilentlyContinue
            $adminMfaPolicies = @($caPolicies | Where-Object {
                $_.State -eq "enabled" -and
                $_.GrantControls.BuiltInControls -contains "mfa" -and
                ($_.Conditions.Users.IncludeRoles.Count -gt 0 -or $_.Conditions.Users.IncludeUsers -contains "All")
            })
            
            if ($adminMfaPolicies.Count -gt 0) {
                $mfaPoliciesExist = $true
            }
        }
        catch {
            # Unable to check Conditional Access policies
        }
        
        # Add finding if no CA policies enforce MFA for admins
        if (-not $mfaPoliciesExist -and $privilegedUsers.Count -gt 0) {
            $findings += @{
                ObjectName = "Conditional Access Configuration"
                ObjectType = "Policy"
                RiskLevel = "High"
                Description = "No enabled Conditional Access policies found that enforce MFA for administrative roles. This creates a significant security gap."
                Remediation = "1. Create a Conditional Access policy requiring MFA for all directory roles. " +
                             "2. Include all administrative role assignments in the policy. " +
                             "3. Configure the policy to block legacy authentication. " +
                             "4. Enable sign-in risk and user risk policies. " +
                             "5. Test the policy with a pilot group before full deployment."
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
    $message = "MFA analysis for privileged accounts completed successfully."
    
    if ($findings.Count -gt 0) {
        $criticalCount = @($findings | Where-Object { $_.RiskLevel -eq "Critical" }).Count
        $highCount = @($findings | Where-Object { $_.RiskLevel -eq "High" }).Count
        
        if ($criticalCount -gt 0) {
            $score = 10  # Critical findings for MFA
            $message = "CRITICAL: Found $criticalCount critical privileged accounts without MFA and $highCount high-privilege accounts without MFA. Immediate remediation required!"
        }
        else {
            $score = 25  # Only high-risk findings
            $message = "WARNING: Found $highCount privileged accounts without proper MFA protection."
        }
    }
    else {
        $message = "All privileged accounts have MFA enabled. Authentication security appears properly configured."
    }
    
    return @{
        CheckId = "EID-T2-001"
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
            TotalPrivilegedUsers = $privilegedUsers.Count
            CriticalRolesChecked = $criticalRoles.Count
            HighPrivilegeRolesChecked = $highPrivilegeRoles.Count
            ConditionalAccessPoliciesExist = $mfaPoliciesExist
        }
    }
}
catch {
    return @{
        CheckId = "EID-T2-001"
        Timestamp = (Get-Date).ToString("o")
        Status = "Error"
        Score = 0
        Severity = "High"
        Category = "Authentication"
        Findings = @()
        Message = "Error analyzing MFA for privileged accounts: $_"
        AffectedObjects = 0
        IgnoredObjects = 0
        Metadata = @{
            TenantId = $TenantId
            ExecutionTime = 0.0
            ErrorDetails = $_.Exception.Message
        }
    }
}