<#
.SYNOPSIS
Detects guest accounts in privileged groups in Entra ID

.METADATA
{
  "id": "EID-T2-004",
  "name": "Guest Accounts in Privileged Groups",
  "description": "Including external guest accounts in highly privileged Entra ID groups introduces unnecessary risk. This check identifies the membership of built-in or custom administrative roles and flags any guest accounts.",
  "category": "PrivilegedAccess",
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
    
    # Critical privileged roles to check for guest accounts
    $criticalRoles = @{
        "62e90394-69f5-4237-9190-012177145e10" = "Global Administrator"
        "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3" = "Application Administrator"
        "194ae4cb-b126-40b2-bd5b-6091b380977d" = "Security Administrator"
        "f28a1f50-f6e7-4571-818b-6a12f2af6b6c" = "SharePoint Administrator"
        "29232cdf-9323-42fd-ade2-1d097af3e4de" = "Exchange Administrator"
        "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9" = "Conditional Access Administrator"
        "7be44c8a-adaf-4e2a-84d6-ab2649e08a13" = "Privileged Authentication Administrator"
        "e8611ab8-c189-46e8-94e1-60213ab1f814" = "Privileged Role Administrator"
        "fe930be7-5e62-47db-91af-98c3a49a38b1" = "User Administrator"
        "158c047a-c907-4556-b7ef-446551a6b5f7" = "Cloud Application Administrator"
    }
    
    # Additional high-privilege roles
    $highPrivilegeRoles = @{
        "966707d0-3269-4727-9be2-8c3a10f19b9d" = "Password Administrator"
        "7698a772-787b-4ac8-901f-60d6b08affd2" = "Cloud Device Administrator"
        "17315797-102d-40b4-93e0-432062caca18" = "Compliance Administrator"
        "b0f54661-2d74-4c50-afa3-1ec803f12efe" = "Billing Administrator"
        "729827e3-9c14-49f7-bb1b-9608f156bbb8" = "Helpdesk Administrator"
        "69091246-20e8-4a56-aa4d-066075b2a7a8" = "Teams Administrator"
        "baf37b3a-610e-45da-9e62-d9d1e5e8914b" = "Priority Account Administrator"
        "e00e864a-17c5-4a4b-9c06-f5b95a8d5bd8" = "Partner Tier2 Support"
        "4d6ac14f-3453-41d0-bef9-a3e0c569773a" = "License Administrator"
        "3a2c62db-5318-420d-8d74-23affee5d9d5" = "Intune Administrator"
    }
    
    # Check if Microsoft.Graph module is available
    $graphModuleAvailable = $null -ne (Get-Module -ListAvailable -Name Microsoft.Graph)
    
    if ($graphModuleAvailable) {
        # Import required modules
        Import-Module Microsoft.Graph.Identity.DirectoryManagement -ErrorAction SilentlyContinue
        Import-Module Microsoft.Graph.Users -ErrorAction SilentlyContinue
        Import-Module Microsoft.Graph.Groups -ErrorAction SilentlyContinue
        
        # Check if already connected
        $context = Get-MgContext -ErrorAction SilentlyContinue
        
        if (-not $context) {
            # Need to connect - for automated scenarios, this would need pre-configured auth
            throw "Not connected to Microsoft Graph. Please run Connect-MgGraph first with appropriate permissions (Directory.Read.All, RoleManagement.Read.All)"
        }
        
        # Use provided TenantId or get from context
        if (-not $TenantId) {
            $TenantId = $context.TenantId
        }
        
        # Track guest accounts found in privileged roles
        $guestPrivileges = @{}
        $totalGuestCount = 0
        $totalPrivilegedMembers = 0
        
        # Check critical roles first
        foreach ($roleId in $criticalRoles.Keys) {
            $roleName = $criticalRoles[$roleId]
            
            try {
                # Get role details
                $role = Get-MgDirectoryRole -Filter "roleTemplateId eq '$roleId'" -ErrorAction SilentlyContinue
                
                if ($role) {
                    # Get members of this role
                    $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All
                    
                    foreach ($member in $members) {
                        $totalPrivilegedMembers++
                        
                        if ($member.AdditionalProperties["@odata.type"] -eq "#microsoft.graph.user") {
                            $userId = $member.Id
                            
                            # Get user details
                            $user = Get-MgUser -UserId $userId -Property Id,DisplayName,UserPrincipalName,UserType,AccountEnabled,CreatedDateTime,Mail,ExternalUserState,ExternalUserStateChangeDateTime,OnPremisesSyncEnabled
                            
                            # Check if user is a guest
                            if ($user.UserType -eq "Guest") {
                                $totalGuestCount++
                                
                                if (-not $guestPrivileges.ContainsKey($userId)) {
                                    $guestPrivileges[$userId] = @{
                                        User = $user
                                        Roles = @()
                                        RoleSeverity = "High"
                                        InvitationState = $user.ExternalUserState
                                        DaysSinceInvited = 0
                                        IsCriticalRole = $false
                                    }
                                }
                                
                                $guestPrivileges[$userId].Roles += $roleName
                                $guestPrivileges[$userId].RoleSeverity = "Critical"
                                $guestPrivileges[$userId].IsCriticalRole = $true
                                
                                # Calculate days since invitation
                                if ($user.ExternalUserStateChangeDateTime) {
                                    $daysSince = (Get-Date) - $user.ExternalUserStateChangeDateTime
                                    $guestPrivileges[$userId].DaysSinceInvited = [int]$daysSince.Days
                                }
                                elseif ($user.CreatedDateTime) {
                                    $daysSince = (Get-Date) - $user.CreatedDateTime
                                    $guestPrivileges[$userId].DaysSinceInvited = [int]$daysSince.Days
                                }
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
        
        # Check high-privilege roles
        foreach ($roleId in $highPrivilegeRoles.Keys) {
            $roleName = $highPrivilegeRoles[$roleId]
            
            try {
                # Get role details
                $role = Get-MgDirectoryRole -Filter "roleTemplateId eq '$roleId'" -ErrorAction SilentlyContinue
                
                if ($role) {
                    # Get members of this role
                    $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All
                    
                    foreach ($member in $members) {
                        $totalPrivilegedMembers++
                        
                        if ($member.AdditionalProperties["@odata.type"] -eq "#microsoft.graph.user") {
                            $userId = $member.Id
                            
                            # Get user details
                            $user = Get-MgUser -UserId $userId -Property Id,DisplayName,UserPrincipalName,UserType,AccountEnabled,CreatedDateTime,Mail,ExternalUserState,ExternalUserStateChangeDateTime,OnPremisesSyncEnabled
                            
                            # Check if user is a guest
                            if ($user.UserType -eq "Guest") {
                                $totalGuestCount++
                                
                                if (-not $guestPrivileges.ContainsKey($userId)) {
                                    $guestPrivileges[$userId] = @{
                                        User = $user
                                        Roles = @()
                                        RoleSeverity = "High"
                                        InvitationState = $user.ExternalUserState
                                        DaysSinceInvited = 0
                                        IsCriticalRole = $false
                                    }
                                }
                                
                                $guestPrivileges[$userId].Roles += $roleName
                                
                                # Calculate days since invitation
                                if ($user.ExternalUserStateChangeDateTime) {
                                    $daysSince = (Get-Date) - $user.ExternalUserStateChangeDateTime
                                    $guestPrivileges[$userId].DaysSinceInvited = [int]$daysSince.Days
                                }
                                elseif ($user.CreatedDateTime) {
                                    $daysSince = (Get-Date) - $user.CreatedDateTime
                                    $guestPrivileges[$userId].DaysSinceInvited = [int]$daysSince.Days
                                }
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
        
        # Also check privileged groups (often used for role assignment)
        $privilegedGroups = @()
        try {
            # Get groups that might have privileged access
            $groups = Get-MgGroup -Filter "securityEnabled eq true" -Top 999 -Property Id,DisplayName,Description,MembershipRule,GroupTypes
            
            foreach ($group in $groups) {
                # Check if group name suggests privileged access
                $groupNameLower = $group.DisplayName.ToLower()
                if ($groupNameLower -match "admin|privilege|security|compliance|owner|operator|manager") {
                    # Check group members
                    $groupMembers = Get-MgGroupMember -GroupId $group.Id -All
                    
                    $hasPrivilegedRole = $false
                    $guestMembersInGroup = @()
                    
                    foreach ($member in $groupMembers) {
                        if ($member.AdditionalProperties["@odata.type"] -eq "#microsoft.graph.user") {
                            $user = Get-MgUser -UserId $member.Id -Property UserType,DisplayName,UserPrincipalName
                            
                            if ($user.UserType -eq "Guest") {
                                $guestMembersInGroup += $user
                            }
                        }
                    }
                    
                    # If group has guest members, add to findings
                    if ($guestMembersInGroup.Count -gt 0) {
                        foreach ($guestUser in $guestMembersInGroup) {
                            $findings += @{
                                ObjectName = $guestUser.UserPrincipalName
                                ObjectType = "User"
                                RiskLevel = "Medium"
                                Description = "Guest account found in potentially privileged group: '$($group.DisplayName)'. This group may have elevated permissions."
                                Remediation = "1. Review if guest access is necessary for this group. " +
                                            "2. Verify the group's actual permissions and access rights. " +
                                            "3. Consider removing guest from group or moving to a less privileged group. " +
                                            "4. Implement group access reviews for regular certification. " +
                                            "5. Use Entitlement Management for time-bound guest access."
                                AffectedAttributes = @("GroupMembership", "UserType", "SecurityGroups")
                            }
                        }
                    }
                }
            }
        }
        catch {
            # Unable to check group memberships
        }
        
        # Create findings for guest accounts in privileged roles
        foreach ($guestId in $guestPrivileges.Keys) {
            $guestInfo = $guestPrivileges[$guestId]
            $guest = $guestInfo.User
            
            $riskLevel = $guestInfo.RoleSeverity
            $accountStatus = if ($guest.AccountEnabled) { "Enabled" } else { "Disabled" }
            $inviteStatus = if ($guestInfo.InvitationState) { $guestInfo.InvitationState } else { "Unknown" }
            
            # Build remediation based on risk level
            $remediation = if ($riskLevel -eq "Critical") {
                "1. IMMEDIATE ACTION REQUIRED: Remove guest account from critical administrative roles immediately. " +
                "2. Review audit logs for all actions performed by this guest account. " +
                "3. If guest admin access is required, create a separate managed account instead. " +
                "4. Implement Privileged Identity Management (PIM) with time-bound access. " +
                "5. Enable continuous access evaluation and risk-based policies. " +
                "6. Configure B2B collaboration settings to restrict guest permissions. " +
                "7. Regular access reviews (monthly) for all guest accounts."
            }
            else {
                "1. Review if guest account requires privileged access. " +
                "2. Consider using Entitlement Management for time-bound access. " +
                "3. Implement access reviews for guest account privileges. " +
                "4. Enable monitoring and alerting for guest administrative actions. " +
                "5. Apply Conditional Access policies specific to guest accounts."
            }
            
            $domain = if ($guest.Mail) { $guest.Mail.Split('@')[1] } else { "Unknown" }
            
            $findings += @{
                ObjectName = $guest.UserPrincipalName
                ObjectType = "Guest"
                RiskLevel = $riskLevel
                Description = "Guest account from domain '$domain' has $($guestInfo.Roles.Count) privileged role(s): $($guestInfo.Roles -join ', '). Account is $accountStatus. Invitation status: $inviteStatus. Guest for $($guestInfo.DaysSinceInvited) days."
                Remediation = $remediation
                AffectedAttributes = @("UserType", "DirectoryRoles", "ExternalUserState", "AccountEnabled")
            }
        }
        
        # Check guest invitation settings
        $guestSettings = $null
        try {
            $authPolicy = Get-MgPolicyAuthorizationPolicy -ErrorAction SilentlyContinue
            
            if ($authPolicy) {
                $allowInvites = $authPolicy.AllowInvitesFrom
                $guestUserRole = $authPolicy.GuestUserRoleId
                
                # Check if guest invitation settings are too permissive
                if ($allowInvites -eq "everyone" -or $allowInvites -eq "everyoneInTheOrganization") {
                    $findings += @{
                        ObjectName = "Guest Invitation Settings"
                        ObjectType = "Policy"
                        RiskLevel = "Medium"
                        Description = "Guest invitation is allowed by $allowInvites. This permissive setting could lead to unauthorized external access."
                        Remediation = "1. Restrict guest invitations to admins and designated guest inviters only. " +
                                    "2. Navigate to External Identities > External collaboration settings. " +
                                    "3. Set 'Guest invite restrictions' to most restrictive option. " +
                                    "4. Configure guest user permissions appropriately. " +
                                    "5. Enable email one-time passcode authentication for guests."
                        AffectedAttributes = @("AllowInvitesFrom", "GuestInviteSettings")
                    }
                }
                
                # Check guest user default permissions
                if ($guestUserRole -eq "a0b1b346-4d3e-4e8b-98f8-753987be4970") {
                    # Guest users have same access as members (risky)
                    $findings += @{
                        ObjectName = "Guest User Permissions"
                        ObjectType = "Policy"
                        RiskLevel = "High"
                        Description = "Guest users have the same permissions as member users. This gives guests excessive access to directory information."
                        Remediation = "1. Restrict guest user permissions immediately. " +
                                    "2. Navigate to External Identities > External collaboration settings. " +
                                    "3. Set 'Guest user permissions are limited' to Yes. " +
                                    "4. Review all existing guest accounts for excessive permissions. " +
                                    "5. Implement Conditional Access policies for guest users."
                        AffectedAttributes = @("GuestUserRoleId", "DefaultUserRolePermissions")
                    }
                }
            }
        }
        catch {
            # Unable to check guest settings
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
    $message = "Guest account privilege analysis completed successfully."
    
    if ($findings.Count -gt 0) {
        $criticalCount = @($findings | Where-Object { $_.RiskLevel -eq "Critical" }).Count
        $highCount = @($findings | Where-Object { $_.RiskLevel -eq "High" }).Count
        $mediumCount = @($findings | Where-Object { $_.RiskLevel -eq "Medium" }).Count
        
        if ($criticalCount -gt 0) {
            $score = 10  # Critical - guests in critical admin roles
            $message = "CRITICAL: Found $criticalCount guest account(s) with critical administrative privileges! This poses severe security risk."
        }
        elseif ($highCount -gt 0) {
            $score = 25  # High-risk findings
            $message = "WARNING: Found $highCount guest account(s) with high-level privileges and $mediumCount medium-risk issues."
        }
        else {
            $score = 50  # Medium-risk findings
            $message = "Found $mediumCount medium-risk issues with guest accounts in potentially privileged groups."
        }
    }
    else {
        $message = "No guest accounts found in privileged roles. Guest access appears properly restricted."
    }
    
    return @{
        CheckId = "EID-T2-004"
        Timestamp = (Get-Date).ToString("o")
        Status = $status
        Score = $score
        Severity = "High"
        Category = "PrivilegedAccess"
        Findings = $findings
        Message = $message
        AffectedObjects = $findings.Count
        IgnoredObjects = 0
        Metadata = @{
            TenantId = $TenantId
            ExecutionTime = [Math]::Round($executionTime, 2)
            TotalPrivilegedMembers = $totalPrivilegedMembers
            GuestAccountsInRoles = $guestPrivileges.Count
            CriticalRolesChecked = $criticalRoles.Count
            HighPrivilegeRolesChecked = $highPrivilegeRoles.Count
            TotalGuestCount = $totalGuestCount
        }
    }
}
catch {
    return @{
        CheckId = "EID-T2-004"
        Timestamp = (Get-Date).ToString("o")
        Status = "Error"
        Score = 0
        Severity = "High"
        Category = "PrivilegedAccess"
        Findings = @()
        Message = "Error analyzing guest accounts in privileged roles: $_"
        AffectedObjects = 0
        IgnoredObjects = 0
        Metadata = @{
            TenantId = $TenantId
            ExecutionTime = 0.0
            ErrorDetails = $_.Exception.Message
        }
    }
}