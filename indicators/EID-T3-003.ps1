<#
.SYNOPSIS
Detects if guest users have permissions to invite other guests in Entra ID

.METADATA
{
  "id": "EID-T3-003",
  "name": "Guests Having Permissions to Invite Other Guests",
  "description": "Allowing guest users to invite other guests can lead to uncontrolled proliferation of external accounts in the directory. This check examines external collaboration settings in Entra ID to determine if guests are allowed to invite other guests.",
  "category": "Authorization",
  "severity": "Medium",
  "weight": 5,
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
        Import-Module Microsoft.Graph.Users -ErrorAction SilentlyContinue
        Import-Module Microsoft.Graph.Identity.SignIns -ErrorAction SilentlyContinue
        
        # Check if already connected
        $context = Get-MgContext -ErrorAction SilentlyContinue
        
        if (-not $context) {
            # Need to connect - for automated scenarios, this would need pre-configured auth
            throw "Not connected to Microsoft Graph. Please run Connect-MgGraph first with appropriate permissions (Policy.Read.All, User.Read.All, Directory.Read.All)"
        }
        
        # Use provided TenantId or get from context
        if (-not $TenantId) {
            $TenantId = $context.TenantId
        }
        
        # Get external collaboration settings (B2B settings)
        $authorizationPolicy = Get-MgPolicyAuthorizationPolicy -ErrorAction SilentlyContinue
        $guestInviteSettings = $authorizationPolicy.AllowInvitesFrom
        
        # Possible values for AllowInvitesFrom:
        # - "none" - No one can invite guests
        # - "adminsAndGuestInviters" - Only admins and users in guest inviter role
        # - "adminsGuestInvitersAndAllMembers" - Admins, guest inviters, and all members
        # - "everyone" - Everyone including guests can invite
        
        $guestsCanInvite = $guestInviteSettings -eq "everyone"
        $membersCanInvite = $guestInviteSettings -in @("adminsGuestInvitersAndAllMembers", "everyone")
        
        # Get additional B2B collaboration restrictions
        $b2bPolicy = Get-MgPolicyB2BCollaborationPolicy -ErrorAction SilentlyContinue
        $hasAllowList = $false
        $hasDenyList = $false
        $allowedDomains = @()
        $deniedDomains = @()
        
        if ($b2bPolicy) {
            if ($b2bPolicy.B2BCollaborationInbound) {
                $hasAllowList = $b2bPolicy.B2BCollaborationInbound.UsersAndGroups.AllowedTargets.Count -gt 0
                $hasDenyList = $b2bPolicy.B2BCollaborationInbound.UsersAndGroups.DeniedTargets.Count -gt 0
                
                if ($b2bPolicy.B2BCollaborationInbound.Applications) {
                    $allowedDomains = $b2bPolicy.B2BCollaborationInbound.Applications.AllowedTargets
                    $deniedDomains = $b2bPolicy.B2BCollaborationInbound.Applications.DeniedTargets
                }
            }
        }
        
        # Get guest user statistics
        $allUsers = Get-MgUser -All -Property UserType,CreatedDateTime,SignInActivity,Mail,DisplayName,Id,AccountEnabled
        $guestUsers = @($allUsers | Where-Object { $_.UserType -eq "Guest" })
        $memberUsers = @($allUsers | Where-Object { $_.UserType -eq "Member" })
        
        # Analyze guest invitation patterns
        $recentGuestThreshold = (Get-Date).AddDays(-90)
        $recentGuests = @($guestUsers | Where-Object { $_.CreatedDateTime -gt $recentGuestThreshold })
        $activeGuests = @($guestUsers | Where-Object { 
            $_.AccountEnabled -and 
            $_.SignInActivity -and 
            $_.SignInActivity.LastSignInDateTime -gt (Get-Date).AddDays(-30)
        })
        $staleGuests = @($guestUsers | Where-Object {
            -not $_.SignInActivity -or
            $_.SignInActivity.LastSignInDateTime -lt (Get-Date).AddDays(-90)
        })
        
        # Calculate guest proliferation metrics
        $guestRatio = if ($allUsers.Count -gt 0) { 
            [Math]::Round(($guestUsers.Count / $allUsers.Count) * 100, 2) 
        } else { 0 }
        
        $guestGrowthRate = if ($guestUsers.Count -gt 0) {
            [Math]::Round(($recentGuests.Count / $guestUsers.Count) * 100, 2)
        } else { 0 }
        
        # Finding 1: Guests can invite other guests
        if ($guestsCanInvite) {
            $findings += @{
                ObjectName = "External Collaboration Settings"
                ObjectType = "PolicyConfiguration"
                RiskLevel = "Medium"
                Description = "Guest users are allowed to invite other guests to the tenant. Currently $($guestUsers.Count) guest users exist ($guestRatio% of all users), with $($recentGuests.Count) added in the last 90 days. This setting enables uncontrolled external account proliferation."
                Remediation = "1. Change external collaboration settings to restrict guest invitations. " +
                             "2. Navigate to External Identities > External collaboration settings. " +
                             "3. Set 'Guest invite restrictions' to 'Only users assigned to specific admin roles'. " +
                             "4. Create a controlled process for guest invitations with approval workflow. " +
                             "5. Implement guest access reviews to regularly validate external accounts. " +
                             "6. Set up alerts for new guest invitations. " +
                             "7. Consider using entitlement management for guest lifecycle."
                AffectedAttributes = @("AllowInvitesFrom", "GuestInviteSettings", "B2BCollaboration")
            }
        }
        
        # Finding 2: All members can invite guests without restrictions
        if ($membersCanInvite -and -not $hasAllowList -and -not $hasDenyList) {
            $riskLevel = if ($guestRatio -gt 20) { "Medium" } else { "Low" }
            
            $findings += @{
                ObjectName = "Guest Invitation Permissions"
                ObjectType = "PolicyConfiguration"
                RiskLevel = $riskLevel
                Description = "All member users ($($memberUsers.Count) users) can invite guests without domain restrictions. No allow/deny lists are configured. Guest ratio is $guestRatio% with $guestGrowthRate% recent growth."
                Remediation = "1. Implement domain-based restrictions for guest invitations. " +
                             "2. Configure allowed or blocked domain lists based on business partners. " +
                             "3. Limit guest invitation permissions to specific roles or groups. " +
                             "4. Set up approval workflows for guest access requests. " +
                             "5. Enable email one-time passcode authentication for guests. " +
                             "6. Configure guest user access restrictions. " +
                             "7. Implement regular access reviews for guest accounts."
                AffectedAttributes = @("MemberInvitePermissions", "DomainRestrictions")
            }
        }
        
        # Finding 3: High guest user ratio
        if ($guestRatio -gt 30) {
            $findings += @{
                ObjectName = "Guest User Population"
                ObjectType = "UserMetrics"
                RiskLevel = "Medium"
                Description = "Guest users comprise $guestRatio% of all users ($($guestUsers.Count) guests out of $($allUsers.Count) total). This high ratio of external users increases security risk and management complexity."
                Remediation = "1. Review and validate all existing guest accounts. " +
                             "2. Remove unnecessary or stale guest accounts ($($staleGuests.Count) inactive guests identified). " +
                             "3. Implement automated guest lifecycle management. " +
                             "4. Set up recurring access reviews for guest users. " +
                             "5. Configure automatic expiration for guest invitations. " +
                             "6. Monitor guest user activities and permissions. " +
                             "7. Consider using B2B direct connect for partner organizations."
                AffectedAttributes = @("GuestRatio", "UserPopulation")
            }
        }
        
        # Finding 4: Stale guest accounts
        if ($staleGuests.Count -gt 20 -or ($guestUsers.Count -gt 0 -and ($staleGuests.Count / $guestUsers.Count) -gt 0.3)) {
            $stalePercentage = if ($guestUsers.Count -gt 0) {
                [Math]::Round(($staleGuests.Count / $guestUsers.Count) * 100, 2)
            } else { 0 }
            
            $findings += @{
                ObjectName = "Stale Guest Accounts"
                ObjectType = "UserManagement"
                RiskLevel = "Low"
                Description = "$($staleGuests.Count) guest accounts ($stalePercentage% of all guests) have been inactive for over 90 days. These stale accounts present unnecessary security risk."
                Remediation = "1. Review and remove inactive guest accounts. " +
                             "2. Implement automated cleanup policies for inactive guests. " +
                             "3. Set up access reviews with automatic removal for denied users. " +
                             "4. Configure guest invitation expiration (default 60 days). " +
                             "5. Enable notification when guests don't sign in within specified period. " +
                             "6. Use Lifecycle Workflows to automate guest offboarding."
                AffectedAttributes = @("InactiveGuests", "AccountLifecycle")
            }
        }
        
        # Finding 5: No domain restrictions configured
        if (($membersCanInvite -or $guestsCanInvite) -and $allowedDomains.Count -eq 0 -and $deniedDomains.Count -eq 0) {
            $findings += @{
                ObjectName = "Domain Restrictions"
                ObjectType = "PolicyConfiguration"
                RiskLevel = "Low"
                Description = "No domain allow or deny lists are configured for B2B collaboration. Guests can be invited from any email domain without restrictions."
                Remediation = "1. Define trusted partner domains for B2B collaboration. " +
                             "2. Configure allow list with trusted partner domains. " +
                             "3. OR configure deny list with high-risk or consumer domains. " +
                             "4. Block invitations from consumer email providers if not needed. " +
                             "5. Document approved partner organizations and domains. " +
                             "6. Regularly review and update domain restriction lists."
                AffectedAttributes = @("AllowedDomains", "DeniedDomains", "B2BRestrictions")
            }
        }
        
        # Finding 6: Check for guests with administrative roles
        $privilegedGuests = @()
        $adminRoles = @(
            "62e90394-69f5-4237-9190-012177145e10",  # Global Administrator
            "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",  # Application Administrator
            "194ae4cb-b126-40b2-bd5b-6091b380977d",  # Security Administrator
            "fe930be7-5e62-47db-91af-98c3a49a38b1"   # User Administrator
        )
        
        foreach ($roleId in $adminRoles) {
            try {
                $role = Get-MgDirectoryRole -Filter "roleTemplateId eq '$roleId'" -ErrorAction SilentlyContinue
                if ($role) {
                    $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All
                    foreach ($member in $members) {
                        if ($member.AdditionalProperties["@odata.type"] -eq "#microsoft.graph.user") {
                            $user = $allUsers | Where-Object { $_.Id -eq $member.Id }
                            if ($user -and $user.UserType -eq "Guest") {
                                $privilegedGuests += @{
                                    User = $user.DisplayName
                                    Email = $user.Mail
                                    Role = $role.DisplayName
                                }
                            }
                        }
                    }
                }
            }
            catch {
                continue
            }
        }
        
        if ($privilegedGuests.Count -gt 0) {
            $guestAdminList = $privilegedGuests | ForEach-Object { "$($_.User) ($($_.Role))" }
            
            $findings += @{
                ObjectName = "Privileged Guest Accounts"
                ObjectType = "RoleAssignment"
                RiskLevel = "Medium"
                Description = "$($privilegedGuests.Count) guest users have administrative roles: $($guestAdminList -join ', '). External users with admin privileges pose significant security risk."
                Remediation = "1. Review and remove administrative roles from guest accounts. " +
                             "2. Use member accounts for administrative tasks. " +
                             "3. If partner admin access is required, use B2B direct connect. " +
                             "4. Implement Privileged Identity Management (PIM) for all admin roles. " +
                             "5. Configure Conditional Access to block guest admin access. " +
                             "6. Set up alerts for privilege assignments to guest users."
                AffectedAttributes = @("PrivilegedRoles", "GuestAdministrators")
            }
        }
        
        # Finding 7: Guest user access to applications
        if ($guestUsers.Count -gt 50) {
            $findings += @{
                ObjectName = "Guest Application Access"
                ObjectType = "ApplicationPermissions"
                RiskLevel = "Low"
                Description = "Large number of guest users ($($guestUsers.Count)) have potential access to tenant applications. Review application assignment policies for guests."
                Remediation = "1. Audit application permissions granted to guest users. " +
                             "2. Implement app assignment policies restricting guest access. " +
                             "3. Use Conditional Access to limit guest application access. " +
                             "4. Configure user assignment required for sensitive applications. " +
                             "5. Review and restrict Microsoft 365 group creation by guests. " +
                             "6. Monitor guest access to sensitive resources."
                AffectedAttributes = @("ApplicationAccess", "GuestPermissions")
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
    $message = "Guest invitation and collaboration settings analysis completed successfully."
    
    if ($findings.Count -gt 0) {
        $mediumCount = @($findings | Where-Object { $_.RiskLevel -eq "Medium" }).Count
        $lowCount = @($findings | Where-Object { $_.RiskLevel -eq "Low" }).Count
        
        if ($mediumCount -gt 0) {
            $score = 50  # Medium findings
            $message = "Found $mediumCount medium-risk issues with guest collaboration settings. Guest invitation permissions need tighter controls."
        }
        else {
            $score = 75  # Only low-risk findings
            $message = "Found $lowCount low-risk guest management improvements. Guest collaboration is reasonably controlled."
        }
    }
    else {
        $message = "Guest invitation settings are properly restricted. External collaboration appears well-controlled."
    }
    
    return @{
        CheckId = "EID-T3-003"
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
            GuestsCanInvite = $guestsCanInvite
            MembersCanInvite = $membersCanInvite
            InviteSettings = $guestInviteSettings
            TotalGuests = $guestUsers.Count
            TotalMembers = $memberUsers.Count
            GuestRatioPercentage = $guestRatio
            RecentGuests = $recentGuests.Count
            ActiveGuests = $activeGuests.Count
            StaleGuests = $staleGuests.Count
            PrivilegedGuests = $privilegedGuests.Count
            HasDomainRestrictions = ($allowedDomains.Count -gt 0 -or $deniedDomains.Count -gt 0)
        }
    }
}
catch {
    return @{
        CheckId = "EID-T3-003"
        Timestamp = (Get-Date).ToString("o")
        Status = "Error"
        Score = 0
        Severity = "Medium"
        Category = "Authorization"
        Findings = @()
        Message = "Error analyzing guest invitation settings: $_"
        AffectedObjects = 0
        IgnoredObjects = 0
        Metadata = @{
            TenantId = $TenantId
            ExecutionTime = 0.0
            ErrorDetails = $_.Exception.Message
        }
    }
}