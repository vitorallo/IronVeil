<#
.SYNOPSIS
Detects cross-environment privileged account overlap between Entra ID and on-premises AD

.METADATA
{
  "id": "EID-T1-002",
  "name": "Cross-Environment Privileged Account Overlap",
  "description": "Accounts that hold high privileges in both Entra ID and on-premises Active Directory represent a critical security bridge between environments. Compromise of these accounts could lead to full hybrid environment takeover.",
  "category": "PrivilegedAccess",
  "severity": "Critical",
  "weight": 10,
  "impact": 10,
  "frameworks": ["MITRE", "NIST"],
  "targets": ["EntraID", "ActiveDirectory"]
}
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$TenantId,
    
    [Parameter(Mandatory=$false)]
    [string]$DomainName = $env:USERDNSDOMAIN
)

try {
    $startTime = Get-Date
    $findings = @()
    
    # Define privileged roles in Entra ID (Azure AD)
    $privilegedEntraRoles = @(
        "Global Administrator",
        "Privileged Role Administrator",
        "Security Administrator",
        "Exchange Administrator",
        "SharePoint Administrator",
        "User Administrator",
        "Password Administrator",
        "Conditional Access Administrator",
        "Application Administrator",
        "Cloud Application Administrator",
        "Authentication Administrator",
        "Privileged Authentication Administrator",
        "Hybrid Identity Administrator",
        "Azure AD Joined Device Local Administrator",
        "Directory Writers",
        "Intune Administrator",
        "Azure Information Protection Administrator",
        "Security Operator",
        "Security Reader",
        "Global Reader",
        "Compliance Administrator",
        "Billing Administrator"
    )
    
    # Critical roles that should never overlap
    $criticalEntraRoles = @(
        "Global Administrator",
        "Privileged Role Administrator",
        "Security Administrator",
        "Hybrid Identity Administrator"
    )
    
    # Define privileged groups in on-premises AD
    $privilegedADGroups = @(
        "Domain Admins",
        "Enterprise Admins",
        "Schema Admins",
        "Administrators",
        "Account Operators",
        "Backup Operators",
        "Server Operators",
        "Print Operators",
        "DNSAdmins",
        "DHCP Administrators",
        "Cert Publishers",
        "Group Policy Creator Owners"
    )
    
    # Critical AD groups that should never overlap with Entra roles
    $criticalADGroups = @(
        "Domain Admins",
        "Enterprise Admins",
        "Schema Admins",
        "Administrators"
    )
    
    # Step 1: Get privileged users from Entra ID
    $entraPrivilegedUsers = @{}
    
    # Check if Microsoft.Graph module is available
    $graphModuleAvailable = $null -ne (Get-Module -ListAvailable -Name Microsoft.Graph)
    
    if ($graphModuleAvailable) {
        # Import required modules
        Import-Module Microsoft.Graph.Identity.DirectoryManagement -ErrorAction SilentlyContinue
        Import-Module Microsoft.Graph.Users -ErrorAction SilentlyContinue
        
        # Check if already connected
        $context = Get-MgContext -ErrorAction SilentlyContinue
        
        if (-not $context) {
            throw "Not connected to Microsoft Graph. Please run Connect-MgGraph first with appropriate permissions (RoleManagement.Read.Directory, User.Read.All)"
        }
        
        # Use provided TenantId or get from context
        if (-not $TenantId) {
            $TenantId = $context.TenantId
        }
        
        # Get all directory role templates
        $roleTemplates = Get-MgDirectoryRoleTemplate -All
        
        # Get active directory roles
        $activeRoles = Get-MgDirectoryRole -All
        
        foreach ($role in $activeRoles) {
            $roleTemplate = $roleTemplates | Where-Object { $_.Id -eq $role.RoleTemplateId }
            $roleName = if ($roleTemplate) { $roleTemplate.DisplayName } else { $role.DisplayName }
            
            # Check if this is a privileged role
            if ($privilegedEntraRoles -contains $roleName) {
                # Get members of this role
                $roleMembers = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All
                
                foreach ($member in $roleMembers) {
                    # Get user details
                    if ($member.AdditionalProperties["@odata.type"] -eq "#microsoft.graph.user") {
                        $user = Get-MgUser -UserId $member.Id -Property Id,DisplayName,UserPrincipalName,OnPremisesSamAccountName,OnPremisesDomainName,OnPremisesSyncEnabled,AccountEnabled,CreatedDateTime -ErrorAction SilentlyContinue
                        
                        if ($user -and $user.OnPremisesSyncEnabled) {
                            # This is a synced user - potential for cross-environment privilege
                            $userKey = if ($user.OnPremisesSamAccountName) { 
                                $user.OnPremisesSamAccountName.ToLower() 
                            } else { 
                                $user.UserPrincipalName.Split("@")[0].ToLower() 
                            }
                            
                            if (-not $entraPrivilegedUsers.ContainsKey($userKey)) {
                                $entraPrivilegedUsers[$userKey] = @{
                                    DisplayName = $user.DisplayName
                                    UserPrincipalName = $user.UserPrincipalName
                                    OnPremisesSamAccountName = $user.OnPremisesSamAccountName
                                    OnPremisesDomainName = $user.OnPremisesDomainName
                                    AccountEnabled = $user.AccountEnabled
                                    CreatedDateTime = $user.CreatedDateTime
                                    EntraRoles = @()
                                    IsSynced = $true
                                }
                            }
                            
                            $entraPrivilegedUsers[$userKey].EntraRoles += $roleName
                        }
                    }
                }
            }
        }
    }
    else {
        throw "Microsoft.Graph module not available. Please install with: Install-Module Microsoft.Graph -Scope CurrentUser"
    }
    
    # Step 2: Get privileged users from on-premises AD
    $adPrivilegedUsers = @{}
    
    if ($DomainName) {
        # Import ADSI Helper
        $helperPath = Join-Path $PSScriptRoot "IronVeil-ADSIHelper.ps1"
        if (Test-Path $helperPath) {
            . $helperPath
        }
        else {
            throw "IronVeil-ADSIHelper.ps1 not found at: $helperPath"
        }
        
        # Get domain information using ADSI
        try {
            $domainInfo = Get-IVDomainInfo -DomainName $DomainName
            
            if ($domainInfo) {
                foreach ($groupName in $privilegedADGroups) {
                    try {
                        # Search for the group using ADSI
                        $groupFilter = "(&(objectClass=group)(sAMAccountName=$groupName))"
                        $groups = Search-IVADObjects -Filter $groupFilter -Properties @('distinguishedName', 'sAMAccountName')
                        
                        if ($groups -and $groups.Count -gt 0) {
                            $group = $groups[0]
                            
                            # Get group members recursively using ADSI
                            $members = Get-IVADGroupMember -Identity $group.sAMAccountName -Recursive
                            
                            foreach ($member in $members) {
                                if ($member.ObjectClass -eq "user") {
                                    # Get full user details using ADSI
                                    $userFilter = "(&(objectClass=user)(sAMAccountName=$($member.SamAccountName)))"
                                    $users = Search-IVADObjects -Filter $userFilter -Properties @('sAMAccountName', 'displayName', 'userPrincipalName', 'userAccountControl', 'whenCreated', 'memberOf')
                                    
                                    if ($users -and $users.Count -gt 0) {
                                        $adUser = $users[0]
                                        
                                        # Check if account is enabled using UserAccountControl
                                        $isEnabled = $false
                                        if ($adUser.userAccountControl) {
                                            $uac = if ($adUser.userAccountControl -is [Array]) { 
                                                $adUser.userAccountControl[0] 
                                            } else { 
                                                $adUser.userAccountControl 
                                            }
                                            $isEnabled = -not (Test-IVUserAccountControl -UAC $uac -Flag 'ACCOUNTDISABLE')
                                        }
                                        
                                        $userKey = $adUser.sAMAccountName.ToLower()
                                        
                                        if (-not $adPrivilegedUsers.ContainsKey($userKey)) {
                                            $adPrivilegedUsers[$userKey] = @{
                                                SamAccountName = $adUser.sAMAccountName
                                                DisplayName = if ($adUser.displayName) { 
                                                    if ($adUser.displayName -is [Array]) { $adUser.displayName[0] } else { $adUser.displayName }
                                                } else { $adUser.sAMAccountName }
                                                UserPrincipalName = if ($adUser.userPrincipalName) { 
                                                    if ($adUser.userPrincipalName -is [Array]) { $adUser.userPrincipalName[0] } else { $adUser.userPrincipalName }
                                                } else { $null }
                                                Enabled = $isEnabled
                                                WhenCreated = if ($adUser.whenCreated) {
                                                    if ($adUser.whenCreated -is [Array]) { $adUser.whenCreated[0] } else { $adUser.whenCreated }
                                                } else { $null }
                                                ADGroups = @()
                                            }
                                        }
                                        
                                        if ($adPrivilegedUsers[$userKey].ADGroups -notcontains $groupName) {
                                            $adPrivilegedUsers[$userKey].ADGroups += $groupName
                                        }
                                    }
                                }
                            }
                        }
                    }
                    catch {
                        # Continue if we can't access a specific group
                    }
                }
            }
        }
        catch {
            # If ADSI operations fail, continue with what we have
        }
    }
    
    # Step 3: Find overlapping privileged accounts
    foreach ($userKey in $entraPrivilegedUsers.Keys) {
        if ($adPrivilegedUsers.ContainsKey($userKey)) {
            $entraUser = $entraPrivilegedUsers[$userKey]
            $adUser = $adPrivilegedUsers[$userKey]
            
            # Determine risk level based on role combinations
            $riskLevel = "High"
            $hasCriticalEntraRole = $false
            $hasCriticalADGroup = $false
            
            foreach ($role in $entraUser.EntraRoles) {
                if ($criticalEntraRoles -contains $role) {
                    $hasCriticalEntraRole = $true
                    break
                }
            }
            
            foreach ($group in $adUser.ADGroups) {
                if ($criticalADGroups -contains $group) {
                    $hasCriticalADGroup = $true
                    break
                }
            }
            
            if ($hasCriticalEntraRole -and $hasCriticalADGroup) {
                $riskLevel = "Critical"
            }
            
            # Calculate days since creation
            $daysSinceCreation = if ($entraUser.CreatedDateTime) {
                (Get-Date) - $entraUser.CreatedDateTime
            } else {
                (Get-Date) - $adUser.WhenCreated
            }
            
            # Build description
            $description = "User has privileged access in both environments. " +
                          "Entra ID roles: $($entraUser.EntraRoles -join ', '). " +
                          "AD groups: $($adUser.ADGroups -join ', '). " +
                          "Account age: $([int]$daysSinceCreation.Days) days. " +
                          "This creates a critical attack path between cloud and on-premises environments."
            
            # Build remediation
            $remediation = if ($riskLevel -eq "Critical") {
                "1. CRITICAL: This account bridges both environments with highest privileges. " +
                "2. Immediately implement separate accounts for cloud and on-premises administration. " +
                "3. Remove either Entra ID roles or AD group memberships from this account. " +
                "4. Enable MFA and Privileged Identity Management (PIM) for cloud roles. " +
                "5. Implement Privileged Access Workstations (PAWs) for administrative tasks. " +
                "6. Enable continuous monitoring and alerting for this account. " +
                "7. Review and audit all recent activities from this account."
            }
            else {
                "1. Implement separate administrative accounts for cloud and on-premises. " +
                "2. Follow the principle of least privilege - remove unnecessary permissions. " +
                "3. Enable MFA for this account if not already enabled. " +
                "4. Consider using Privileged Identity Management (PIM) for just-in-time access. " +
                "5. Regular review of account permissions (monthly). " +
                "6. Implement conditional access policies for administrative actions."
            }
            
            $findings += @{
                ObjectName = $entraUser.DisplayName
                ObjectType = "User"
                RiskLevel = $riskLevel
                Description = $description
                Remediation = $remediation
                AffectedAttributes = @("EntraRoles", "ADGroupMembership", "OnPremisesSyncEnabled")
            }
        }
    }
    
    # Calculate execution time
    $executionTime = ((Get-Date) - $startTime).TotalSeconds
    
    # Determine final score and status
    $score = 100  # Start with perfect score
    $status = "Success"
    $message = "Cross-environment privilege analysis completed successfully."
    
    if ($findings.Count -gt 0) {
        $criticalCount = @($findings | Where-Object { $_.RiskLevel -eq "Critical" }).Count
        $highCount = @($findings | Where-Object { $_.RiskLevel -eq "High" }).Count
        
        if ($criticalCount -gt 0) {
            $score = 0  # Critical findings mean score of 0
            $message = "CRITICAL: Found $criticalCount accounts with critical privileges in both environments and $highCount with high-risk cross-environment privileges. These accounts pose extreme risk!"
        }
        else {
            $score = 25  # Only high-risk findings
            $message = "WARNING: Found $highCount accounts with privileged access in both cloud and on-premises environments."
        }
    }
    else {
        $message = "No cross-environment privileged account overlap detected. Administrative accounts are properly segregated."
    }
    
    return @{
        CheckId = "EID-T1-002"
        Timestamp = (Get-Date).ToString("o")
        Status = $status
        Score = $score
        Severity = "Critical"
        Category = "PrivilegedAccess"
        Findings = $findings
        Message = $message
        AffectedObjects = $findings.Count
        IgnoredObjects = 0
        Metadata = @{
            TenantId = $TenantId
            Domain = $DomainName
            ExecutionTime = [Math]::Round($executionTime, 2)
            EntraPrivilegedUsers = $entraPrivilegedUsers.Count
            ADPrivilegedUsers = $adPrivilegedUsers.Count
            OverlappingAccounts = $findings.Count
            CheckedEntraRoles = $privilegedEntraRoles.Count
            CheckedADGroups = $privilegedADGroups.Count
        }
    }
}
catch {
    return @{
        CheckId = "EID-T1-002"
        Timestamp = (Get-Date).ToString("o")
        Status = "Error"
        Score = 0
        Severity = "Critical"
        Category = "PrivilegedAccess"
        Findings = @()
        Message = "Error analyzing cross-environment privileges: $_"
        AffectedObjects = 0
        IgnoredObjects = 0
        Metadata = @{
            TenantId = $TenantId
            Domain = $DomainName
            ExecutionTime = 0.0
            ErrorDetails = $_.Exception.Message
        }
    }
}