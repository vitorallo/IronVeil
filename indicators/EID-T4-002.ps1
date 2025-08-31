<#
.SYNOPSIS
Detects if regular users have permissions to create Microsoft 365 groups without administrative oversight

.METADATA
{
  "id": "EID-T4-002",
  "name": "Users Can Create Microsoft 365 Groups",
  "description": "Regular users have permissions to create Microsoft 365 groups without administrative oversight. This can lead to sprawl, naming convention violations, data governance issues, and shadow IT scenarios where sensitive data is shared without proper controls.",
  "category": "Authorization",
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
        Import-Module Microsoft.Graph.Groups -ErrorAction SilentlyContinue
        Import-Module Microsoft.Graph.Beta.Identity.DirectoryManagement -ErrorAction SilentlyContinue
        
        # Check if already connected
        $context = Get-MgContext -ErrorAction SilentlyContinue
        
        if (-not $context) {
            # Need to connect - for automated scenarios, this would need pre-configured auth
            throw "Not connected to Microsoft Graph. Please run Connect-MgGraph first with appropriate permissions (Directory.Read.All, Group.Read.All, Policy.Read.All)"
        }
        
        # Use provided TenantId or get from context
        if (-not $TenantId) {
            $TenantId = $context.TenantId
        }
        
        # Get directory settings for Groups
        $groupSettings = Get-MgDirectorySetting -All -ErrorAction SilentlyContinue | Where-Object { 
            $_.DisplayName -eq "Group.Unified" -or $_.TemplateId -eq "62375ab9-6b52-47ed-826b-58e47e0e304b"
        }
        
        $usersCanCreateGroups = $true  # Default if no settings found
        $enableGroupCreation = $true
        $groupCreationAllowedGroupId = $null
        $allowedGroupName = $null
        
        if ($groupSettings) {
            # Parse the settings values
            foreach ($setting in $groupSettings.Values) {
                if ($setting.Name -eq "EnableGroupCreation") {
                    $enableGroupCreation = [System.Convert]::ToBoolean($setting.Value)
                }
                if ($setting.Name -eq "GroupCreationAllowedGroupId") {
                    $groupCreationAllowedGroupId = $setting.Value
                }
            }
            
            # If EnableGroupCreation is false, no users can create groups
            # If EnableGroupCreation is true and GroupCreationAllowedGroupId is set, only that group can create
            # If EnableGroupCreation is true and GroupCreationAllowedGroupId is empty, all users can create
            
            if (-not $enableGroupCreation) {
                $usersCanCreateGroups = $false
            }
            elseif (![string]::IsNullOrWhiteSpace($groupCreationAllowedGroupId)) {
                $usersCanCreateGroups = $false  # Only specific group can create
                # Get the group name for reporting
                try {
                    $allowedGroup = Get-MgGroup -GroupId $groupCreationAllowedGroupId -Property "displayName" -ErrorAction SilentlyContinue
                    if ($allowedGroup) {
                        $allowedGroupName = $allowedGroup.DisplayName
                    }
                }
                catch {
                    $allowedGroupName = "Unknown Group"
                }
            }
        }
        
        # Get statistics about existing groups
        $allGroups = Get-MgGroup -All -Property "id,displayName,groupTypes,createdDateTime,visibility" -ErrorAction SilentlyContinue
        $m365Groups = @($allGroups | Where-Object { $_.GroupTypes -contains "Unified" })
        $recentGroups = @($m365Groups | Where-Object { 
            $_.CreatedDateTime -and $_.CreatedDateTime -gt (Get-Date).AddDays(-90) 
        })
        
        # Check for naming convention violations (common indicators of unrestricted creation)
        $suspiciousNames = @()
        $namingPatterns = @(
            "test",
            "temp",
            "delete",
            "demo",
            "personal",
            "my ",
            "private"
        )
        
        foreach ($group in $m365Groups) {
            $groupNameLower = $group.DisplayName.ToLower()
            foreach ($pattern in $namingPatterns) {
                if ($groupNameLower -match "^$pattern" -or $groupNameLower -match "\s$pattern") {
                    $suspiciousNames += $group.DisplayName
                    break
                }
            }
        }
        
        # Finding 1: All users can create Microsoft 365 groups
        if ($usersCanCreateGroups -and $enableGroupCreation) {
            $findings += @{
                ObjectName = "Microsoft 365 Group Creation Settings"
                ObjectType = "TenantSettings"
                RiskLevel = "Low"
                Description = "All users in the tenant can create Microsoft 365 groups without restriction. This can lead to group sprawl, naming convention violations, and uncontrolled data sharing. Currently there are $($m365Groups.Count) Microsoft 365 groups, with $($recentGroups.Count) created in the last 90 days."
                Remediation = "1. Navigate to Azure AD > Settings > General > Microsoft 365 Groups. " +
                             "2. Set 'Users can create Microsoft 365 groups in Azure portals' to No. " +
                             "3. Create a security group for users allowed to create groups. " +
                             "4. Configure the GroupCreationAllowedGroupId setting with this group's ID. " +
                             "5. Implement a group naming policy to enforce conventions. " +
                             "6. Consider implementing an approval workflow for group creation. " +
                             "7. Enable group expiration policies to manage lifecycle. " +
                             "8. Train designated users on proper group creation and governance."
                AffectedAttributes = @("EnableGroupCreation", "GroupCreationAllowedGroupId")
            }
        }
        
        # Finding 2: No group creation restrictions configured
        if ($null -eq $groupSettings) {
            $findings += @{
                ObjectName = "Directory Settings Configuration"
                ObjectType = "TenantSettings"
                RiskLevel = "Low"
                Description = "No Microsoft 365 Groups settings template is configured. By default, all users can create groups. Without configured settings, you cannot control group creation, naming policies, or lifecycle management."
                Remediation = "1. Use PowerShell or Graph API to create Group.Unified directory settings. " +
                             "2. Configure EnableGroupCreation and GroupCreationAllowedGroupId settings. " +
                             "3. Implement group naming policies with prefixes/suffixes. " +
                             "4. Set up blocked words list for inappropriate group names. " +
                             "5. Configure group expiration policies (30, 90, or 180 days). " +
                             "6. Enable group creation audit logging for monitoring."
                AffectedAttributes = @("DirectorySettings", "Group.Unified")
            }
        }
        
        # Finding 3: Large number of groups with suspicious names
        if ($suspiciousNames.Count -gt 5) {
            $exampleNames = $suspiciousNames | Select-Object -First 5
            $findings += @{
                ObjectName = "Group Naming Patterns"
                ObjectType = "Groups"
                RiskLevel = "Low"
                Description = "Found $($suspiciousNames.Count) Microsoft 365 groups with names suggesting ad-hoc or test creation (e.g., $(($exampleNames -join ', '))). This indicates lack of governance and possible shadow IT."
                Remediation = "1. Review and clean up test/temporary groups. " +
                             "2. Implement a group naming policy with required prefixes. " +
                             "3. Configure blocked words list for common test names. " +
                             "4. Set up regular reviews of group creation patterns. " +
                             "5. Educate users on proper group naming conventions. " +
                             "6. Consider requiring business justification for group creation."
                AffectedAttributes = @("displayName", "groupTypes")
            }
        }
        
        # Finding 4: Rapid group creation rate
        if ($recentGroups.Count -gt 50) {
            $creationRate = [Math]::Round($recentGroups.Count / 90.0, 2)
            $findings += @{
                ObjectName = "Group Creation Rate"
                ObjectType = "Metrics"
                RiskLevel = "Low"
                Description = "$($recentGroups.Count) Microsoft 365 groups were created in the last 90 days (average $creationRate per day). This high creation rate suggests unrestricted user access and potential group sprawl."
                Remediation = "1. Implement restrictions on who can create groups. " +
                             "2. Set up group expiration policies to manage lifecycle. " +
                             "3. Enable activity reports to monitor group usage. " +
                             "4. Consider implementing an approval workflow. " +
                             "5. Review and archive unused groups regularly. " +
                             "6. Educate users on when to create new groups vs. using existing ones."
                AffectedAttributes = @("createdDateTime", "groupCount")
            }
        }
        
        # Finding 5: Check for public groups if unrestricted creation
        if ($usersCanCreateGroups) {
            $publicGroups = @($m365Groups | Where-Object { $_.Visibility -eq "Public" })
            if ($publicGroups.Count -gt 0) {
                $publicPercentage = [Math]::Round(($publicGroups.Count / [Math]::Max($m365Groups.Count, 1)) * 100, 1)
                
                if ($publicPercentage -gt 30) {
                    $findings += @{
                        ObjectName = "Public Group Exposure"
                        ObjectType = "Groups"
                        RiskLevel = "Low"
                        Description = "$($publicGroups.Count) of $($m365Groups.Count) Microsoft 365 groups ($publicPercentage%) are public. With unrestricted group creation, users may inadvertently share sensitive data in public groups."
                        Remediation = "1. Review public groups for sensitive content. " +
                                     "2. Set default visibility to Private for new groups. " +
                                     "3. Implement data loss prevention (DLP) policies. " +
                                     "4. Configure sensitivity labels for groups. " +
                                     "5. Train users on public vs. private group implications. " +
                                     "6. Regular audit of public group membership and content."
                        AffectedAttributes = @("visibility", "privacy")
                    }
                }
            }
        }
        
        # Finding 6: If only specific group can create, verify it exists and has members
        if (!$usersCanCreateGroups -and ![string]::IsNullOrWhiteSpace($groupCreationAllowedGroupId)) {
            try {
                $allowedGroup = Get-MgGroup -GroupId $groupCreationAllowedGroupId -ErrorAction SilentlyContinue
                if ($allowedGroup) {
                    $members = Get-MgGroupMember -GroupId $groupCreationAllowedGroupId -All -ErrorAction SilentlyContinue
                    $memberCount = if ($members) { @($members).Count } else { 0 }
                    
                    if ($memberCount -eq 0) {
                        $findings += @{
                            ObjectName = $allowedGroup.DisplayName
                            ObjectType = "Group"
                            RiskLevel = "Low"
                            Description = "Group creation is restricted to members of '$($allowedGroup.DisplayName)', but this group has no members. Effectively, no one can create Microsoft 365 groups."
                            Remediation = "1. Add appropriate users to the group creation allowed group. " +
                                         "2. Document who should have group creation privileges. " +
                                         "3. Implement a request process for group creation rights. " +
                                         "4. Regular review of group creation permissions."
                            AffectedAttributes = @("members", "GroupCreationAllowedGroupId")
                        }
                    }
                }
            }
            catch {
                # Group doesn't exist or can't be accessed
                $findings += @{
                    ObjectName = "Group Creation Allowed Group"
                    ObjectType = "Configuration"
                    RiskLevel = "Low"
                    Description = "Group creation is restricted to a specific group (ID: $groupCreationAllowedGroupId) but this group cannot be found or accessed."
                    Remediation = "1. Verify the GroupCreationAllowedGroupId setting is correct. " +
                                 "2. Ensure the specified group exists and is accessible. " +
                                 "3. Update the setting with a valid group ID. " +
                                 "4. Document the group creation governance model."
                    AffectedAttributes = @("GroupCreationAllowedGroupId")
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
    $message = "Microsoft 365 group creation settings analysis completed successfully."
    
    if ($findings.Count -gt 0) {
        $score = 75  # Low-risk findings
        $message = "Found $($findings.Count) configuration issues with Microsoft 365 group creation settings that should be reviewed."
    }
    else {
        $message = "Microsoft 365 group creation is properly restricted and governed. No issues found."
    }
    
    return @{
        CheckId = "EID-T4-002"
        Timestamp = (Get-Date).ToString("o")
        Status = $status
        Score = $score
        Severity = "Low"
        Category = "Authorization"
        Findings = $findings
        Message = $message
        AffectedObjects = $findings.Count
        IgnoredObjects = 0
        Metadata = @{
            TenantId = $TenantId
            ExecutionTime = [Math]::Round($executionTime, 2)
            UsersCanCreateGroups = $usersCanCreateGroups
            TotalM365Groups = $m365Groups.Count
            RecentGroupsCreated = $recentGroups.Count
            GroupsWithSuspiciousNames = $suspiciousNames.Count
        }
    }
}
catch {
    return @{
        CheckId = "EID-T4-002"
        Timestamp = (Get-Date).ToString("o")
        Status = "Error"
        Score = 0
        Severity = "Low"
        Category = "Authorization"
        Findings = @()
        Message = "Error analyzing Microsoft 365 group creation settings: $_"
        AffectedObjects = 0
        IgnoredObjects = 0
        Metadata = @{
            TenantId = $TenantId
            ExecutionTime = 0.0
            ErrorDetails = $_.Exception.Message
        }
    }
}