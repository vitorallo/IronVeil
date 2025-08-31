<#
.SYNOPSIS
Detects if Administrative Units are not being used in Entra ID for granular delegation

.METADATA
{
  "id": "EID-T3-001",
  "name": "Administrative Units Not Being Used",
  "description": "Administrative Units (AUs) allow for granular delegation of administrative tasks within Entra ID. Without AUs, organizations often resort to granting broader, less secure permissions. This check assesses the presence and proper configuration of Administrative Units in large or complex Entra ID environments.",
  "category": "Authorization",
  "severity": "Medium",
  "weight": 5,
  "impact": 6,
  "frameworks": ["MITRE", "NIST"],
  "targets": ["EntraID"]
}
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$TenantId,
    
    [Parameter(Mandatory=$false)]
    [int]$MinimumUserThreshold = 500  # Threshold for when AUs should be used
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
        Import-Module Microsoft.Graph.Groups -ErrorAction SilentlyContinue
        
        # Check if already connected
        $context = Get-MgContext -ErrorAction SilentlyContinue
        
        if (-not $context) {
            # Need to connect - for automated scenarios, this would need pre-configured auth
            throw "Not connected to Microsoft Graph. Please run Connect-MgGraph first with appropriate permissions (Directory.Read.All, AdministrativeUnit.Read.All)"
        }
        
        # Use provided TenantId or get from context
        if (-not $TenantId) {
            $TenantId = $context.TenantId
        }
        
        # Get tenant size information
        $totalUsers = (Get-MgUser -All -CountVariable UserCount -ConsistencyLevel eventual).Count
        $totalGroups = (Get-MgGroup -All -CountVariable GroupCount -ConsistencyLevel eventual).Count
        
        # Get all Administrative Units
        $adminUnits = Get-MgDirectoryAdministrativeUnit -All -ErrorAction SilentlyContinue
        $auCount = if ($adminUnits) { @($adminUnits).Count } else { 0 }
        
        # Analyze AU usage
        $auWithMembers = 0
        $auWithScopedAdmins = 0
        $totalAuMembers = 0
        $auDetails = @()
        
        if ($auCount -gt 0) {
            foreach ($au in $adminUnits) {
                # Get members of the AU
                $members = Get-MgDirectoryAdministrativeUnitMember -AdministrativeUnitId $au.Id -All -ErrorAction SilentlyContinue
                $memberCount = if ($members) { @($members).Count } else { 0 }
                $totalAuMembers += $memberCount
                
                if ($memberCount -gt 0) {
                    $auWithMembers++
                }
                
                # Check for scoped role assignments
                $scopedRoles = Get-MgDirectoryAdministrativeUnitScopedRoleMember -AdministrativeUnitId $au.Id -All -ErrorAction SilentlyContinue
                $scopedRoleCount = if ($scopedRoles) { @($scopedRoles).Count } else { 0 }
                
                if ($scopedRoleCount -gt 0) {
                    $auWithScopedAdmins++
                }
                
                $auDetails += @{
                    Name = $au.DisplayName
                    Id = $au.Id
                    MemberCount = $memberCount
                    ScopedRoleCount = $scopedRoleCount
                    Visibility = $au.Visibility
                    Description = $au.Description
                }
            }
        }
        
        # Determine if AUs should be used based on tenant size and complexity
        $shouldUseAUs = ($totalUsers -ge $MinimumUserThreshold) -or ($totalGroups -ge 100)
        
        # Calculate AU coverage percentage
        $auCoverage = if ($totalUsers -gt 0) { [Math]::Round(($totalAuMembers / $totalUsers) * 100, 2) } else { 0 }
        
        # Finding 1: No Administrative Units configured
        if ($auCount -eq 0 -and $shouldUseAUs) {
            $findings += @{
                ObjectName = "Tenant Configuration"
                ObjectType = "TenantSettings"
                RiskLevel = "Medium"
                Description = "No Administrative Units are configured in this tenant with $totalUsers users and $totalGroups groups. For organizations of this size, Administrative Units provide essential delegation boundaries and security isolation."
                Remediation = "1. Design an Administrative Unit strategy based on organizational structure (departments, regions, or business units). " +
                             "2. Create Administrative Units for different administrative boundaries. " +
                             "3. Assign users and groups to appropriate Administrative Units. " +
                             "4. Delegate scoped administrative roles within each AU. " +
                             "5. Document the AU structure and delegation model. " +
                             "6. Train administrators on scoped role assignments. " +
                             "7. Regularly review and audit AU membership and permissions."
                AffectedAttributes = @("AdministrativeUnits", "ScopedRoleAssignments")
            }
        }
        # Finding 2: AUs exist but are not properly utilized
        elseif ($auCount -gt 0 -and $auWithMembers -eq 0) {
            $findings += @{
                ObjectName = "Administrative Unit Configuration"
                ObjectType = "AdministrativeUnit"
                RiskLevel = "Medium"
                Description = "$auCount Administrative Unit(s) exist but none have any members assigned. These empty AUs provide no security benefit and indicate incomplete implementation."
                Remediation = "1. Review existing Administrative Units and their intended purpose. " +
                             "2. Assign appropriate users and groups to each AU based on organizational structure. " +
                             "3. Configure scoped role assignments for delegated administration. " +
                             "4. Remove unused Administrative Units to reduce complexity. " +
                             "5. Document the delegation model and train administrators."
                AffectedAttributes = @("Members", "ScopedRoleMembers")
            }
        }
        # Finding 3: AUs have members but no scoped administrators
        elseif ($auCount -gt 0 -and $auWithMembers -gt 0 -and $auWithScopedAdmins -eq 0) {
            $findings += @{
                ObjectName = "Administrative Unit Delegation"
                ObjectType = "AdministrativeUnit"
                RiskLevel = "Medium"
                Description = "$auWithMembers Administrative Unit(s) have members but no scoped role assignments. Without delegated administrators, AUs don't provide the intended security isolation and delegation benefits."
                Remediation = "1. Define administrative responsibilities for each AU. " +
                             "2. Assign scoped administrative roles (User Administrator, Helpdesk Administrator) within AUs. " +
                             "3. Remove global administrative permissions where scoped permissions suffice. " +
                             "4. Implement least privilege principle using AU-scoped roles. " +
                             "5. Regularly audit and review scoped role assignments."
                AffectedAttributes = @("ScopedRoleMembers", "RoleAssignments")
            }
        }
        # Finding 4: Low AU coverage in large organization
        elseif ($shouldUseAUs -and $auCoverage -lt 50) {
            $findings += @{
                ObjectName = "Administrative Unit Coverage"
                ObjectType = "TenantMetrics"
                RiskLevel = "Low"
                Description = "Only $auCoverage% of users are managed through Administrative Units in a tenant with $totalUsers users. Low AU coverage means most administrative actions still require global permissions."
                Remediation = "1. Expand Administrative Unit coverage to include all user populations. " +
                             "2. Create AUs for different departments, locations, or business units. " +
                             "3. Migrate users from global scope to appropriate AUs. " +
                             "4. Update delegation model to use AU-scoped roles. " +
                             "5. Set target for 80%+ AU coverage for better security isolation."
                AffectedAttributes = @("UserAssignments", "Coverage")
            }
        }
        
        # Finding 5: Check for proper AU configuration patterns
        foreach ($au in $auDetails) {
            # Check for AUs with too many members (might be too broad)
            if ($au.MemberCount -gt 1000) {
                $findings += @{
                    ObjectName = $au.Name
                    ObjectType = "AdministrativeUnit"
                    RiskLevel = "Low"
                    Description = "Administrative Unit '$($au.Name)' has $($au.MemberCount) members, which may be too broad for effective delegation. Large AUs reduce the security isolation benefit."
                    Remediation = "1. Review if this AU can be split into smaller, more focused units. " +
                                 "2. Consider creating sub-AUs for different departments or teams. " +
                                 "3. Ensure scoped administrators only have necessary permissions. " +
                                 "4. Implement regular access reviews for large AUs."
                    AffectedAttributes = @("MemberCount", "Scope")
                }
            }
            
            # Check for AUs without descriptions (poor documentation)
            if ([string]::IsNullOrWhiteSpace($au.Description)) {
                $findings += @{
                    ObjectName = $au.Name
                    ObjectType = "AdministrativeUnit"
                    RiskLevel = "Low"
                    Description = "Administrative Unit '$($au.Name)' lacks a description, making it difficult to understand its purpose and scope."
                    Remediation = "1. Add a clear description explaining the AU's purpose and scope. " +
                                 "2. Document which users/groups should be members. " +
                                 "3. Specify the delegation model for this AU. " +
                                 "4. Include contact information for AU administrators."
                    AffectedAttributes = @("Description", "Documentation")
                }
            }
        }
        
        # Check for overlapping AU memberships (complexity indicator)
        if ($auCount -gt 1) {
            $userAuMemberships = @{}
            foreach ($au in $adminUnits) {
                $members = Get-MgDirectoryAdministrativeUnitMember -AdministrativeUnitId $au.Id -All -ErrorAction SilentlyContinue
                foreach ($member in $members) {
                    if ($member.AdditionalProperties["@odata.type"] -eq "#microsoft.graph.user") {
                        $userId = $member.Id
                        if (-not $userAuMemberships.ContainsKey($userId)) {
                            $userAuMemberships[$userId] = @()
                        }
                        $userAuMemberships[$userId] += $au.DisplayName
                    }
                }
            }
            
            $multiAuUsers = @($userAuMemberships.GetEnumerator() | Where-Object { $_.Value.Count -gt 1 })
            if ($multiAuUsers.Count -gt 10) {
                $findings += @{
                    ObjectName = "Administrative Unit Overlap"
                    ObjectType = "Configuration"
                    RiskLevel = "Low"
                    Description = "$($multiAuUsers.Count) users are members of multiple Administrative Units, which may indicate complex or overlapping delegation boundaries."
                    Remediation = "1. Review users with multiple AU memberships for necessity. " +
                                 "2. Simplify AU structure to reduce overlap. " +
                                 "3. Document why certain users need multiple AU memberships. " +
                                 "4. Consider restructuring AUs along clearer organizational boundaries."
                    AffectedAttributes = @("MembershipOverlap", "Complexity")
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
    $message = "Administrative Unit analysis completed successfully."
    
    if ($findings.Count -gt 0) {
        $mediumCount = @($findings | Where-Object { $_.RiskLevel -eq "Medium" }).Count
        $lowCount = @($findings | Where-Object { $_.RiskLevel -eq "Low" }).Count
        
        if ($mediumCount -gt 0) {
            $score = 50  # Medium findings
            $message = "Found $mediumCount medium-risk issues with Administrative Unit configuration. Organization is not fully utilizing AUs for delegation and security isolation."
        }
        else {
            $score = 75  # Only low-risk findings
            $message = "Found $lowCount low-risk Administrative Unit configuration improvements."
        }
    }
    else {
        $message = "Administrative Units are properly configured and utilized. Delegation model appears well-structured."
    }
    
    return @{
        CheckId = "EID-T3-001"
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
            TotalUsers = $totalUsers
            TotalGroups = $totalGroups
            AdministrativeUnitCount = $auCount
            AUsWithMembers = $auWithMembers
            AUsWithScopedAdmins = $auWithScopedAdmins
            AUCoveragePercentage = $auCoverage
            ShouldUseAUs = $shouldUseAUs
        }
    }
}
catch {
    return @{
        CheckId = "EID-T3-001"
        Timestamp = (Get-Date).ToString("o")
        Status = "Error"
        Score = 0
        Severity = "Medium"
        Category = "Authorization"
        Findings = @()
        Message = "Error analyzing Administrative Unit configuration: $_"
        AffectedObjects = 0
        IgnoredObjects = 0
        Metadata = @{
            TenantId = $TenantId
            ExecutionTime = 0.0
            ErrorDetails = $_.Exception.Message
        }
    }
}