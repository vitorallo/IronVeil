<#
.SYNOPSIS
Detects risky API permissions granted to applications in Entra ID

.METADATA
{
  "id": "EID-T1-001",
  "name": "Risky API Permissions Granted to Applications",
  "description": "Applications with excessive permissions like RoleManagement.ReadWrite.Directory, Application.ReadWrite.All, or Directory.ReadWrite.All can escalate to Global Administrator privileges or access all tenant data. This check identifies applications with high-risk Microsoft Graph API permissions.",
  "category": "PrivilegedAccess",
  "severity": "Critical",
  "weight": 10,
  "impact": 10,
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
    
    # High-risk permissions that could lead to privilege escalation or data exposure
    $criticalPermissions = @(
        "RoleManagement.ReadWrite.Directory",      # Can grant itself Global Admin
        "AppRoleAssignment.ReadWrite.All",         # Can grant itself any permission
        "Application.ReadWrite.All",               # Can modify any application
        "Directory.ReadWrite.All",                 # Can modify any directory object
        "RoleManagement.ReadWrite.CloudPC",        # Can manage cloud PC roles
        "EntitlementManagement.ReadWrite.All",     # Can manage access packages
        "PrivilegedAccess.ReadWrite.AzureAD",      # Can manage privileged access
        "PrivilegedAccess.ReadWrite.AzureResources" # Can manage Azure resource privileges
    )
    
    $highRiskPermissions = @(
        "User.ReadWrite.All",                      # Can modify any user
        "Group.ReadWrite.All",                     # Can modify any group
        "GroupMember.ReadWrite.All",               # Can modify group memberships
        "Domain.ReadWrite.All",                    # Can modify domain settings
        "Policy.ReadWrite.ApplicationConfiguration", # Can modify app policies
        "Policy.ReadWrite.ConditionalAccess",      # Can modify conditional access
        "AuditLog.Read.All",                       # Can read all audit logs
        "Directory.AccessAsUser.All",              # Can impersonate users
        "Mail.ReadWrite",                          # Can read/write all mailboxes
        "Files.ReadWrite.All",                     # Can read/write all files
        "Sites.FullControl.All",                   # Full SharePoint control
        "DeviceManagementConfiguration.ReadWrite.All", # Can manage device configs
        "DeviceManagementManagedDevices.ReadWrite.All" # Can manage devices
    )
    
    # Check if Microsoft.Graph module is available
    $graphModuleAvailable = $null -ne (Get-Module -ListAvailable -Name Microsoft.Graph)
    
    if ($graphModuleAvailable) {
        # Import required modules
        Import-Module Microsoft.Graph.Applications -ErrorAction SilentlyContinue
        Import-Module Microsoft.Graph.Identity.DirectoryManagement -ErrorAction SilentlyContinue
        
        # Check if already connected
        $context = Get-MgContext -ErrorAction SilentlyContinue
        
        if (-not $context) {
            # Need to connect - for automated scenarios, this would need pre-configured auth
            throw "Not connected to Microsoft Graph. Please run Connect-MgGraph first with appropriate permissions (Application.Read.All, Directory.Read.All)"
        }
        
        # Use provided TenantId or get from context
        if (-not $TenantId) {
            $TenantId = $context.TenantId
        }
        
        # Get all application registrations
        $applications = Get-MgApplication -All -Property Id,DisplayName,AppId,RequiredResourceAccess,CreatedDateTime
        
        # Get all service principals (enterprise applications)
        $servicePrincipals = Get-MgServicePrincipal -All -Property Id,DisplayName,AppId,AppRoles,OAuth2PermissionScopes,AppRoleAssignedTo
        
        # Create a hashtable for quick SP lookup
        $spLookup = @{}
        foreach ($sp in $servicePrincipals) {
            $spLookup[$sp.AppId] = $sp
        }
        
        # Analyze each application
        foreach ($app in $applications) {
            $appRisks = @()
            $riskLevel = "Low"
            $riskyPermissions = @()
            
            # Check required resource access (configured permissions)
            foreach ($resource in $app.RequiredResourceAccess) {
                # Microsoft Graph API ID
                if ($resource.ResourceAppId -eq "00000003-0000-0000-c000-000000000000") {
                    foreach ($permission in $resource.ResourceAccess) {
                        # Get the actual permission name from the service principal
                        $graphSP = $servicePrincipals | Where-Object { $_.AppId -eq "00000003-0000-0000-c000-000000000000" } | Select-Object -First 1
                        
                        if ($graphSP) {
                            # Check if it's an application permission (not delegated)
                            if ($permission.Type -eq "Role") {
                                $permissionDetails = $graphSP.AppRoles | Where-Object { $_.Id -eq $permission.Id }
                                if ($permissionDetails) {
                                    $permissionName = $permissionDetails.Value
                                    
                                    # Check against critical permissions
                                    if ($criticalPermissions -contains $permissionName) {
                                        $riskLevel = "Critical"
                                        $riskyPermissions += $permissionName
                                        $appRisks += "Critical permission: $permissionName (can lead to full tenant compromise)"
                                    }
                                    # Check against high-risk permissions
                                    elseif ($highRiskPermissions -contains $permissionName) {
                                        if ($riskLevel -ne "Critical") {
                                            $riskLevel = "High"
                                        }
                                        $riskyPermissions += $permissionName
                                        $appRisks += "High-risk permission: $permissionName"
                                    }
                                }
                            }
                        }
                    }
                }
            }
            
            # Check if the app has actual consent (granted permissions)
            if ($spLookup.ContainsKey($app.AppId)) {
                $sp = $spLookup[$app.AppId]
                
                # Get app role assignments (actual granted permissions)
                try {
                    $assignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id
                    
                    foreach ($assignment in $assignments) {
                        # Get the permission details
                        $resourceSP = Get-MgServicePrincipal -ServicePrincipalId $assignment.ResourceId -ErrorAction SilentlyContinue
                        if ($resourceSP -and $resourceSP.AppId -eq "00000003-0000-0000-c000-000000000000") {
                            $permission = $resourceSP.AppRoles | Where-Object { $_.Id -eq $assignment.AppRoleId }
                            if ($permission) {
                                $permissionName = $permission.Value
                                
                                # Check if this is a risky permission that wasn't in RequiredResourceAccess
                                if (($criticalPermissions -contains $permissionName -or $highRiskPermissions -contains $permissionName) -and 
                                    $riskyPermissions -notcontains $permissionName) {
                                    $riskyPermissions += $permissionName
                                    $appRisks += "Granted permission: $permissionName"
                                    
                                    if ($criticalPermissions -contains $permissionName) {
                                        $riskLevel = "Critical"
                                    }
                                    elseif ($riskLevel -ne "Critical") {
                                        $riskLevel = "High"
                                    }
                                }
                            }
                        }
                    }
                }
                catch {
                    # Unable to get app role assignments, continue
                }
            }
            
            # If risky permissions found, add to findings
            if ($riskyPermissions.Count -gt 0) {
                $daysSinceCreation = (Get-Date) - $app.CreatedDateTime
                
                # Build remediation based on risk level
                $remediation = if ($riskLevel -eq "Critical") {
                    "1. IMMEDIATE ACTION REQUIRED: This application has permissions that could compromise the entire tenant. " +
                    "2. Review if this application is legitimate and required. " +
                    "3. If legitimate, implement strict conditional access policies. " +
                    "4. Consider removing permissions: $($riskyPermissions -join ', '). " +
                    "5. Enable continuous access evaluation. " +
                    "6. Audit all activities performed by this application. " +
                    "7. Implement principle of least privilege."
                }
                else {
                    "1. Review if all granted permissions are necessary. " +
                    "2. Consider removing excessive permissions: $($riskyPermissions -join ', '). " +
                    "3. Implement conditional access policies for this application. " +
                    "4. Enable audit logging for this application's activities. " +
                    "5. Regular review of application permissions (quarterly)."
                }
                
                $findings += @{
                    ObjectName = $app.DisplayName
                    ObjectType = "Application"
                    RiskLevel = $riskLevel
                    Description = "Application has dangerous API permissions. $($appRisks -join '. '). Created $([int]$daysSinceCreation.Days) days ago."
                    Remediation = $remediation
                    AffectedAttributes = @("RequiredResourceAccess", "AppRoleAssignments", "OAuth2Permissions")
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
    $message = "Application permission analysis completed successfully."
    
    if ($findings.Count -gt 0) {
        $criticalCount = @($findings | Where-Object { $_.RiskLevel -eq "Critical" }).Count
        $highCount = @($findings | Where-Object { $_.RiskLevel -eq "High" }).Count
        
        if ($criticalCount -gt 0) {
            $score = 0  # Critical findings mean score of 0
            $message = "CRITICAL: Found $criticalCount applications with permissions that could lead to full tenant compromise and $highCount with high-risk permissions. Immediate review required!"
        }
        else {
            $score = 25  # Only high-risk findings
            $message = "WARNING: Found $highCount applications with high-risk permissions requiring review."
        }
    }
    else {
        $message = "No applications with risky API permissions detected. Application permissions appear properly configured."
    }
    
    return @{
        CheckId = "EID-T1-001"
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
            ExecutionTime = [Math]::Round($executionTime, 2)
            TotalApplications = $applications.Count
            TotalServicePrincipals = $servicePrincipals.Count
            CriticalPermissionsChecked = $criticalPermissions.Count
            HighRiskPermissionsChecked = $highRiskPermissions.Count
        }
    }
}
catch {
    return @{
        CheckId = "EID-T1-001"
        Timestamp = (Get-Date).ToString("o")
        Status = "Error"
        Score = 0
        Severity = "Critical"
        Category = "PrivilegedAccess"
        Findings = @()
        Message = "Error analyzing application permissions: $_"
        AffectedObjects = 0
        IgnoredObjects = 0
        Metadata = @{
            TenantId = $TenantId
            ExecutionTime = 0.0
            ErrorDetails = $_.Exception.Message
        }
    }
}