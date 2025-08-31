<#
.SYNOPSIS
Detects directory synchronization errors between on-premises Active Directory and Entra ID

.METADATA
{
  "id": "EID-T4-006",
  "name": "Directory Synchronization Errors Present",
  "description": "Directory synchronization between on-premises Active Directory and Entra ID is experiencing errors. Sync errors can lead to authentication failures, inconsistent security policies, and users being unable to access cloud resources. Common issues include duplicate attributes, validation errors, and connectivity problems.",
  "category": "Synchronization",
  "severity": "Low",
  "weight": 4,
  "impact": 4,
  "frameworks": ["MITRE", "NIST"],
  "targets": ["EntraID"]
}
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$TenantId,
    
    [Parameter(Mandatory=$false)]
    [int]$ErrorThreshold = 10,  # Number of errors to consider problematic
    
    [Parameter(Mandatory=$false)]
    [int]$HoursToCheck = 24  # Look back period for sync errors
)

try {
    $startTime = Get-Date
    $findings = @()
    
    # Check if Microsoft.Graph module is available
    $graphModuleAvailable = $null -ne (Get-Module -ListAvailable -Name Microsoft.Graph)
    
    if ($graphModuleAvailable) {
        # Import required modules
        Import-Module Microsoft.Graph.Identity.DirectoryManagement -ErrorAction SilentlyContinue
        Import-Module Microsoft.Graph.Reports -ErrorAction SilentlyContinue
        Import-Module Microsoft.Graph.Users -ErrorAction SilentlyContinue
        
        # Check if already connected
        $context = Get-MgContext -ErrorAction SilentlyContinue
        
        if (-not $context) {
            # Need to connect - for automated scenarios, this would need pre-configured auth
            throw "Not connected to Microsoft Graph. Please run Connect-MgGraph first with appropriate permissions (Directory.Read.All, AuditLog.Read.All, Reports.Read.All)"
        }
        
        # Use provided TenantId or get from context
        if (-not $TenantId) {
            $TenantId = $context.TenantId
        }
        
        # Check if hybrid environment (sync enabled)
        $isHybridEnvironment = $false
        $syncEnabled = $false
        $lastSyncTime = $null
        $syncInterval = $null
        
        $organization = Get-MgOrganization -ErrorAction SilentlyContinue
        if ($organization) {
            $syncEnabled = $organization.OnPremisesSyncEnabled -eq $true
            $isHybridEnvironment = $syncEnabled
            $lastSyncTime = $organization.OnPremisesLastSyncDateTime
            
            # Calculate sync interval if we have last sync time
            if ($lastSyncTime) {
                $timeSinceLastSync = (Get-Date) - $lastSyncTime
                $syncInterval = $timeSinceLastSync.TotalMinutes
            }
        }
        
        if (-not $isHybridEnvironment) {
            # Not a hybrid environment, no sync errors to check
            $message = "Directory synchronization is not configured. This is a cloud-only environment."
            
            return @{
                CheckId = "EID-T4-006"
                Timestamp = (Get-Date).ToString("o")
                Status = "Success"
                Score = 100
                Severity = "Low"
                Category = "Synchronization"
                Findings = @()
                Message = $message
                AffectedObjects = 0
                IgnoredObjects = 0
                Metadata = @{
                    TenantId = $TenantId
                    ExecutionTime = [Math]::Round(((Get-Date) - $startTime).TotalSeconds, 2)
                    IsHybridEnvironment = $false
                    SyncEnabled = $false
                }
            }
        }
        
        # Get sync error information
        $syncErrors = @()
        $userSyncErrors = @()
        $groupSyncErrors = @()
        $contactSyncErrors = @()
        $deviceSyncErrors = @()
        
        # Check for users with sync errors
        try {
            # Get users with onPremisesProvisioningErrors
            $usersWithErrors = Get-MgUser -Filter "onPremisesProvisioningErrors/any()" -Property "id,userPrincipalName,displayName,onPremisesProvisioningErrors,onPremisesSyncEnabled" -All -ErrorAction SilentlyContinue
            
            if ($usersWithErrors) {
                foreach ($user in $usersWithErrors) {
                    if ($user.OnPremisesProvisioningErrors) {
                        foreach ($error in $user.OnPremisesProvisioningErrors) {
                            $userSyncErrors += @{
                                ObjectType = "User"
                                ObjectName = $user.UserPrincipalName
                                ErrorCategory = $error.Category
                                ErrorCode = $error.ErrorCode
                                ErrorDescription = $error.Value
                                OccurredDateTime = $error.OccurredDateTime
                            }
                        }
                    }
                }
            }
        }
        catch {
            Write-Verbose "Could not retrieve user sync errors: $_"
        }
        
        # Check for groups with sync errors
        try {
            $groupsWithErrors = Get-MgGroup -Filter "onPremisesProvisioningErrors/any()" -Property "id,displayName,onPremisesProvisioningErrors" -All -ErrorAction SilentlyContinue
            
            if ($groupsWithErrors) {
                foreach ($group in $groupsWithErrors) {
                    if ($group.OnPremisesProvisioningErrors) {
                        foreach ($error in $group.OnPremisesProvisioningErrors) {
                            $groupSyncErrors += @{
                                ObjectType = "Group"
                                ObjectName = $group.DisplayName
                                ErrorCategory = $error.Category
                                ErrorCode = $error.ErrorCode
                                ErrorDescription = $error.Value
                                OccurredDateTime = $error.OccurredDateTime
                            }
                        }
                    }
                }
            }
        }
        catch {
            Write-Verbose "Could not retrieve group sync errors: $_"
        }
        
        # Combine all sync errors
        $syncErrors = $userSyncErrors + $groupSyncErrors + $contactSyncErrors + $deviceSyncErrors
        
        # Group errors by type for analysis
        $errorsByCategory = @{}
        $errorsByCode = @{}
        $recentErrors = @()
        
        $cutoffTime = (Get-Date).AddHours(-$HoursToCheck)
        
        foreach ($error in $syncErrors) {
            # Group by category
            if (-not $errorsByCategory.ContainsKey($error.ErrorCategory)) {
                $errorsByCategory[$error.ErrorCategory] = @()
            }
            $errorsByCategory[$error.ErrorCategory] += $error
            
            # Group by error code
            if (-not $errorsByCode.ContainsKey($error.ErrorCode)) {
                $errorsByCode[$error.ErrorCode] = @()
            }
            $errorsByCode[$error.ErrorCode] += $error
            
            # Check if recent
            if ($error.OccurredDateTime -and $error.OccurredDateTime -gt $cutoffTime) {
                $recentErrors += $error
            }
        }
        
        # Check directory sync statistics via audit logs if available
        try {
            $syncAuditLogs = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/auditLogs/directoryAudits?`$filter=category eq 'Synchronization'" -ErrorAction SilentlyContinue
            
            if ($syncAuditLogs -and $syncAuditLogs.value) {
                # Analyze sync audit events for errors
                foreach ($log in $syncAuditLogs.value) {
                    if ($log.result -eq "failure" -and $log.activityDateTime -gt $cutoffTime) {
                        # Additional sync errors from audit logs
                    }
                }
            }
        }
        catch {
            Write-Verbose "Could not retrieve sync audit logs: $_"
        }
        
        # Finding 1: Active sync errors present
        if ($syncErrors.Count -gt 0) {
            $findings += @{
                ObjectName = "Directory Synchronization Errors"
                ObjectType = "SyncStatus"
                RiskLevel = "Low"
                Description = "Found $($syncErrors.Count) directory synchronization error(s) affecting $($userSyncErrors.Count) user(s) and $($groupSyncErrors.Count) group(s). These errors prevent proper synchronization between on-premises AD and Entra ID."
                Remediation = "1. Review Azure AD Connect Health portal for detailed error information. " +
                             "2. Common fixes for sync errors: " +
                             "   - Duplicate attribute values (UPN, ProxyAddress, Mail) " +
                             "   - Invalid characters in attributes " +
                             "   - Exceeding attribute length limits " +
                             "   - License assignment issues " +
                             "3. Run Azure AD Connect sync cycle after fixes. " +
                             "4. Use IdFix tool to identify and fix on-premises issues. " +
                             "5. Check Azure AD Connect server connectivity and credentials. " +
                             "6. Ensure sufficient licenses for synced users. " +
                             "7. Monitor sync status after remediation."
                AffectedAttributes = @("onPremisesProvisioningErrors", "syncStatus")
            }
        }
        
        # Finding 2: Sync interval too long
        if ($syncInterval -and $syncInterval -gt 180) {  # More than 3 hours
            $findings += @{
                ObjectName = "Sync Interval"
                ObjectType = "Configuration"
                RiskLevel = "Low"
                Description = "Last directory synchronization was $([Math]::Round($syncInterval/60, 1)) hours ago. Default sync interval is 30 minutes. Extended intervals may indicate sync service issues or configuration problems."
                Remediation = "1. Check Azure AD Connect service status on sync server. " +
                             "2. Verify scheduled task for sync is running. " +
                             "3. Review sync server event logs for errors. " +
                             "4. Check network connectivity to Azure AD. " +
                             "5. Manually trigger sync cycle for testing: " +
                             "   Start-ADSyncSyncCycle -PolicyType Delta " +
                             "6. Ensure sync server meets system requirements. " +
                             "7. Consider upgrading Azure AD Connect if outdated."
                AffectedAttributes = @("lastSyncDateTime", "syncInterval")
            }
        }
        
        # Finding 3: Duplicate attribute errors
        $duplicateErrors = @($syncErrors | Where-Object { $_.ErrorCode -match "Duplicate" -or $_.ErrorDescription -match "duplicate|already exists" })
        if ($duplicateErrors.Count -gt 0) {
            $exampleDuplicates = $duplicateErrors | Select-Object -First 3
            $findings += @{
                ObjectName = "Duplicate Attribute Errors"
                ObjectType = "ValidationError"
                RiskLevel = "Low"
                Description = "Found $($duplicateErrors.Count) duplicate attribute error(s). Common duplicates include UserPrincipalName, ProxyAddresses, and Mail attributes. These prevent objects from syncing to cloud."
                Remediation = "1. Use IdFix tool to scan for duplicate attributes. " +
                             "2. Common duplicate resolution steps: " +
                             "   - Check for duplicate UPNs across forests " +
                             "   - Remove duplicate proxy addresses " +
                             "   - Ensure mail attributes are unique " +
                             "3. For soft-deleted objects causing duplicates: " +
                             "   - Permanently delete from Azure AD Recycle Bin " +
                             "   - Wait for deletion to replicate " +
                             "4. Update on-premises AD attributes to be unique. " +
                             "5. Force sync after fixing duplicates."
                AffectedAttributes = @("userPrincipalName", "proxyAddresses", "mail")
            }
        }
        
        # Finding 4: Validation errors
        $validationErrors = @($syncErrors | Where-Object { $_.ErrorCategory -eq "ValidationError" -or $_.ErrorCode -match "Validation" })
        if ($validationErrors.Count -gt 0) {
            $findings += @{
                ObjectName = "Attribute Validation Errors"
                ObjectType = "ValidationError"
                RiskLevel = "Low"
                Description = "Found $($validationErrors.Count) attribute validation error(s). These occur when on-premises attributes don't meet Azure AD requirements for format, length, or character sets."
                Remediation = "1. Common validation issues and fixes: " +
                             "   - Remove invalid characters (@, #, $, %, &) from names " +
                             "   - Ensure UPNs follow email format (user@domain.com) " +
                             "   - Check attribute length limits (e.g., 256 chars for UPN) " +
                             "   - Fix phone number formats (+1-555-1234) " +
                             "2. Use IdFix to identify validation issues. " +
                             "3. Update on-premises AD schema if needed. " +
                             "4. Configure attribute filtering if problematic attributes aren't needed. " +
                             "5. Test with small batch before full sync."
                AffectedAttributes = @("attributeValidation", "characterSets")
            }
        }
        
        # Finding 5: Large number of recent errors
        if ($recentErrors.Count -gt $ErrorThreshold) {
            $findings += @{
                ObjectName = "Recent Sync Error Surge"
                ObjectType = "TrendAnalysis"
                RiskLevel = "Low"
                Description = "$($recentErrors.Count) synchronization errors occurred in the last $HoursToCheck hours, exceeding threshold of $ErrorThreshold. This spike may indicate a systemic issue affecting directory synchronization."
                Remediation = "1. Check for recent changes: " +
                             "   - Azure AD Connect configuration updates " +
                             "   - On-premises AD schema modifications " +
                             "   - Network or firewall changes " +
                             "   - Certificate expirations " +
                             "2. Review Azure AD Connect Health alerts. " +
                             "3. Verify sync service account permissions. " +
                             "4. Check for mass user/group modifications. " +
                             "5. Consider rolling back recent changes. " +
                             "6. Open support ticket if issue persists."
                AffectedAttributes = @("errorTrend", "recentErrors")
            }
        }
        
        # Finding 6: Specific error patterns
        foreach ($errorCode in $errorsByCode.Keys) {
            $count = $errorsByCode[$errorCode].Count
            
            # Check for known problematic error codes
            switch -Wildcard ($errorCode) {
                "*FederatedDomain*" {
                    if ($count -gt 5) {
                        $findings += @{
                            ObjectName = "Federated Domain Sync Errors"
                            ObjectType = "FederationError"
                            RiskLevel = "Low"
                            Description = "$count objects have federated domain errors. Users with federated domains cannot have passwords synced and may have authentication issues."
                            Remediation = "1. Verify federation configuration is correct. " +
                                         "2. Check if affected users should be cloud-only. " +
                                         "3. Update UPN to managed domain if appropriate. " +
                                         "4. Ensure federation service is accessible. " +
                                         "5. Review ADFS or other IdP configuration."
                            AffectedAttributes = @("federatedDomain", "authentication")
                        }
                    }
                }
                "*License*" {
                    if ($count -gt 10) {
                        $findings += @{
                            ObjectName = "License Assignment Errors"
                            ObjectType = "LicenseError"
                            RiskLevel = "Low"
                            Description = "$count objects have license-related sync errors. This may prevent users from accessing licensed services."
                            Remediation = "1. Verify sufficient licenses are available. " +
                                         "2. Check group-based licensing configuration. " +
                                         "3. Remove conflicting direct license assignments. " +
                                         "4. Ensure usage location is set for users. " +
                                         "5. Review license dependency requirements."
                            AffectedAttributes = @("licenses", "usageLocation")
                        }
                    }
                }
                "*Quota*" {
                    if ($count -gt 0) {
                        $findings += @{
                            ObjectName = "Directory Quota Exceeded"
                            ObjectType = "QuotaError"
                            RiskLevel = "Low"
                            Description = "$count objects cannot sync due to directory quota limits being exceeded."
                            Remediation = "1. Check current directory object count vs. limits. " +
                                         "2. Remove unnecessary objects from sync scope. " +
                                         "3. Clean up deleted objects in recycle bin. " +
                                         "4. Consider upgrading Azure AD edition for higher limits. " +
                                         "5. Implement OU filtering to reduce sync scope."
                            AffectedAttributes = @("directoryQuota", "objectCount")
                        }
                    }
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
    $message = "Directory synchronization analysis completed successfully."
    
    if ($findings.Count -gt 0) {
        # Adjust score based on number and types of errors
        if ($syncErrors.Count -gt 100) {
            $score = 50  # Many errors
        }
        elseif ($syncErrors.Count -gt 50) {
            $score = 60  # Moderate errors
        }
        elseif ($syncErrors.Count -gt 10) {
            $score = 70  # Some errors
        }
        else {
            $score = 75  # Few errors
        }
        
        $message = "Found $($findings.Count) synchronization issue(s) affecting $($syncErrors.Count) object(s). Directory sync health requires attention."
    }
    else {
        if ($isHybridEnvironment) {
            $message = "Directory synchronization is operating normally with no errors detected."
        }
        else {
            $message = "Directory synchronization is not configured (cloud-only environment)."
        }
    }
    
    return @{
        CheckId = "EID-T4-006"
        Timestamp = (Get-Date).ToString("o")
        Status = $status
        Score = $score
        Severity = "Low"
        Category = "Synchronization"
        Findings = $findings
        Message = $message
        AffectedObjects = $syncErrors.Count
        IgnoredObjects = 0
        Metadata = @{
            TenantId = $TenantId
            ExecutionTime = [Math]::Round($executionTime, 2)
            IsHybridEnvironment = $isHybridEnvironment
            SyncEnabled = $syncEnabled
            LastSyncTime = if ($lastSyncTime) { $lastSyncTime.ToString("o") } else { $null }
            SyncIntervalMinutes = if ($syncInterval) { [Math]::Round($syncInterval, 1) } else { $null }
            TotalSyncErrors = $syncErrors.Count
            UserSyncErrors = $userSyncErrors.Count
            GroupSyncErrors = $groupSyncErrors.Count
            RecentErrorCount = $recentErrors.Count
        }
    }
}
catch {
    return @{
        CheckId = "EID-T4-006"
        Timestamp = (Get-Date).ToString("o")
        Status = "Error"
        Score = 0
        Severity = "Low"
        Category = "Synchronization"
        Findings = @()
        Message = "Error analyzing directory synchronization status: $_"
        AffectedObjects = 0
        IgnoredObjects = 0
        Metadata = @{
            TenantId = $TenantId
            ExecutionTime = 0.0
            ErrorDetails = $_.Exception.Message
        }
    }
}