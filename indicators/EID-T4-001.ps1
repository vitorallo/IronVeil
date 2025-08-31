<#
.SYNOPSIS
Detects if the default Global Administrator account created during tenant setup is still active

.METADATA
{
  "id": "EID-T4-001",
  "name": "Default Global Administrator Account Still Active",
  "description": "The initial Global Administrator account created during tenant setup remains active and may not follow organizational naming conventions or security practices. This account often has a generic name, may lack MFA, and represents a known target for attackers.",
  "category": "PrivilegedAccess",
  "severity": "Low",
  "weight": 3,
  "impact": 4,
  "frameworks": ["MITRE", "NIST"],
  "targets": ["EntraID"]
}
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$TenantId,
    
    [Parameter(Mandatory=$false)]
    [int]$AccountAgeThresholdDays = 30  # Accounts older than this are considered original
)

try {
    $startTime = Get-Date
    $findings = @()
    
    # Check if Microsoft.Graph module is available
    $graphModuleAvailable = $null -ne (Get-Module -ListAvailable -Name Microsoft.Graph)
    
    if ($graphModuleAvailable) {
        # Import required modules
        Import-Module Microsoft.Graph.Users -ErrorAction SilentlyContinue
        Import-Module Microsoft.Graph.Identity.DirectoryManagement -ErrorAction SilentlyContinue
        
        # Check if already connected
        $context = Get-MgContext -ErrorAction SilentlyContinue
        
        if (-not $context) {
            # Need to connect - for automated scenarios, this would need pre-configured auth
            throw "Not connected to Microsoft Graph. Please run Connect-MgGraph first with appropriate permissions (User.Read.All, Directory.Read.All, RoleManagement.Read.Directory)"
        }
        
        # Use provided TenantId or get from context
        if (-not $TenantId) {
            $TenantId = $context.TenantId
        }
        
        # Get all Global Administrators
        $globalAdminRoleId = "62e90394-69f5-4237-9190-012177145e10"  # Well-known ID for Global Administrator
        $globalAdmins = Get-MgDirectoryRoleMember -DirectoryRoleId $globalAdminRoleId -All -ErrorAction SilentlyContinue
        
        if ($globalAdmins) {
            $oldestAdminAccount = $null
            $oldestCreatedDate = Get-Date
            $suspiciousAdmins = @()
            
            foreach ($admin in $globalAdmins) {
                # Get full user details
                $user = Get-MgUser -UserId $admin.Id -Property "id,userPrincipalName,displayName,createdDateTime,accountEnabled,signInActivity,onPremisesSyncEnabled,userType,mail,otherMails,proxyAddresses" -ErrorAction SilentlyContinue
                
                if ($user) {
                    # Track the oldest Global Admin account
                    if ($user.CreatedDateTime -and $user.CreatedDateTime -lt $oldestCreatedDate) {
                        $oldestCreatedDate = $user.CreatedDateTime
                        $oldestAdminAccount = $user
                    }
                    
                    # Check for default/generic naming patterns
                    $genericPatterns = @(
                        "admin",
                        "administrator", 
                        "root",
                        "superuser",
                        "sysadmin",
                        "test",
                        "temp",
                        "default",
                        "user1",
                        "adminuser"
                    )
                    
                    $userNameLower = $user.UserPrincipalName.ToLower()
                    $displayNameLower = if ($user.DisplayName) { $user.DisplayName.ToLower() } else { "" }
                    $isGenericName = $false
                    
                    foreach ($pattern in $genericPatterns) {
                        if ($userNameLower -match "^$pattern" -or $userNameLower -match "$pattern@" -or 
                            $displayNameLower -eq $pattern -or $displayNameLower -match "^$pattern\s") {
                            $isGenericName = $true
                            break
                        }
                    }
                    
                    # Check account age
                    $accountAge = if ($user.CreatedDateTime) { 
                        (Get-Date) - $user.CreatedDateTime 
                    } else { 
                        [TimeSpan]::MaxValue 
                    }
                    
                    # Check for lack of recent sign-in activity
                    $lastSignIn = $null
                    if ($user.SignInActivity -and $user.SignInActivity.LastSignInDateTime) {
                        $lastSignIn = $user.SignInActivity.LastSignInDateTime
                    }
                    
                    $inactiveDays = if ($lastSignIn) {
                        ((Get-Date) - $lastSignIn).TotalDays
                    } else {
                        -1  # Never signed in or data not available
                    }
                    
                    # Identify suspicious default admin accounts
                    if ($isGenericName -or ($accountAge.TotalDays -gt $AccountAgeThresholdDays -and $inactiveDays -gt 90)) {
                        $suspiciousAdmins += @{
                            User = $user
                            IsGenericName = $isGenericName
                            AccountAge = $accountAge
                            InactiveDays = $inactiveDays
                            LastSignIn = $lastSignIn
                        }
                    }
                }
            }
            
            # Finding 1: Original Global Admin account still active
            if ($oldestAdminAccount -and $oldestAdminAccount.AccountEnabled) {
                $accountAgeDays = ((Get-Date) - $oldestCreatedDate).TotalDays
                
                if ($accountAgeDays -gt $AccountAgeThresholdDays) {
                    $lastSignInInfo = "Never"
                    if ($oldestAdminAccount.SignInActivity -and $oldestAdminAccount.SignInActivity.LastSignInDateTime) {
                        $lastSignInInfo = $oldestAdminAccount.SignInActivity.LastSignInDateTime.ToString("yyyy-MM-dd")
                    }
                    
                    $findings += @{
                        ObjectName = $oldestAdminAccount.UserPrincipalName
                        ObjectType = "User"
                        RiskLevel = "Low"
                        Description = "The oldest Global Administrator account '$($oldestAdminAccount.UserPrincipalName)' was created $([Math]::Round($accountAgeDays, 0)) days ago and is still active. This appears to be the original admin account created during tenant setup. Last sign-in: $lastSignInInfo"
                        Remediation = "1. Review if this original admin account is still needed. " +
                                     "2. If the account is used, ensure it follows organizational naming conventions. " +
                                     "3. Verify strong authentication (MFA) is enforced on this account. " +
                                     "4. Consider creating properly named administrative accounts and disabling the original. " +
                                     "5. If keeping the account, ensure it has a strong, unique password. " +
                                     "6. Add the account to Conditional Access policies for enhanced security. " +
                                     "7. Enable sign-in risk policies for this privileged account."
                        AffectedAttributes = @("accountEnabled", "createdDateTime", "userPrincipalName")
                    }
                }
            }
            
            # Finding 2: Generic/default named Global Admin accounts
            foreach ($suspicious in $suspiciousAdmins) {
                if ($suspicious.IsGenericName) {
                    $lastSignInInfo = "Never"
                    if ($suspicious.LastSignIn) {
                        $lastSignInInfo = $suspicious.LastSignIn.ToString("yyyy-MM-dd")
                    }
                    
                    $findings += @{
                        ObjectName = $suspicious.User.UserPrincipalName
                        ObjectType = "User"
                        RiskLevel = "Low"
                        Description = "Global Administrator account '$($suspicious.User.UserPrincipalName)' uses a generic or default naming pattern. These accounts are often targeted by attackers as they may have weaker security controls. Last sign-in: $lastSignInInfo"
                        Remediation = "1. Rename the account to follow organizational naming standards. " +
                                     "2. Ensure the account has MFA enabled and enforced. " +
                                     "3. Review if this account is actually needed or can be replaced. " +
                                     "4. Implement Privileged Identity Management (PIM) for just-in-time access. " +
                                     "5. Add to Conditional Access policies requiring compliant devices. " +
                                     "6. Enable continuous access evaluation for real-time risk assessment."
                        AffectedAttributes = @("userPrincipalName", "displayName")
                    }
                }
            }
            
            # Finding 3: Inactive Global Admin accounts
            foreach ($suspicious in $suspiciousAdmins) {
                if ($suspicious.InactiveDays -gt 90 -and $suspicious.User.AccountEnabled) {
                    $inactiveMsg = if ($suspicious.InactiveDays -eq -1) {
                        "This account has never signed in"
                    } else {
                        "This account has been inactive for $([Math]::Round($suspicious.InactiveDays, 0)) days"
                    }
                    
                    $findings += @{
                        ObjectName = $suspicious.User.UserPrincipalName
                        ObjectType = "User"
                        RiskLevel = "Low"
                        Description = "Global Administrator account '$($suspicious.User.UserPrincipalName)' is enabled but inactive. $inactiveMsg. Inactive privileged accounts increase the attack surface."
                        Remediation = "1. Review if this account is still needed. " +
                                     "2. If not needed, disable or delete the account. " +
                                     "3. If needed occasionally, implement PIM for just-in-time activation. " +
                                     "4. Consider using a break-glass account process instead. " +
                                     "5. Implement regular access reviews for all Global Admin accounts. " +
                                     "6. Set up alerts for when inactive privileged accounts are accessed."
                        AffectedAttributes = @("accountEnabled", "signInActivity")
                    }
                }
            }
            
            # Finding 4: Check for accounts without proper email configuration
            foreach ($admin in $globalAdmins) {
                $user = Get-MgUser -UserId $admin.Id -Property "userPrincipalName,mail,otherMails" -ErrorAction SilentlyContinue
                
                if ($user -and [string]::IsNullOrWhiteSpace($user.Mail) -and 
                    ($null -eq $user.OtherMails -or $user.OtherMails.Count -eq 0)) {
                    
                    $findings += @{
                        ObjectName = $user.UserPrincipalName
                        ObjectType = "User"
                        RiskLevel = "Low"
                        Description = "Global Administrator account '$($user.UserPrincipalName)' lacks a configured email address, which may indicate it's a service or default account not following best practices."
                        Remediation = "1. Configure a proper email address for security notifications. " +
                                     "2. Ensure the account can receive security alerts and MFA notifications. " +
                                     "3. Review if this is a service account that should not have Global Admin rights. " +
                                     "4. Consider replacing with a properly configured administrative account."
                        AffectedAttributes = @("mail", "otherMails")
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
    $message = "Default Global Administrator account analysis completed successfully."
    
    if ($findings.Count -gt 0) {
        $score = 75  # Low-risk findings
        $message = "Found $($findings.Count) potential issues with default or original Global Administrator accounts that should be reviewed."
    }
    else {
        $message = "No issues found with default Global Administrator accounts. All admin accounts appear to follow security best practices."
    }
    
    return @{
        CheckId = "EID-T4-001"
        Timestamp = (Get-Date).ToString("o")
        Status = $status
        Score = $score
        Severity = "Low"
        Category = "PrivilegedAccess"
        Findings = $findings
        Message = $message
        AffectedObjects = $findings.Count
        IgnoredObjects = 0
        Metadata = @{
            TenantId = $TenantId
            ExecutionTime = [Math]::Round($executionTime, 2)
            TotalGlobalAdmins = if ($globalAdmins) { @($globalAdmins).Count } else { 0 }
        }
    }
}
catch {
    return @{
        CheckId = "EID-T4-001"
        Timestamp = (Get-Date).ToString("o")
        Status = "Error"
        Score = 0
        Severity = "Low"
        Category = "PrivilegedAccess"
        Findings = @()
        Message = "Error analyzing default Global Administrator accounts: $_"
        AffectedObjects = 0
        IgnoredObjects = 0
        Metadata = @{
            TenantId = $TenantId
            ExecutionTime = 0.0
            ErrorDetails = $_.Exception.Message
        }
    }
}