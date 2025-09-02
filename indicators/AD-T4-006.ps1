<#
.SYNOPSIS
Checks if the SYSVOL share has appropriate permissions following the principle of least privilege

.METADATA
{
  "id": "AD-T4-006",
  "name": "Insecure SYSVOL Share Permissions",
  "description": "The SYSVOL share has overly permissive permissions that could allow unauthorized access to Group Policy files",
  "category": "FileSystemSecurity",
  "severity": "Low",
  "weight": 4,
  "impact": 4,
  "frameworks": ["MITRE", "NIST"],
  "targets": ["ActiveDirectory"]
}
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$DomainName = $env:USERDNSDOMAIN
)

$startTime = Get-Date

try {
    # Initialize results
    $findings = @()
    $affectedCount = 0
    $ignoredCount = 0
    $score = 100
    
    # Get domain information
    $domain = Get-ADDomain -Server $DomainName -ErrorAction Stop
    
    # Get all domain controllers
    $domainControllers = Get-ADDomainController -Filter * -Server $DomainName -ErrorAction Stop
    
    # Define expected permissions for SYSVOL
    $expectedPermissions = @{
        'Authenticated Users' = @('ReadAndExecute', 'Read')
        'SYSTEM' = @('FullControl')
        'Administrators' = @('FullControl')
        'CREATOR OWNER' = @('FullControl')
        'Domain Admins' = @('FullControl')
        'Enterprise Admins' = @('FullControl')
        'Server Operators' = @('ReadAndExecute', 'Read')
    }
    
    foreach ($dc in $domainControllers) {
        try {
            $dcName = $dc.HostName
            Write-Verbose "Checking SYSVOL permissions on $dcName"
            
            # Build SYSVOL path
            $sysvolPath = "\\$dcName\SYSVOL"
            $sysvolLocalPath = "\\$dcName\C$\Windows\SYSVOL"
            
            # Check share permissions
            try {
                $share = Get-WmiObject -Class Win32_Share -ComputerName $dcName -Filter "Name='SYSVOL'" -ErrorAction Stop
                
                if ($share) {
                    # Get share security descriptor
                    $shareSD = $share.GetAccessMask().Descriptor
                    
                    # Check if share exists but with wrong path
                    if ($share.Path -and -not $share.Path.EndsWith('SYSVOL')) {
                        $findings += @{
                            ObjectName = "$dcName - SYSVOL Share"
                            ObjectType = "Share"
                            RiskLevel = "Medium"
                            Description = "SYSVOL share on $dcName points to incorrect path: $($share.Path)"
                            Remediation = "Verify SYSVOL share points to the correct SYSVOL directory (typically C:\Windows\SYSVOL)"
                            AffectedAttributes = @("SharePath")
                        }
                        $affectedCount++
                        $score -= 15
                    }
                }
            } catch {
                $findings += @{
                    ObjectName = "$dcName - SYSVOL Share"
                    ObjectType = "Share"
                    RiskLevel = "High"
                    Description = "Could not verify SYSVOL share on $dcName - share may not exist or be inaccessible"
                    Remediation = "Ensure SYSVOL share exists and is accessible. Run 'dcdiag /test:netlogons' to verify share health"
                    AffectedAttributes = @("ShareAvailability")
                }
                $affectedCount++
                $score -= 20
            }
            
            # Check NTFS permissions on SYSVOL folders
            $sysvolSubfolders = @(
                "$sysvolPath\$($domain.DNSRoot)",
                "$sysvolPath\$($domain.DNSRoot)\Policies",
                "$sysvolPath\$($domain.DNSRoot)\Scripts"
            )
            
            foreach ($folder in $sysvolSubfolders) {
                try {
                    $acl = Get-Acl -Path $folder -ErrorAction Stop
                    $folderName = Split-Path $folder -Leaf
                    
                    # Check for Everyone permissions (should not exist)
                    $everyoneRules = $acl.Access | Where-Object { 
                        $_.IdentityReference -match 'Everyone|S-1-1-0' 
                    }
                    
                    if ($everyoneRules) {
                        foreach ($rule in $everyoneRules) {
                            $findings += @{
                                ObjectName = "$dcName - $folder"
                                ObjectType = "Folder"
                                RiskLevel = "Medium"
                                Description = "'Everyone' group has $($rule.FileSystemRights) permissions on SYSVOL folder"
                                Remediation = "Remove 'Everyone' permissions from SYSVOL. Use 'Authenticated Users' with Read permissions instead"
                                AffectedAttributes = @("NTFS Permissions", "Everyone")
                            }
                            $affectedCount++
                            $score -= 20
                        }
                    }
                    
                    # Check for excessive permissions for Authenticated Users
                    $authUsersRules = $acl.Access | Where-Object { 
                        $_.IdentityReference -match 'Authenticated Users|S-1-5-11' 
                    }
                    
                    foreach ($rule in $authUsersRules) {
                        if ($rule.FileSystemRights -match 'Write|Modify|FullControl|ChangePermissions|TakeOwnership') {
                            $findings += @{
                                ObjectName = "$dcName - $folder"
                                ObjectType = "Folder"
                                RiskLevel = "High"
                                Description = "'Authenticated Users' has excessive permissions ($($rule.FileSystemRights)) on SYSVOL"
                                Remediation = "'Authenticated Users' should only have Read & Execute permissions on SYSVOL"
                                AffectedAttributes = @("NTFS Permissions", "Authenticated Users")
                            }
                            $affectedCount++
                            $score -= 25
                        }
                    }
                    
                    # Check for non-standard groups with write access
                    $writeAccessRules = $acl.Access | Where-Object {
                        $_.FileSystemRights -match 'Write|Modify|FullControl' -and
                        $_.IdentityReference -notmatch 'SYSTEM|Administrators|Domain Admins|Enterprise Admins|CREATOR OWNER'
                    }
                    
                    foreach ($rule in $writeAccessRules) {
                        $findings += @{
                            ObjectName = "$dcName - $folder"
                            ObjectType = "Folder"
                            RiskLevel = "Medium"
                            Description = "Non-standard account '$($rule.IdentityReference)' has write access to SYSVOL"
                            Remediation = "Review and remove unnecessary write permissions. Only Domain/Enterprise Admins should modify SYSVOL"
                            AffectedAttributes = @("NTFS Permissions", $rule.IdentityReference.ToString())
                        }
                        $affectedCount++
                        $score -= 15
                    }
                    
                    # Check for denied permissions (can cause issues)
                    $denyRules = $acl.Access | Where-Object { $_.AccessControlType -eq 'Deny' }
                    if ($denyRules) {
                        foreach ($rule in $denyRules) {
                            $findings += @{
                                ObjectName = "$dcName - $folder"
                                ObjectType = "Folder"
                                RiskLevel = "Low"
                                Description = "Deny permission found for '$($rule.IdentityReference)' on SYSVOL"
                                Remediation = "Avoid using Deny permissions. Use group membership to control access instead"
                                AffectedAttributes = @("NTFS Permissions", "Deny Rules")
                            }
                            $score -= 5
                        }
                    }
                    
                    # Check inheritance settings
                    if ($acl.AreAccessRulesProtected) {
                        $findings += @{
                            ObjectName = "$dcName - $folder"
                            ObjectType = "Folder"
                            RiskLevel = "Low"
                            Description = "Inheritance is disabled on SYSVOL folder '$folderName'"
                            Remediation = "Enable inheritance to ensure consistent permissions unless there's a specific requirement"
                            AffectedAttributes = @("Inheritance")
                        }
                        $score -= 3
                    }
                    
                } catch {
                    $ignoredCount++
                    Write-Warning "Could not check permissions on ${folder}: ${_}"
                }
            }
            
            # Check for orphaned SIDs in permissions
            try {
                $sysvolAcl = Get-Acl -Path $sysvolPath -ErrorAction Stop
                $orphanedSids = $sysvolAcl.Access | Where-Object { 
                    $_.IdentityReference -match '^S-1-5-21-' 
                }
                
                if ($orphanedSids) {
                    $findings += @{
                        ObjectName = "$dcName - SYSVOL"
                        ObjectType = "Share"
                        RiskLevel = "Low"
                        Description = "Orphaned SIDs found in SYSVOL permissions (deleted accounts still in ACL)"
                        Remediation = "Remove orphaned SIDs from SYSVOL permissions to maintain clean ACLs"
                        AffectedAttributes = @("Orphaned SIDs")
                    }
                    $affectedCount++
                    $score -= 5
                }
            } catch {
                Write-Verbose "Could not check for orphaned SIDs on $dcName"
            }
            
            # Check SYSVOL replication health (FRS vs DFSR)
            try {
                $replicationMethod = Get-WmiObject -Namespace "root\microsoftdfs" -Class "dfsrreplicatedfolderinfo" `
                    -ComputerName $dcName -ErrorAction SilentlyContinue
                
                if (-not $replicationMethod) {
                    # Might be using FRS (legacy)
                    $frsService = Get-Service -ComputerName $dcName -Name "NtFrs" -ErrorAction SilentlyContinue
                    if ($frsService -and $frsService.Status -eq "Running") {
                        $findings += @{
                            ObjectName = $dcName
                            ObjectType = "DomainController"
                            RiskLevel = "Low"
                            Description = "Domain Controller is using legacy FRS for SYSVOL replication instead of DFSR"
                            Remediation = "Migrate from FRS to DFSR for improved SYSVOL replication reliability and performance"
                            AffectedAttributes = @("Replication Method")
                        }
                        $score -= 10
                    }
                }
            } catch {
                Write-Verbose "Could not determine SYSVOL replication method on $dcName"
            }
            
        } catch {
            $ignoredCount++
            Write-Warning "Could not check SYSVOL on ${dcName}: ${_}"
        }
    }
    
    # Additional check: Look for GPO folders with incorrect permissions
    try {
        $gpoPath = "\\$($domain.PDCEmulator)\SYSVOL\$($domain.DNSRoot)\Policies"
        $gpoFolders = Get-ChildItem -Path $gpoPath -Directory -ErrorAction SilentlyContinue | Select-Object -First 10
        
        foreach ($gpoFolder in $gpoFolders) {
            $gpoAcl = Get-Acl -Path $gpoFolder.FullName -ErrorAction SilentlyContinue
            if ($gpoAcl) {
                # Check if GPO has Authenticated Users read access
                $authUsersAccess = $gpoAcl.Access | Where-Object { 
                    $_.IdentityReference -match 'Authenticated Users' -and
                    $_.FileSystemRights -match 'Read'
                }
                
                if (-not $authUsersAccess) {
                    $findings += @{
                        ObjectName = "GPO: $($gpoFolder.Name)"
                        ObjectType = "GroupPolicy"
                        RiskLevel = "Low"
                        Description = "GPO folder missing 'Authenticated Users' read permissions"
                        Remediation = "Ensure all GPOs have proper read permissions for Authenticated Users unless specifically filtered"
                        AffectedAttributes = @("GPO Permissions")
                    }
                    $score -= 2
                }
            }
        }
    } catch {
        Write-Verbose "Could not check individual GPO permissions"
    }
    
    # Ensure score doesn't go below 0
    $score = [Math]::Max(0, $score)
    
    # Determine overall status
    $status = if ($findings.Count -eq 0) { "Success" } 
              elseif ($score -lt 50) { "Failed" } 
              else { "Warning" }
    
    $message = if ($findings.Count -eq 0) {
        "SYSVOL share permissions are properly configured on all domain controllers"
    } else {
        "Found $($findings.Count) SYSVOL permission issues affecting $affectedCount objects"
    }
    
    $executionTime = (Get-Date) - $startTime
    
    return @{
        CheckId = "AD-T4-006"
        Timestamp = (Get-Date).ToString("o")
        Status = $status
        Score = $score
        Severity = "Low"
        Category = "FileSystemSecurity"
        Findings = $findings
        Message = $message
        AffectedObjects = $affectedCount
        IgnoredObjects = $ignoredCount
        Metadata = @{
            Domain = $DomainName
            ExecutionTime = $executionTime.TotalSeconds
            DomainControllersChecked = $domainControllers.Count
            PDCEmulator = $domain.PDCEmulator
        }
    }
    
} catch {
    return @{
        CheckId = "AD-T4-006"
        Timestamp = (Get-Date).ToString("o")
        Status = "Error"
        Score = 0
        Severity = "Low"
        Category = "FileSystemSecurity"
        Findings = @()
        Message = "Error checking SYSVOL permissions: $_"
        AffectedObjects = 0
        IgnoredObjects = 0
        Metadata = @{
            Domain = $DomainName
            ExecutionTime = ((Get-Date) - $startTime).TotalSeconds
            Error = $_.Exception.Message
        }
    }
}