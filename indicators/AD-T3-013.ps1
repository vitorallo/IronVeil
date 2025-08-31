<#
.SYNOPSIS
Analyzes Group Policy Objects for security misconfigurations

.METADATA
{
  "id": "AD-T3-013",
  "name": "Misconfigured Group Policy Objects - General Security Settings",
  "description": "GPOs with misconfigurations that weaken security posture",
  "category": "Configuration",
  "severity": "Medium",
  "weight": 5,
  "impact": 6,
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
    
    # Get all GPOs
    $gpos = Get-GPO -All -Domain $DomainName -ErrorAction Stop
    
    foreach ($gpo in $gpos) {
        try {
            $gpoIssues = @()
            $gpoRiskLevel = "Low"
            
            # Get GPO report
            $gpoReport = Get-GPOReport -Guid $gpo.Id -ReportType Xml -Domain $DomainName
            $xml = [xml]$gpoReport
            
            # Check if GPO is linked
            $isLinked = $false
            $linkedOUs = @()
            if ($xml.GPO.LinksTo) {
                $isLinked = $true
                foreach ($link in $xml.GPO.LinksTo) {
                    $linkedOUs += $link.SOMPath
                }
            }
            
            # Check if GPO is empty
            if (-not $xml.GPO.Computer.ExtensionData -and -not $xml.GPO.User.ExtensionData) {
                if ($isLinked) {
                    $gpoIssues += "Empty GPO is linked to OUs"
                    $gpoRiskLevel = "Low"
                }
            } else {
                # Check Computer Configuration settings
                if ($xml.GPO.Computer.ExtensionData) {
                    foreach ($extension in $xml.GPO.Computer.ExtensionData) {
                        # Check for Security Options
                        if ($extension.Extension.SecurityOptions) {
                            foreach ($option in $extension.Extension.SecurityOptions.KeyName) {
                                # Check for weak settings
                                switch ($option.KeyName) {
                                    "EnableLUA" {
                                        if ($option.SettingNumber -eq 0) {
                                            $gpoIssues += "UAC is disabled"
                                            $gpoRiskLevel = "High"
                                        }
                                    }
                                    "LimitBlankPasswordUse" {
                                        if ($option.SettingNumber -eq 0) {
                                            $gpoIssues += "Blank passwords allowed for network access"
                                            $gpoRiskLevel = "High"
                                        }
                                    }
                                    "NoLMHash" {
                                        if ($option.SettingNumber -eq 0) {
                                            $gpoIssues += "LM hash storage enabled"
                                            $gpoRiskLevel = "Medium"
                                        }
                                    }
                                    "RestrictAnonymous" {
                                        if ($option.SettingNumber -eq 0) {
                                            $gpoIssues += "Anonymous access not restricted"
                                            $gpoRiskLevel = "Medium"
                                        }
                                    }
                                    "ClearTextPassword" {
                                        if ($option.SettingNumber -eq 1) {
                                            $gpoIssues += "Clear text passwords enabled"
                                            $gpoRiskLevel = "Critical"
                                        }
                                    }
                                }
                            }
                        }
                        
                        # Check for Audit Policy
                        if ($extension.Extension.AuditSetting) {
                            $auditDisabled = $true
                            foreach ($audit in $extension.Extension.AuditSetting) {
                                if ($audit.SettingValue -ne "No Auditing") {
                                    $auditDisabled = $false
                                    break
                                }
                            }
                            if ($auditDisabled) {
                                $gpoIssues += "Security auditing disabled"
                                if ($gpoRiskLevel -eq "Low") {
                                    $gpoRiskLevel = "Medium"
                                }
                            }
                        }
                        
                        # Check for Local Users and Groups
                        if ($extension.Extension.LocalUsersAndGroups) {
                            foreach ($group in $extension.Extension.LocalUsersAndGroups.Group) {
                                if ($group.Properties.groupName -eq "Administrators") {
                                    # Check if non-admin users are added to local admins
                                    foreach ($member in $group.Properties.Members.Member) {
                                        if ($member.name -and $member.name -notmatch "Domain Admins|Administrator") {
                                            $gpoIssues += "Non-standard members added to local Administrators: $($member.name)"
                                            if ($gpoRiskLevel -eq "Low") {
                                                $gpoRiskLevel = "Medium"
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        
                        # Check for Registry settings
                        if ($extension.Extension.RegistrySetting) {
                            foreach ($reg in $extension.Extension.RegistrySetting) {
                                # Check for Windows Defender disabled
                                if ($reg.KeyPath -match "Windows Defender" -and $reg.Value.Name -eq "DisableAntiSpyware") {
                                    if ($reg.Value.Number -eq 1) {
                                        $gpoIssues += "Windows Defender disabled"
                                        $gpoRiskLevel = "High"
                                    }
                                }
                                # Check for Windows Firewall disabled
                                if ($reg.KeyPath -match "WindowsFirewall" -and $reg.Value.Name -eq "EnableFirewall") {
                                    if ($reg.Value.Number -eq 0) {
                                        $gpoIssues += "Windows Firewall disabled"
                                        $gpoRiskLevel = "High"
                                    }
                                }
                            }
                        }
                        
                        # Check for Scripts
                        if ($extension.Extension.Script) {
                            foreach ($script in $extension.Extension.Script) {
                                if ($script.Command) {
                                    # Check for suspicious script locations
                                    if ($script.Command -notmatch "^\\\\.*\\SYSVOL\\" -and 
                                        $script.Command -notmatch "^%SystemRoot%") {
                                        $gpoIssues += "Script from non-standard location: $($script.Command)"
                                        if ($gpoRiskLevel -eq "Low") {
                                            $gpoRiskLevel = "Medium"
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                
                # Check User Configuration settings
                if ($xml.GPO.User.ExtensionData) {
                    foreach ($extension in $xml.GPO.User.ExtensionData) {
                        # Check for Drive Maps with credentials
                        if ($extension.Extension.DriveMapSettings) {
                            foreach ($drive in $extension.Extension.DriveMapSettings.Drive) {
                                if ($drive.Properties.userName) {
                                    $gpoIssues += "Drive mapping with embedded credentials"
                                    if ($gpoRiskLevel -ne "High" -and $gpoRiskLevel -ne "Critical") {
                                        $gpoRiskLevel = "Medium"
                                    }
                                }
                            }
                        }
                        
                        # Check for Scheduled Tasks
                        if ($extension.Extension.ScheduledTasks) {
                            foreach ($task in $extension.Extension.ScheduledTasks.Task) {
                                if ($task.Properties.runAs -and $task.Properties.logonType -eq "Password") {
                                    $gpoIssues += "Scheduled task with stored credentials"
                                    if ($gpoRiskLevel -eq "Low") {
                                        $gpoRiskLevel = "Medium"
                                    }
                                }
                            }
                        }
                    }
                }
            }
            
            # Check GPO permissions
            $gpoPermissions = Get-GPPermission -Guid $gpo.Id -All -Domain $DomainName -ErrorAction Stop
            
            foreach ($permission in $gpoPermissions) {
                # Check for excessive permissions
                if ($permission.Permission -eq "GpoEditDeleteModifySecurity") {
                    if ($permission.Trustee.Name -notin @("Domain Admins", "Enterprise Admins", "SYSTEM", "Group Policy Creator Owners")) {
                        $gpoIssues += "Excessive permissions for '$($permission.Trustee.Name)'"
                        if ($gpoRiskLevel -eq "Low") {
                            $gpoRiskLevel = "Medium"
                        }
                    }
                }
                
                # Check for Authenticated Users without Read permission (GPO won't apply)
                if ($permission.Trustee.Name -eq "Authenticated Users" -and $permission.Permission -eq "None") {
                    $gpoIssues += "Authenticated Users lacks Read permission (GPO won't apply)"
                }
            }
            
            # Check if GPO is enforced on critical OUs
            $isCriticalGPO = $false
            foreach ($ou in $linkedOUs) {
                if ($ou -match "Domain Controllers|Admin|Servers") {
                    $isCriticalGPO = $true
                    break
                }
            }
            
            if ($gpoIssues.Count -gt 0) {
                $linkInfo = if ($isLinked) { 
                    "Linked to: $($linkedOUs -join ', ')" 
                } else { 
                    "Not linked" 
                }
                
                if ($isCriticalGPO -and $gpoRiskLevel -ne "Low") {
                    $gpoRiskLevel = "High"
                }
                
                $findings += @{
                    ObjectName = $gpo.DisplayName
                    ObjectType = "GroupPolicyObject"
                    RiskLevel = $gpoRiskLevel
                    Description = "GPO has security issues: $($gpoIssues -join '; '). $linkInfo"
                    Remediation = "Review and correct GPO settings according to security best practices"
                    AffectedAttributes = @("GPO Settings")
                }
                $affectedCount++
                
                # Score impact
                if ($gpoRiskLevel -eq "Critical") {
                    $score -= 20
                } elseif ($gpoRiskLevel -eq "High") {
                    $score -= 15
                } elseif ($gpoRiskLevel -eq "Medium") {
                    $score -= 10
                } else {
                    $score -= 5
                }
            }
            
            # Check for unlinked GPOs (cleanup opportunity)
            if (-not $isLinked -and $gpo.DisplayName -notmatch "Default Domain") {
                $findings += @{
                    ObjectName = $gpo.DisplayName
                    ObjectType = "GroupPolicyObject"
                    RiskLevel = "Low"
                    Description = "GPO is not linked to any OU (orphaned)"
                    Remediation = "Delete orphaned GPOs or link them if needed"
                    AffectedAttributes = @("GPO Links")
                }
                $affectedCount++
                $score -= 2
            }
            
        } catch {
            $ignoredCount++
            Write-Warning "Could not analyze GPO '$($gpo.DisplayName)': $_"
        }
    }
    
    # Check for missing critical GPOs
    $criticalGPOs = @("Default Domain Policy", "Default Domain Controllers Policy")
    foreach ($criticalGPO in $criticalGPOs) {
        if ($gpos.DisplayName -notcontains $criticalGPO) {
            $findings += @{
                ObjectName = $criticalGPO
                ObjectType = "GroupPolicyObject"
                RiskLevel = "High"
                Description = "Critical GPO '$criticalGPO' is missing"
                Remediation = "Restore or recreate the missing default GPO"
                AffectedAttributes = @("GPO Existence")
            }
            $affectedCount++
            $score -= 20
        }
    }
    
    # Ensure score doesn't go below 0
    $score = [Math]::Max(0, $score)
    
    # Determine overall status
    $status = if ($findings.Count -eq 0) { "Success" } 
              elseif ($score -lt 50) { "Failed" } 
              else { "Warning" }
    
    $message = if ($findings.Count -eq 0) {
        "All Group Policy Objects are properly configured"
    } else {
        "Found $($findings.Count) GPO configuration issues"
    }
    
    $executionTime = (Get-Date) - $startTime
    
    return @{
        CheckId = "AD-T3-013"
        Timestamp = (Get-Date).ToString("o")
        Status = $status
        Score = $score
        Severity = "Medium"
        Category = "Configuration"
        Findings = $findings
        Message = $message
        AffectedObjects = $affectedCount
        IgnoredObjects = $ignoredCount
        Metadata = @{
            Domain = $DomainName
            ExecutionTime = $executionTime.TotalSeconds
            TotalGPOs = $gpos.Count
        }
    }
    
} catch {
    return @{
        CheckId = "AD-T3-013"
        Timestamp = (Get-Date).ToString("o")
        Status = "Error"
        Score = 0
        Severity = "Medium"
        Category = "Configuration"
        Findings = @()
        Message = "Error analyzing Group Policy Objects: $_"
        AffectedObjects = 0
        IgnoredObjects = 0
        Metadata = @{
            Domain = $DomainName
            ExecutionTime = ((Get-Date) - $startTime).TotalSeconds
            Error = $_.Exception.Message
        }
    }
}