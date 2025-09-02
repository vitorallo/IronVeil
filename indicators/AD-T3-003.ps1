<#
.SYNOPSIS
Identifies stale or inactive user and computer accounts with no recent login activity

.METADATA
{
  "id": "AD-T3-003",
  "name": "Stale or Inactive Accounts",
  "description": "User and computer accounts that are no longer in use but remain active pose security risks",
  "category": "AccountManagement",
  "severity": "Medium",
  "weight": 5,
  "impact": 5,
  "frameworks": ["MITRE", "NIST"],
  "targets": ["ActiveDirectory"]
}
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$DomainName = $env:USERDNSDOMAIN,
    
    [Parameter(Mandatory=$false)]
    [int]$InactiveDaysThreshold = 90
)

$startTime = Get-Date

try {
    # Initialize results
    $findings = @()
    $affectedCount = 0
    $ignoredCount = 0
    $score = 100
    
    # Calculate date threshold
    $inactiveDate = (Get-Date).AddDays(-$InactiveDaysThreshold)
    $veryInactiveDate = (Get-Date).AddDays(-180)  # 6 months
    $extremelyInactiveDate = (Get-Date).AddDays(-365)  # 1 year
    
    # Check for inactive user accounts
    try {
        $inactiveUsers = Get-ADUser -Filter "((LastLogonTimestamp -lt '$($inactiveDate.ToFileTime())' -or LastLogonTimestamp -notlike '*') -and Enabled -eq 'true' -and Name -notlike '*svc*' -and Name -notlike '*service*')" -Properties LastLogonTimestamp, LastLogonDate, whenCreated, PasswordLastSet, memberOf -Server $DomainName -ErrorAction Stop
        
        foreach ($user in $inactiveUsers) {
            $lastLogon = if ($user.LastLogonTimestamp) {
                [DateTime]::FromFileTime($user.LastLogonTimestamp)
            } else {
                $null
            }
            
            $daysSinceLogon = if ($lastLogon) {
                ((Get-Date) - $lastLogon).Days
            } else {
                ((Get-Date) - $user.whenCreated).Days
            }
            
            # Check if user is privileged
            $isPrivileged = $false
            $privilegedGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators", "Account Operators", "Backup Operators", "Server Operators")
            foreach ($group in $user.memberOf) {
                $groupName = ($group -split ",")[0] -replace "CN=", ""
                if ($privilegedGroups -contains $groupName) {
                    $isPrivileged = $true
                    break
                }
            }
            
            $riskLevel = if ($daysSinceLogon -gt 365) { "High" }
                         elseif ($daysSinceLogon -gt 180) { "Medium" }
                         else { "Low" }
            
            if ($isPrivileged) {
                $riskLevel = "High"  # Privileged inactive accounts are always high risk
            }
            
            $findings += @{
                ObjectName = $user.SamAccountName
                ObjectType = "User"
                RiskLevel = $riskLevel
                Description = "User account inactive for $daysSinceLogon days$(if ($isPrivileged) { ' (PRIVILEGED ACCOUNT)' } else { '' })"
                Remediation = if ($daysSinceLogon -gt 365) { "Disable or delete this account if no longer needed" } 
                             else { "Review account necessity and disable if not required" }
                AffectedAttributes = @("LastLogonTimestamp", "Enabled")
            }
            $affectedCount++
            
            # Adjust score based on risk
            if ($isPrivileged) {
                $score -= 5
            } elseif ($daysSinceLogon -gt 365) {
                $score -= 3
            } elseif ($daysSinceLogon -gt 180) {
                $score -= 2
            } else {
                $score -= 1
            }
        }
    } catch {
        $ignoredCount++
        Write-Warning "Could not check inactive user accounts: $_"
    }
    
    # Check for inactive computer accounts
    try {
        $inactiveComputers = Get-ADComputer -Filter "((LastLogonTimestamp -lt '$($inactiveDate.ToFileTime())' -or LastLogonTimestamp -notlike '*') -and Enabled -eq 'true')" -Properties LastLogonTimestamp, LastLogonDate, whenCreated, OperatingSystem, PasswordLastSet -Server $DomainName -ErrorAction Stop
        
        foreach ($computer in $inactiveComputers) {
            $lastLogon = if ($computer.LastLogonTimestamp) {
                [DateTime]::FromFileTime($computer.LastLogonTimestamp)
            } else {
                $null
            }
            
            $daysSinceLogon = if ($lastLogon) {
                ((Get-Date) - $lastLogon).Days
            } else {
                ((Get-Date) - $computer.whenCreated).Days
            }
            
            # Check if it's a domain controller or server
            $isServer = $computer.OperatingSystem -like "*Server*"
            $isDC = $computer.OperatingSystem -like "*Domain Controller*"
            
            $riskLevel = if ($isDC) { "Critical" }
                        elseif ($isServer -and $daysSinceLogon -gt 180) { "High" }
                        elseif ($daysSinceLogon -gt 365) { "High" }
                        elseif ($daysSinceLogon -gt 180) { "Medium" }
                        else { "Low" }
            
            $findings += @{
                ObjectName = $computer.Name
                ObjectType = "Computer"
                RiskLevel = $riskLevel
                Description = "Computer account inactive for $daysSinceLogon days$(if ($isServer) { " (SERVER: $($computer.OperatingSystem))" } else { '' })"
                Remediation = if ($daysSinceLogon -gt 365) { "Remove computer from domain and disable account" } 
                             else { "Verify if computer is still in use and disable if decommissioned" }
                AffectedAttributes = @("LastLogonTimestamp", "Enabled")
            }
            $affectedCount++
            
            # Adjust score based on risk
            if ($isDC) {
                $score -= 10
            } elseif ($isServer) {
                $score -= 5
            } elseif ($daysSinceLogon -gt 365) {
                $score -= 3
            } elseif ($daysSinceLogon -gt 180) {
                $score -= 2
            } else {
                $score -= 1
            }
        }
    } catch {
        $ignoredCount++
        Write-Warning "Could not check inactive computer accounts: $_"
    }
    
    # Check for accounts with expired passwords but still enabled
    try {
        $passwordExpiredUsers = Get-ADUser -Filter {
            PasswordExpired -eq $true -and
            Enabled -eq $true
        } -Properties PasswordExpired, PasswordLastSet, memberOf -Server $DomainName -ErrorAction Stop
        
        foreach ($user in $passwordExpiredUsers) {
            $daysSincePasswordSet = if ($user.PasswordLastSet) {
                ((Get-Date) - $user.PasswordLastSet).Days
            } else {
                999
            }
            
            $findings += @{
                ObjectName = $user.SamAccountName
                ObjectType = "User"
                RiskLevel = "Medium"
                Description = "Account has expired password but is still enabled (password age: $daysSincePasswordSet days)"
                Remediation = "Disable account or require password reset at next logon"
                AffectedAttributes = @("PasswordExpired", "Enabled")
            }
            $affectedCount++
            $score -= 2
        }
    } catch {
        $ignoredCount++
        Write-Warning "Could not check accounts with expired passwords: $_"
    }
    
    # Check for accounts that have never logged in
    try {
        $neverLoggedInUsers = Get-ADUser -Filter {
            LastLogonTimestamp -notlike "*" -and
            Enabled -eq $true -and
            whenCreated -lt $inactiveDate
        } -Properties LastLogonTimestamp, whenCreated -Server $DomainName -ErrorAction Stop
        
        foreach ($user in $neverLoggedInUsers) {
            $accountAge = ((Get-Date) - $user.whenCreated).Days
            
            $findings += @{
                ObjectName = $user.SamAccountName
                ObjectType = "User"
                RiskLevel = "Medium"
                Description = "Account created $accountAge days ago but never logged in"
                Remediation = "Review if account is needed and disable if not required"
                AffectedAttributes = @("LastLogonTimestamp", "whenCreated")
            }
            $affectedCount++
            $score -= 2
        }
    } catch {
        $ignoredCount++
        Write-Warning "Could not check never-logged-in accounts: $_"
    }
    
    # Ensure score doesn't go below 0
    $score = [Math]::Max(0, $score)
    
    # Determine overall status
    $status = if ($findings.Count -eq 0) { "Success" } 
              elseif ($score -lt 50) { "Failed" } 
              else { "Warning" }
    
    $message = if ($findings.Count -eq 0) {
        "No stale or inactive accounts detected"
    } else {
        "Found $($findings.Count) stale or inactive accounts that pose security risks"
    }
    
    $executionTime = (Get-Date) - $startTime
    
    return @{
        CheckId = "AD-T3-003"
        Timestamp = (Get-Date).ToString("o")
        Status = $status
        Score = $score
        Severity = "Medium"
        Category = "AccountManagement"
        Findings = $findings
        Message = $message
        AffectedObjects = $affectedCount
        IgnoredObjects = $ignoredCount
        Metadata = @{
            Domain = $DomainName
            ExecutionTime = $executionTime.TotalSeconds
            InactiveDaysThreshold = $InactiveDaysThreshold
            TotalInactiveUsers = ($findings | Where-Object { $_.ObjectType -eq "User" }).Count
            TotalInactiveComputers = ($findings | Where-Object { $_.ObjectType -eq "Computer" }).Count
        }
    }
    
} catch {
    return @{
        CheckId = "AD-T3-003"
        Timestamp = (Get-Date).ToString("o")
        Status = "Error"
        Score = 0
        Severity = "Medium"
        Category = "AccountManagement"
        Findings = @()
        Message = "Error checking stale or inactive accounts: $_"
        AffectedObjects = 0
        IgnoredObjects = 0
        Metadata = @{
            Domain = $DomainName
            ExecutionTime = ((Get-Date) - $startTime).TotalSeconds
            Error = $_.Exception.Message
        }
    }
}