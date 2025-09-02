<#
.SYNOPSIS
Simple test rule using only .NET classes - no PowerShell cmdlets

.METADATA
{
  "id": "TEST-001",
  "name": "PowerShell Pipeline Test Rule",
  "description": "A simple test rule that uses only .NET Framework classes to verify the PowerShell execution pipeline works correctly without relying on PowerShell cmdlets that may not be available in isolated environments.",
  "category": "SystemTest",
  "severity": "Low", 
  "weight": 1,
  "impact": 1,
  "frameworks": ["Test"],
  "targets": ["ActiveDirectory"]
}
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$DomainName = $env:USERDNSDOMAIN
)

try {
    # Use .NET DateTime instead of Get-Date cmdlet
    $startTime = [DateTime]::Now
    $findings = @()
    
    # Simple test: Check if we can access basic system information
    $computerName = [System.Environment]::MachineName
    $userName = [System.Environment]::UserName
    $osVersion = [System.Environment]::OSVersion.VersionString
    $dotNetVersion = [System.Environment]::Version.ToString()
    
    # Create a test finding to verify the JSON output structure
    $findings += @{
        ObjectName = $computerName
        ObjectType = "Computer"
        RiskLevel = "Info"
        Description = "Test rule executed successfully on computer '$computerName' by user '$userName'. OS: $osVersion, .NET: $dotNetVersion"
        Remediation = "This is a test rule - no remediation needed. The PowerShell execution pipeline is working correctly."
        AffectedAttributes = @("MachineName", "UserName", "OSVersion")
    }
    
    # Calculate execution time using .NET
    $executionTime = ([DateTime]::Now - $startTime).TotalSeconds
    
    # Return properly formatted result using .NET DateTime formatting
    return @{
        CheckId = "TEST-001"
        Timestamp = $startTime.ToString("o")  # ISO 8601 format
        Status = "Success"
        Score = 100
        Severity = "Low"
        Category = "SystemTest"
        Findings = $findings
        Message = "Test rule completed successfully. Found $($findings.Count) test result(s). PowerShell execution pipeline is working."
        AffectedObjects = $findings.Count
        IgnoredObjects = 0
        Metadata = @{
            Domain = $DomainName
            TenantId = $null
            ExecutionTime = [Math]::Round($executionTime, 3)
            RuleVersion = "1.0.0"
            Environment = "Test"
            ComputerName = $computerName
            UserName = $userName
            OSVersion = $osVersion
            DotNetVersion = $dotNetVersion
        }
    }
}
catch {
    # Use .NET exception handling instead of PowerShell error variables
    $errorMessage = $_.Exception.Message
    $executionTime = ([DateTime]::Now - $startTime).TotalSeconds
    
    return @{
        CheckId = "TEST-001"
        Timestamp = [DateTime]::Now.ToString("o")
        Status = "Error"
        Score = 0
        Severity = "Low"
        Category = "SystemTest"
        Findings = @()
        Message = "Test rule failed with error: $errorMessage"
        AffectedObjects = 0
        IgnoredObjects = 0
        Metadata = @{
            Domain = $DomainName
            ExecutionTime = [Math]::Round($executionTime, 3)
            RuleVersion = "1.0.0"
            ErrorDetails = $errorMessage
        }
    }
}