<#
.SYNOPSIS
Detects Group Policy Preferences with stored passwords using weak encryption

.METADATA
{
  "id": "AD-T2-004",
  "name": "Reversible Passwords in Group Policy Objects",
  "description": "Group Policy Preferences (GPP) with stored passwords use a publicly known AES key for encryption. This allows anyone with read access to SYSVOL to decrypt these passwords. Also checks for 'Store passwords using reversible encryption' policy.",
  "category": "CredentialExposure",
  "severity": "High",
  "weight": 7,
  "impact": 8,
  "frameworks": ["MITRE", "NIST"],
  "targets": ["ActiveDirectory"]
}
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$DomainName = $env:USERDNSDOMAIN
)

try {
    $startTime = Get-Date
    $findings = @()
    
    # Import IronVeil ADSI Helper
    . "$PSScriptRoot\IronVeil-ADSIHelper.ps1"
    
    if (-not $DomainName) {
        throw "Domain name could not be determined"
    }
    
    # Get domain information
    $domainInfo = Get-IVDomainInfo -DomainName $DomainName
    $domainDN = $domainInfo.DistinguishedName
    $domainNetBIOS = $domainInfo.NetBIOSName
    
    # Get SYSVOL path
    $sysvolPath = "\\$DomainName\SYSVOL\$DomainName\Policies"
    
    # Check if SYSVOL is accessible
    if (-not (Test-Path $sysvolPath)) {
        throw "Cannot access SYSVOL share at $sysvolPath"
    }
    
    # Part 1: Check for GPP passwords (cpassword in XML files)
    $gppFiles = @(
        "Groups\Groups.xml",
        "Services\Services.xml",
        "Scheduledtasks\ScheduledTasks.xml",
        "DataSources\DataSources.xml",
        "Drives\Drives.xml",
        "Printers\Printers.xml"
    )
    
    # Get all GPOs using ADSI helper
    $gpos = Get-IVGPO -DomainName $DomainName -All
    
    $gposChecked = 0
    $gposWithPasswords = 0
    
    foreach ($gpo in $gpos) {
        $gpoName = if ($gpo.DisplayName) { $gpo.DisplayName } else { $gpo.Id }
        $gpoId = $gpo.Id
        $gpoPath = "$sysvolPath\{$gpoId}"
        
        if (-not (Test-Path $gpoPath)) {
            continue
        }
        
        $gposChecked++
        $passwordsFound = @()
        
        # Check both Machine and User preference files
        foreach ($context in @("Machine\Preferences", "User\Preferences")) {
            foreach ($gppFile in $gppFiles) {
                $fullPath = Join-Path $gpoPath "$context\$gppFile"
                
                if (Test-Path $fullPath) {
                    try {
                        $content = Get-Content $fullPath -Raw
                        
                        # Look for cpassword attribute (GPP encrypted password)
                        if ($content -match 'cpassword\s*=\s*"([^"]+)"') {
                            $encryptedPasswords = [regex]::Matches($content, 'cpassword\s*=\s*"([^"]+)"')
                            
                            foreach ($match in $encryptedPasswords) {
                                $encryptedPassword = $match.Groups[1].Value
                                
                                # Extract additional context
                                $userName = ""
                                $accountName = ""
                                
                                if ($content -match 'userName\s*=\s*"([^"]+)"') {
                                    $userName = $Matches[1]
                                }
                                if ($content -match 'accountName\s*=\s*"([^"]+)"') {
                                    $accountName = $Matches[1]
                                }
                                if ($content -match 'runAs\s*=\s*"([^"]+)"') {
                                    $userName = $Matches[1]
                                }
                                
                                $affectedAccount = if ($userName) { $userName } elseif ($accountName) { $accountName } else { "Unknown" }
                                
                                $passwordsFound += @{
                                    File = "$context\$gppFile"
                                    Account = $affectedAccount
                                    EncryptedPassword = $encryptedPassword.Substring(0, [Math]::Min(20, $encryptedPassword.Length)) + "..."
                                }
                            }
                        }
                    }
                    catch {
                        # Error reading file, skip
                    }
                }
            }
        }
        
        if ($passwordsFound.Count -gt 0) {
            $gposWithPasswords++
            
            $accountsList = ($passwordsFound | ForEach-Object { $_.Account }) -join ", "
            $filesList = ($passwordsFound | ForEach-Object { $_.File }) -join ", "
            
            $findings += @{
                ObjectName = $gpoName
                ObjectType = "GroupPolicy"
                RiskLevel = "Critical"
                Description = "GPO contains $($passwordsFound.Count) password(s) encrypted with known AES key in GPP files. Affected accounts: $accountsList. Files: $filesList. These passwords can be easily decrypted by any domain user."
                Remediation = "1. IMMEDIATELY remove these GPP files or the cpassword attributes. 2. Reset passwords for all affected accounts. 3. Use GPO to deploy scheduled tasks/services without embedded credentials. 4. Consider using Group Managed Service Accounts (gMSA) instead. 5. Microsoft has blocked creation of new GPP passwords but old ones remain."
                AffectedAttributes = @("cpassword", "GPPPassword", $filesList)
            }
        }
    }
    
    # Part 2: Check for "Store passwords using reversible encryption" in GPO files
    $reversibleEncryptionGPOs = @()
    
    foreach ($gpo in $gpos) {
        $gpoName = if ($gpo.DisplayName) { $gpo.DisplayName } else { $gpo.Id }
        $gpoId = $gpo.Id
        
        # Check GptTmpl.inf for security settings
        $gptTmplPath = "$sysvolPath\{$gpoId}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
        
        if (Test-Path $gptTmplPath) {
            try {
                $content = Get-Content $gptTmplPath -Raw -ErrorAction SilentlyContinue
                
                # Look for ClearTextPassword setting in [System Access] section
                if ($content -match "ClearTextPassword\s*=\s*1") {
                    $reversibleEncryptionGPOs += $gpoName
                }
            }
            catch {
                # Error reading file, skip
            }
        }
    }
    
    foreach ($gpoName in $reversibleEncryptionGPOs) {
        $findings += @{
            ObjectName = $gpoName
            ObjectType = "GroupPolicy"
            RiskLevel = "High"
            Description = "GPO has 'Store passwords using reversible encryption' enabled. This stores user passwords in a reversibly encrypted format in AD, equivalent to storing them in clear text."
            Remediation = "1. Disable 'Store passwords using reversible encryption' in this GPO. 2. Force all users to change their passwords after disabling this setting. 3. This setting should only be used if absolutely required for digest authentication."
            AffectedAttributes = @("ClearTextPassword", "ReversibleEncryption", "PasswordPolicy")
        }
    }
    
    # Part 3: Check Default Domain Policy for reversible encryption
    # Note: We can't directly check reversible encryption via LDAP, but we can check if it's configured in Default Domain Policy GPO
    $defaultDomainPolicyGuid = "{31B2F340-016D-11D2-945F-00C04FB984F9}"
    $defaultPolicyPath = "$sysvolPath\{$defaultDomainPolicyGuid}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
    
    if (Test-Path $defaultPolicyPath) {
        try {
            $content = Get-Content $defaultPolicyPath -Raw -ErrorAction SilentlyContinue
            
            if ($content -match "ClearTextPassword\s*=\s*1") {
                $findings += @{
                    ObjectName = "Default Domain Policy"
                    ObjectType = "PasswordPolicy"
                    RiskLevel = "Critical"
                    Description = "Domain-wide password policy has reversible encryption ENABLED! All user passwords in this domain are stored in a reversibly encrypted format, essentially clear text."
                    Remediation = "1. CRITICAL: Immediately disable reversible encryption in the Default Domain Policy. 2. Force ALL domain users to change their passwords. 3. Review why this was enabled - it's almost never necessary. 4. Audit all password access logs."
                    AffectedAttributes = @("ReversibleEncryptionEnabled", "msDS-PasswordSettings")
                }
            }
        }
        catch {
            # Couldn't check default domain policy
        }
    }
    
    # Part 4: Check for Fine-Grained Password Policies with reversible encryption
    try {
        $fgppObjects = Get-IVFineGrainedPasswordPolicy -DomainName $DomainName
        
        foreach ($fgpp in $fgppObjects) {
            if ($fgpp.ReversibleEncryptionEnabled -eq $true) {
                # Get names of objects this policy applies to
                $appliesTo = @()
                foreach ($targetDN in $fgpp.AppliesTo) {
                    try {
                        $targetEntry = [ADSI]"LDAP://$targetDN"
                        $targetName = $targetEntry.Properties["name"][0]
                        $appliesTo += $targetName
                        $targetEntry.Dispose()
                    }
                    catch {
                        $appliesTo += $targetDN
                    }
                }
                
                $appliesToStr = $appliesTo -join ", "
                
                $findings += @{
                    ObjectName = $fgpp.Name
                    ObjectType = "FineGrainedPasswordPolicy"
                    RiskLevel = "High"
                    Description = "Fine-Grained Password Policy has reversible encryption enabled. Applies to: $appliesToStr. Passwords for these users/groups are stored in reversible format."
                    Remediation = "1. Disable reversible encryption in this FGPP. 2. Force password changes for all affected users. 3. Review if digest authentication is truly required."
                    AffectedAttributes = @("ReversibleEncryptionEnabled", "msDS-PasswordSettingsPrecedence", "AppliesTo")
                }
            }
        }
    }
    catch {
        # Fine-grained password policies might not be available
    }
    
    # Calculate execution time
    $executionTime = ((Get-Date) - $startTime).TotalSeconds
    
    # Determine final score and status
    $score = 100  # Start with perfect score
    $status = "Success"
    $message = "GPO password security check completed."
    
    if ($findings.Count -gt 0) {
        $criticalCount = @($findings | Where-Object { $_.RiskLevel -eq "Critical" }).Count
        $highCount = @($findings | Where-Object { $_.RiskLevel -eq "High" }).Count
        
        if ($criticalCount -gt 0) {
            $score = 0
            $message = "CRITICAL: Found $criticalCount GPO(s) with easily decryptable passwords and $highCount with reversible encryption! Immediate remediation required."
        }
        else {
            $score = [Math]::Max(25, 100 - ($highCount * 25))
            $message = "WARNING: Found $highCount policy configurations with reversible password storage enabled."
        }
    }
    else {
        $message = "No GPP passwords or reversible encryption policies detected. Password storage configurations appear secure."
    }
    
    return @{
        CheckId = "AD-T2-004"
        Timestamp = (Get-Date).ToString("o")
        Status = $status
        Score = $score
        Severity = "High"
        Category = "CredentialExposure"
        Findings = $findings
        Message = $message
        AffectedObjects = $findings.Count
        IgnoredObjects = 0
        Metadata = @{
            Domain = $DomainName
            ExecutionTime = [Math]::Round($executionTime, 2)
            GPOsChecked = $gposChecked
            GPOsWithPasswords = $gposWithPasswords
            ReversibleEncryptionPolicies = $reversibleEncryptionGPOs.Count
        }
    }
}
catch {
    return @{
        CheckId = "AD-T2-004"
        Timestamp = (Get-Date).ToString("o")
        Status = "Error"
        Score = 0
        Severity = "High"
        Category = "CredentialExposure"
        Findings = @()
        Message = "Error executing GPO password check: $_"
        AffectedObjects = 0
        IgnoredObjects = 0
        Metadata = @{
            Domain = $DomainName
            ExecutionTime = 0.0
            ErrorDetails = $_.Exception.Message
        }
    }
}