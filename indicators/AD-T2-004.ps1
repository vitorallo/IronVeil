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
    
    # Import required module
    Import-Module ActiveDirectory -ErrorAction SilentlyContinue
    Import-Module GroupPolicy -ErrorAction SilentlyContinue
    
    if (-not $DomainName) {
        throw "Domain name could not be determined"
    }
    
    # Get domain information
    $domain = Get-ADDomain -Identity $DomainName
    $domainDN = $domain.DistinguishedName
    $domainNetBIOS = $domain.NetBIOSName
    
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
    
    # Get all GPOs
    try {
        $gpos = Get-GPO -All -Domain $DomainName
    }
    catch {
        $gpos = @()
        # Try alternative method using AD module
        $gpoContainer = "CN=Policies,CN=System,$domainDN"
        $gpoObjects = Get-ADObject -SearchBase $gpoContainer -Filter {objectClass -eq "groupPolicyContainer"} -Properties displayName, gPCFileSysPath
        
        foreach ($gpoObj in $gpoObjects) {
            $gpos += @{
                Id = $gpoObj.Name
                DisplayName = $gpoObj.displayName
                Path = $gpoObj.gPCFileSysPath
            }
        }
    }
    
    $gposChecked = 0
    $gposWithPasswords = 0
    
    foreach ($gpo in $gpos) {
        $gpoName = if ($gpo.DisplayName) { $gpo.DisplayName } else { $gpo.Id }
        $gpoId = if ($gpo.Id) { $gpo.Id } else { $gpo.Name }
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
    
    # Part 2: Check for "Store passwords using reversible encryption" policy
    $reversibleEncryptionGPOs = @()
    
    foreach ($gpo in $gpos) {
        $gpoName = if ($gpo.DisplayName) { $gpo.DisplayName } else { $gpo.Id }
        
        try {
            # Check if GPO has password policy settings
            if (Get-Command Get-GPOReport -ErrorAction SilentlyContinue) {
                $gpoReport = Get-GPOReport -Name $gpoName -ReportType Xml -Domain $DomainName -ErrorAction SilentlyContinue
                
                if ($gpoReport -match "ClearTextPassword.*true|ReversibleEncryption.*true|StoreClearTextPasswords.*1") {
                    $reversibleEncryptionGPOs += $gpoName
                }
            }
        }
        catch {
            # Alternative method: Check registry.pol files directly
            $gpoId = if ($gpo.Id) { $gpo.Id } else { $gpo.Name }
            $regPolPath = "$sysvolPath\{$gpoId}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
            
            if (Test-Path $regPolPath) {
                $content = Get-Content $regPolPath -Raw -ErrorAction SilentlyContinue
                if ($content -match "ClearTextPassword\s*=\s*1|PasswordComplexity\s*=\s*0.*ClearTextPassword") {
                    $reversibleEncryptionGPOs += $gpoName
                }
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
    try {
        $defaultDomainPolicy = Get-ADDefaultDomainPasswordPolicy -Identity $DomainName
        
        if ($defaultDomainPolicy.ReversibleEncryptionEnabled -eq $true) {
            $findings += @{
                ObjectName = "Default Domain Password Policy"
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
    
    # Part 4: Check for Fine-Grained Password Policies with reversible encryption
    try {
        $fgppObjects = Get-ADFineGrainedPasswordPolicy -Filter * -Properties * -ErrorAction SilentlyContinue
        
        foreach ($fgpp in $fgppObjects) {
            if ($fgpp.ReversibleEncryptionEnabled -eq $true) {
                $appliesTo = ($fgpp.AppliesTo | ForEach-Object { 
                    $obj = Get-ADObject $_ -Properties Name -ErrorAction SilentlyContinue
                    if ($obj) { $obj.Name } else { $_ }
                }) -join ", "
                
                $findings += @{
                    ObjectName = $fgpp.Name
                    ObjectType = "FineGrainedPasswordPolicy"
                    RiskLevel = "High"
                    Description = "Fine-Grained Password Policy has reversible encryption enabled. Applies to: $appliesTo. Passwords for these users/groups are stored in reversible format."
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