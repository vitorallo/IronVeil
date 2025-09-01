<#
.SYNOPSIS
IronVeil ADSI Helper Library - Lightweight AD operations without RSAT dependency

.DESCRIPTION
This library provides common Active Directory operations using System.DirectoryServices (ADSI)
eliminating the need for RSAT installation. Designed for standalone operation.

.NOTES
No external dependencies required - uses only .NET Framework components available on all Windows systems
#>

# Global configuration
$Script:ADSIConfig = @{
    PageSize = 1000
    Timeout = 120
    PropertiesToLoadAlways = @('distinguishedName', 'objectClass', 'objectGUID', 'whenCreated', 'whenChanged')
}

function Get-IVDomainInfo {
    <#
    .SYNOPSIS
    Gets current domain information without ActiveDirectory module
    
    .PARAMETER DomainName
    Optional domain name, defaults to current domain
    #>
    param(
        [string]$DomainName = $env:USERDNSDOMAIN
    )
    
    try {
        if (-not $DomainName) {
            # Try to get from computer's domain membership
            $computerSystem = Get-WmiObject Win32_ComputerSystem
            $DomainName = $computerSystem.Domain
        }
        
        # Connect to RootDSE
        $rootDSE = New-Object System.DirectoryServices.DirectoryEntry("LDAP://RootDSE")
        
        # Get domain naming context
        $domainDN = $rootDSE.defaultNamingContext
        $configDN = $rootDSE.configurationNamingContext
        
        # Get domain object
        $domainEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$domainDN")
        
        # Extract domain information
        $domainInfo = @{
            DomainName = $DomainName
            DistinguishedName = $domainDN
            ConfigurationNamingContext = $configDN
            DomainSID = (New-Object System.Security.Principal.SecurityIdentifier($domainEntry.objectSid.Value, 0)).Value
            DomainEntry = $domainEntry
            RootDSE = $rootDSE
        }
        
        return $domainInfo
    }
    catch {
        throw "Failed to get domain information: $_"
    }
}

function Search-IVADObjects {
    <#
    .SYNOPSIS
    Performs LDAP search without ActiveDirectory module
    
    .PARAMETER Filter
    LDAP filter string
    
    .PARAMETER SearchBase
    Distinguished name of search base (optional, defaults to domain root)
    
    .PARAMETER Properties
    Array of properties to retrieve
    
    .PARAMETER Scope
    Search scope: Base, OneLevel, or Subtree (default)
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Filter,
        
        [string]$SearchBase,
        
        [string[]]$Properties = @(),
        
        [System.DirectoryServices.SearchScope]$Scope = 'Subtree',
        
        [int]$PageSize = 1000,
        
        [int]$SizeLimit = 0
    )
    
    try {
        # Get domain info if SearchBase not provided
        if (-not $SearchBase) {
            $domainInfo = Get-IVDomainInfo
            $SearchBase = $domainInfo.DistinguishedName
        }
        
        # Create directory searcher
        $searchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$SearchBase")
        $searcher = New-Object System.DirectoryServices.DirectorySearcher($searchRoot)
        
        # Configure searcher
        $searcher.Filter = $Filter
        $searcher.SearchScope = $Scope
        $searcher.PageSize = $PageSize
        
        if ($SizeLimit -gt 0) {
            $searcher.SizeLimit = $SizeLimit
        }
        
        # Add properties to load
        $allProperties = $Script:ADSIConfig.PropertiesToLoadAlways + $Properties | Select-Object -Unique
        foreach ($prop in $allProperties) {
            [void]$searcher.PropertiesToLoad.Add($prop)
        }
        
        # Perform search
        $results = $searcher.FindAll()
        
        # Convert results to PowerShell objects
        $objects = @()
        foreach ($result in $results) {
            $obj = [PSCustomObject]@{}
            
            foreach ($prop in $result.Properties.PropertyNames) {
                $value = $result.Properties[$prop]
                
                # Handle different property types
                if ($value.Count -eq 1) {
                    # Single value
                    $obj | Add-Member -NotePropertyName $prop -NotePropertyValue $value[0]
                }
                elseif ($value.Count -gt 1) {
                    # Multi-value
                    $obj | Add-Member -NotePropertyName $prop -NotePropertyValue @($value)
                }
                else {
                    # No value
                    $obj | Add-Member -NotePropertyName $prop -NotePropertyValue $null
                }
            }
            
            # Add path for reference
            $obj | Add-Member -NotePropertyName 'ADSIPath' -NotePropertyValue $result.Path
            
            $objects += $obj
        }
        
        # Clean up
        $results.Dispose()
        $searcher.Dispose()
        $searchRoot.Dispose()
        
        return $objects
    }
    catch {
        throw "LDAP search failed: $_"
    }
}

function Get-IVADUser {
    <#
    .SYNOPSIS
    Gets AD users without ActiveDirectory module
    
    .PARAMETER Filter
    Optional LDAP filter for users
    
    .PARAMETER Properties
    Additional properties to retrieve
    #>
    param(
        [string]$Filter = "(objectClass=user)",
        [string[]]$Properties = @()
    )
    
    # Ensure we're filtering for user objects
    if ($Filter -notlike "*objectClass=user*") {
        $Filter = "(&(objectClass=user)(objectCategory=person)$Filter)"
    }
    
    # Common user properties
    $userProperties = @('sAMAccountName', 'userPrincipalName', 'memberOf', 'userAccountControl', 
                       'lastLogonTimestamp', 'pwdLastSet', 'accountExpires', 'adminCount',
                       'servicePrincipalName', 'msDS-AllowedToDelegateTo') + $Properties
    
    return Search-IVADObjects -Filter $Filter -Properties $userProperties
}

function Get-IVADComputer {
    <#
    .SYNOPSIS
    Gets AD computers without ActiveDirectory module
    
    .PARAMETER Filter
    Optional LDAP filter for computers
    
    .PARAMETER Properties
    Additional properties to retrieve
    #>
    param(
        [string]$Filter = "(objectClass=computer)",
        [string[]]$Properties = @()
    )
    
    # Ensure we're filtering for computer objects
    if ($Filter -notlike "*objectClass=computer*") {
        $Filter = "(&(objectClass=computer)$Filter)"
    }
    
    # Common computer properties
    $computerProperties = @('sAMAccountName', 'dNSHostName', 'operatingSystem', 
                           'operatingSystemVersion', 'userAccountControl', 'servicePrincipalName',
                           'msDS-AllowedToActOnBehalfOfOtherIdentity', 'lastLogonTimestamp',
                           'primaryGroupID') + $Properties
    
    return Search-IVADObjects -Filter $Filter -Properties $computerProperties
}

function Get-IVADGroup {
    <#
    .SYNOPSIS
    Gets AD groups without ActiveDirectory module
    
    .PARAMETER Filter
    Optional LDAP filter for groups
    
    .PARAMETER Properties
    Additional properties to retrieve
    #>
    param(
        [string]$Filter = "(objectClass=group)",
        [string[]]$Properties = @()
    )
    
    # Ensure we're filtering for group objects
    if ($Filter -notlike "*objectClass=group*") {
        $Filter = "(&(objectClass=group)$Filter)"
    }
    
    # Common group properties
    $groupProperties = @('sAMAccountName', 'member', 'memberOf', 'groupType', 
                        'adminCount', 'objectSid') + $Properties
    
    return Search-IVADObjects -Filter $Filter -Properties $groupProperties
}

function Get-IVADDomainController {
    <#
    .SYNOPSIS
    Gets domain controllers without ActiveDirectory module
    #>
    param(
        [string]$DomainName = $env:USERDNSDOMAIN
    )
    
    try {
        $domainInfo = Get-IVDomainInfo -DomainName $DomainName
        
        # Search for computer objects with primary group ID 516 (Domain Controllers)
        $filter = "(&(objectClass=computer)(primaryGroupID=516))"
        
        $dcProperties = @('sAMAccountName', 'dNSHostName', 'operatingSystem', 
                         'operatingSystemVersion', 'serverReference', 'lastLogonTimestamp')
        
        $dcs = Search-IVADObjects -Filter $filter -Properties $dcProperties
        
        return $dcs
    }
    catch {
        throw "Failed to get domain controllers: $_"
    }
}

function Convert-IVFileTimeToDateTime {
    <#
    .SYNOPSIS
    Converts AD FileTime (Int64) to DateTime
    #>
    param(
        [Int64]$FileTime
    )
    
    if ($FileTime -eq 0 -or $FileTime -eq 0x7FFFFFFFFFFFFFFF) {
        return $null
    }
    
    try {
        return [DateTime]::FromFileTimeUtc($FileTime)
    }
    catch {
        return $null
    }
}

function Test-IVUserAccountControl {
    <#
    .SYNOPSIS
    Tests UserAccountControl flags
    
    .PARAMETER UAC
    UserAccountControl value
    
    .PARAMETER Flag
    Flag to test (e.g., 'ACCOUNTDISABLE', 'DONT_EXPIRE_PASSWORD', 'TRUSTED_FOR_DELEGATION')
    #>
    param(
        [int]$UAC,
        [string]$Flag
    )
    
    $flags = @{
        'SCRIPT' = 0x0001
        'ACCOUNTDISABLE' = 0x0002
        'HOMEDIR_REQUIRED' = 0x0008
        'LOCKOUT' = 0x0010
        'PASSWD_NOTREQD' = 0x0020
        'PASSWD_CANT_CHANGE' = 0x0040
        'ENCRYPTED_TEXT_PWD_ALLOWED' = 0x0080
        'TEMP_DUPLICATE_ACCOUNT' = 0x0100
        'NORMAL_ACCOUNT' = 0x0200
        'INTERDOMAIN_TRUST_ACCOUNT' = 0x0800
        'WORKSTATION_TRUST_ACCOUNT' = 0x1000
        'SERVER_TRUST_ACCOUNT' = 0x2000
        'DONT_EXPIRE_PASSWORD' = 0x10000
        'MNS_LOGON_ACCOUNT' = 0x20000
        'SMARTCARD_REQUIRED' = 0x40000
        'TRUSTED_FOR_DELEGATION' = 0x80000
        'NOT_DELEGATED' = 0x100000
        'USE_DES_KEY_ONLY' = 0x200000
        'DONT_REQ_PREAUTH' = 0x400000
        'PASSWORD_EXPIRED' = 0x800000
        'TRUSTED_TO_AUTH_FOR_DELEGATION' = 0x1000000
        'NO_AUTH_DATA_REQUIRED' = 0x2000000
    }
    
    if ($flags.ContainsKey($Flag)) {
        return ($UAC -band $flags[$Flag]) -ne 0
    }
    
    return $false
}

function Get-IVWellKnownSID {
    <#
    .SYNOPSIS
    Returns well-known SIDs for privileged groups
    #>
    param(
        [string]$DomainSID
    )
    
    $wellKnownSIDs = @{
        # Built-in groups
        'Administrators' = 'S-1-5-32-544'
        'Account Operators' = 'S-1-5-32-548'
        'Server Operators' = 'S-1-5-32-549'
        'Print Operators' = 'S-1-5-32-550'
        'Backup Operators' = 'S-1-5-32-551'
        'Replicators' = 'S-1-5-32-552'
    }
    
    # Add domain-specific SIDs if domain SID provided
    if ($DomainSID) {
        $wellKnownSIDs['Domain Admins'] = "$DomainSID-512"
        $wellKnownSIDs['Domain Controllers'] = "$DomainSID-516"
        $wellKnownSIDs['Schema Admins'] = "$DomainSID-518"
        $wellKnownSIDs['Enterprise Admins'] = "$DomainSID-519"
        $wellKnownSIDs['Group Policy Creator Owners'] = "$DomainSID-520"
        $wellKnownSIDs['Read-only Domain Controllers'] = "$DomainSID-521"
        $wellKnownSIDs['Enterprise Read-only Domain Controllers'] = "$DomainSID-527"
    }
    
    return $wellKnownSIDs
}

function Get-IVGroupMembers {
    <#
    .SYNOPSIS
    Gets members of an AD group using ADSI
    
    .PARAMETER GroupDN
    Distinguished name of the group
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$GroupDN
    )
    
    try {
        $group = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$GroupDN")
        $members = @()
        
        # Get member DNs
        $memberDNs = $group.member
        
        if ($memberDNs) {
            foreach ($memberDN in $memberDNs) {
                try {
                    $memberEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$memberDN")
                    $members += [PSCustomObject]@{
                        DistinguishedName = $memberDN
                        Name = $memberEntry.name.Value
                        ObjectClass = $memberEntry.objectClass[-1]
                        SamAccountName = $memberEntry.sAMAccountName.Value
                    }
                    $memberEntry.Dispose()
                }
                catch {
                    # Member might be from another domain or deleted
                    $members += [PSCustomObject]@{
                        DistinguishedName = $memberDN
                        Name = "Unknown"
                        ObjectClass = "Unknown"
                        SamAccountName = "Unknown"
                    }
                }
            }
        }
        
        $group.Dispose()
        return $members
    }
    catch {
        throw "Failed to get group members: $_"
    }
}

function Get-IVDomainACL {
    <#
    .SYNOPSIS
    Gets the ACL of the domain object without ActiveDirectory module
    
    .PARAMETER DomainDN
    Distinguished name of the domain (optional, defaults to current domain)
    #>
    param(
        [string]$DomainDN
    )
    
    try {
        if (-not $DomainDN) {
            $domainInfo = Get-IVDomainInfo
            $DomainDN = $domainInfo.DistinguishedName
        }
        
        # Get the domain object
        $domainEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DomainDN")
        
        # Get the security descriptor
        $security = $domainEntry.ObjectSecurity
        
        return $security
    }
    catch {
        throw "Failed to get domain ACL: $_"
    }
}

function Get-IVObjectBySID {
    <#
    .SYNOPSIS
    Gets an AD object by its SID without ActiveDirectory module
    
    .PARAMETER SID
    The SID to search for
    
    .PARAMETER Properties
    Additional properties to retrieve
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$SID,
        
        [string[]]$Properties = @()
    )
    
    try {
        # Create SID binding string
        $sidBind = "<SID=$SID>"
        
        # Try to bind directly to the object
        $objEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$sidBind")
        
        if ($objEntry.Name) {
            $obj = [PSCustomObject]@{
                DistinguishedName = $objEntry.distinguishedName.Value
                ObjectClass = $objEntry.objectClass.Value[-1]
                SamAccountName = $objEntry.sAMAccountName.Value
                Name = $objEntry.name.Value
                ObjectSID = $SID
            }
            
            # Add additional properties
            foreach ($prop in $Properties) {
                if ($objEntry.Properties.Contains($prop)) {
                    $value = $objEntry.Properties[$prop].Value
                    $obj | Add-Member -NotePropertyName $prop -NotePropertyValue $value
                }
            }
            
            $objEntry.Dispose()
            return $obj
        }
        else {
            # Fallback to LDAP search
            $filter = "(objectSID=$SID)"
            $results = Search-IVADObjects -Filter $filter -Properties $Properties
            return $results | Select-Object -First 1
        }
    }
    catch {
        # Try alternate search if direct binding fails
        try {
            # Convert SID to escaped format for LDAP filter
            $sidObj = New-Object System.Security.Principal.SecurityIdentifier($SID)
            $sidBytes = New-Object byte[] $sidObj.BinaryLength
            $sidObj.GetBinaryForm($sidBytes, 0)
            $sidHex = ($sidBytes | ForEach-Object { "\{0:x2}" -f $_ }) -join ""
            
            $filter = "(objectSID=$sidHex)"
            $results = Search-IVADObjects -Filter $filter -Properties $Properties
            return $results | Select-Object -First 1
        }
        catch {
            return $null
        }
    }
}

function Get-IVObjectByName {
    <#
    .SYNOPSIS
    Gets an AD object by its name without ActiveDirectory module
    
    .PARAMETER Name
    The name to search for (sAMAccountName or CN)
    
    .PARAMETER Properties
    Additional properties to retrieve
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name,
        
        [string[]]$Properties = @()
    )
    
    try {
        # Clean up the name if it's in domain\user format
        if ($Name -like "*\*") {
            $Name = $Name.Split('\')[-1]
        }
        
        # Search for the object
        $filter = "(|(sAMAccountName=$Name)(cn=$Name)(name=$Name))"
        $results = Search-IVADObjects -Filter $filter -Properties $Properties
        
        return $results | Select-Object -First 1
    }
    catch {
        return $null
    }
}

function Test-IVDCService {
    <#
    .SYNOPSIS
    Tests if a service is running on domain controllers
    
    .PARAMETER ServiceName
    Name of the service to check
    
    .PARAMETER DomainControllers
    Optional array of DC names, otherwise gets all DCs
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$ServiceName,
        
        [string[]]$DomainControllers = @()
    )
    
    try {
        if ($DomainControllers.Count -eq 0) {
            # Get all domain controllers
            $dcs = Get-IVADDomainController
            $DomainControllers = $dcs | ForEach-Object { 
                if ($_.dNSHostName) { 
                    if ($_.dNSHostName -is [Array]) { $_.dNSHostName[0] } else { $_.dNSHostName }
                } else { 
                    $_.name 
                }
            }
        }
        
        $results = @()
        foreach ($dc in $DomainControllers) {
            try {
                # Try to get service status via WMI
                $service = Get-WmiObject -Class Win32_Service -ComputerName $dc -Filter "Name='$ServiceName'" -ErrorAction Stop
                
                $results += [PSCustomObject]@{
                    DomainController = $dc
                    ServiceName = $ServiceName
                    Status = $service.State
                    StartMode = $service.StartMode
                    Running = ($service.State -eq 'Running')
                }
            }
            catch {
                # If WMI fails, try alternative method or mark as unknown
                $results += [PSCustomObject]@{
                    DomainController = $dc
                    ServiceName = $ServiceName
                    Status = "Unknown"
                    StartMode = "Unknown"
                    Running = $false
                    Error = $_.Exception.Message
                }
            }
        }
        
        return $results
    }
    catch {
        throw "Failed to test DC service: $_"
    }
}

function Get-IVCertificateTemplates {
    <#
    .SYNOPSIS
    Gets certificate templates without ActiveDirectory module
    
    .PARAMETER ConfigurationDN
    Optional configuration naming context
    #>
    param(
        [string]$ConfigurationDN
    )
    
    try {
        if (-not $ConfigurationDN) {
            $domainInfo = Get-IVDomainInfo
            $ConfigurationDN = $domainInfo.ConfigurationNamingContext
        }
        
        # Build the certificate templates container path
        $templateContainer = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigurationDN"
        
        # Search for certificate templates
        $filter = "(objectClass=pKICertificateTemplate)"
        $properties = @(
            'cn', 'displayName', 'msPKI-Certificate-Name-Flag', 'msPKI-Enrollment-Flag',
            'msPKI-RA-Signature', 'msPKI-Template-Schema-Version', 'pKIExtendedKeyUsage',
            'msPKI-Certificate-Application-Policy', 'msPKI-Cert-Template-OID',
            'nTSecurityDescriptor', 'whenCreated', 'whenChanged', 'revision'
        )
        
        $templates = Search-IVADObjects -Filter $filter -SearchBase $templateContainer -Properties $properties
        
        return $templates
    }
    catch {
        # Certificate Services might not be installed
        return @()
    }
}

function Get-IVTemplateACL {
    <#
    .SYNOPSIS
    Gets the ACL of a certificate template
    
    .PARAMETER TemplateDN
    Distinguished name of the template
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$TemplateDN
    )
    
    try {
        $templateEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$TemplateDN")
        $security = $templateEntry.ObjectSecurity
        $templateEntry.Dispose()
        
        return $security
    }
    catch {
        throw "Failed to get template ACL: $_"
    }
}

function Get-IVGPO {
    <#
    .SYNOPSIS
    Gets Group Policy Objects without ActiveDirectory module
    
    .PARAMETER DomainName
    Domain name to query
    
    .PARAMETER All
    Get all GPOs
    
    .PARAMETER Name
    Get specific GPO by display name
    #>
    param(
        [string]$DomainName = $env:USERDNSDOMAIN,
        [switch]$All,
        [string]$Name
    )
    
    try {
        $domainInfo = Get-IVDomainInfo -DomainName $DomainName
        $gpoContainer = "CN=Policies,CN=System,$($domainInfo.DistinguishedName)"
        
        # Build filter
        $filter = "(objectClass=groupPolicyContainer)"
        if ($Name) {
            $filter = "(&$filter(displayName=$Name))"
        }
        
        # Search for GPOs
        $searcher = [adsisearcher]$filter
        $searcher.SearchRoot = [ADSI]"LDAP://$gpoContainer"
        $searcher.PageSize = 1000
        $searcher.PropertiesToLoad.AddRange(@('name', 'displayName', 'gPCFileSysPath', 
                                              'gPCMachineExtensionNames', 'gPCUserExtensionNames',
                                              'versionNumber', 'flags', 'whenCreated', 'whenChanged'))
        
        $results = $searcher.FindAll()
        $gpos = @()
        
        foreach ($result in $results) {
            $props = $result.Properties
            $gpo = [PSCustomObject]@{
                Id = $($props['name'][0])
                DisplayName = $($props['displayname'][0])
                Path = $($props['gpcfilesyspath'][0])
                DistinguishedName = $result.Path -replace '^LDAP://', ''
                MachineExtensions = $($props['gpcmachineextensionnames'][0])
                UserExtensions = $($props['gpcuserextensionnames'][0])
                Version = $($props['versionnumber'][0])
                Flags = $($props['flags'][0])
                WhenCreated = $($props['whencreated'][0])
                WhenChanged = $($props['whenchanged'][0])
            }
            $gpos += $gpo
        }
        
        $results.Dispose()
        $searcher.Dispose()
        
        return $gpos
    }
    catch {
        throw "Failed to get GPOs: $_"
    }
}

function Get-IVGPOLink {
    <#
    .SYNOPSIS
    Gets GPO links from OUs and domain root
    
    .PARAMETER DomainName
    Domain name to query
    #>
    param(
        [string]$DomainName = $env:USERDNSDOMAIN
    )
    
    try {
        $domainInfo = Get-IVDomainInfo -DomainName $DomainName
        
        # Search for objects with gPLink attribute
        $filter = "(gPLink=*)"
        $searcher = [adsisearcher]$filter
        $searcher.SearchRoot = [ADSI]"LDAP://$($domainInfo.DistinguishedName)"
        $searcher.PageSize = 1000
        $searcher.PropertiesToLoad.AddRange(@('distinguishedName', 'gPLink', 'gPOptions', 'name'))
        
        $results = $searcher.FindAll()
        $links = @()
        
        foreach ($result in $results) {
            $props = $result.Properties
            $gPLink = $props['gplink'][0]
            
            # Parse gPLink attribute (format: [LDAP://CN={GUID},CN=Policies,...;FLAGS])
            $pattern = '\[LDAP://([^;]+);(\d+)\]'
            $matches = [regex]::Matches($gPLink, $pattern)
            
            foreach ($match in $matches) {
                $gpoDN = $match.Groups[1].Value
                $flags = [int]$match.Groups[2].Value
                
                # Extract GPO GUID from DN
                if ($gpoDN -match 'CN=\{([^}]+)\}') {
                    $gpoId = $Matches[1]
                    
                    $link = [PSCustomObject]@{
                        Target = $result.Path -replace '^LDAP://', ''
                        TargetName = $($props['name'][0])
                        GpoId = $gpoId
                        GpoDN = $gpoDN
                        Enforced = ($flags -band 2) -eq 2
                        LinkEnabled = ($flags -band 1) -eq 0
                    }
                    $links += $link
                }
            }
        }
        
        $results.Dispose()
        $searcher.Dispose()
        
        return $links
    }
    catch {
        throw "Failed to get GPO links: $_"
    }
}

function Get-IVDefaultDomainPasswordPolicy {
    <#
    .SYNOPSIS
    Gets default domain password policy without ActiveDirectory module
    
    .PARAMETER DomainName
    Domain name to query
    #>
    param(
        [string]$DomainName = $env:USERDNSDOMAIN
    )
    
    try {
        $domainInfo = Get-IVDomainInfo -DomainName $DomainName
        
        # Get domain object
        $domainEntry = [ADSI]"LDAP://$($domainInfo.DistinguishedName)"
        
        $policy = [PSCustomObject]@{
            MinPasswordLength = $domainEntry.minPwdLength.Value
            PasswordHistoryCount = $domainEntry.pwdHistoryLength.Value
            MaxPasswordAge = if ($domainEntry.maxPwdAge.Value) { 
                [TimeSpan]::FromTicks([Math]::Abs($domainEntry.maxPwdAge.Value))
            } else { $null }
            MinPasswordAge = if ($domainEntry.minPwdAge.Value) {
                [TimeSpan]::FromTicks([Math]::Abs($domainEntry.minPwdAge.Value))
            } else { $null }
            ComplexityEnabled = $null  # Not directly available via LDAP
            ReversibleEncryptionEnabled = $null  # Not directly available via LDAP
            LockoutDuration = if ($domainEntry.lockoutDuration.Value) {
                [TimeSpan]::FromTicks([Math]::Abs($domainEntry.lockoutDuration.Value))
            } else { $null }
            LockoutObservationWindow = if ($domainEntry.lockOutObservationWindow.Value) {
                [TimeSpan]::FromTicks([Math]::Abs($domainEntry.lockOutObservationWindow.Value))
            } else { $null }
            LockoutThreshold = $domainEntry.lockoutThreshold.Value
        }
        
        $domainEntry.Dispose()
        
        return $policy
    }
    catch {
        throw "Failed to get password policy: $_"
    }
}

function Get-IVFineGrainedPasswordPolicy {
    <#
    .SYNOPSIS
    Gets Fine-Grained Password Policies without ActiveDirectory module
    
    .PARAMETER DomainName
    Domain name to query
    #>
    param(
        [string]$DomainName = $env:USERDNSDOMAIN
    )
    
    try {
        $domainInfo = Get-IVDomainInfo -DomainName $DomainName
        $psoContainer = "CN=Password Settings Container,CN=System,$($domainInfo.DistinguishedName)"
        
        # Check if PSO container exists
        try {
            $test = [ADSI]"LDAP://$psoContainer"
            $test.Dispose()
        }
        catch {
            # No PSO container, return empty array
            return @()
        }
        
        # Search for PSO objects
        $filter = "(objectClass=msDS-PasswordSettings)"
        $searcher = [adsisearcher]$filter
        $searcher.SearchRoot = [ADSI]"LDAP://$psoContainer"
        $searcher.PageSize = 1000
        $searcher.PropertiesToLoad.AddRange(@('name', 'msDS-PasswordSettingsPrecedence',
                                              'msDS-MinimumPasswordLength', 'msDS-PasswordHistoryLength',
                                              'msDS-MaximumPasswordAge', 'msDS-MinimumPasswordAge',
                                              'msDS-PasswordComplexityEnabled', 'msDS-PasswordReversibleEncryptionEnabled',
                                              'msDS-LockoutThreshold', 'msDS-LockoutDuration',
                                              'msDS-LockoutObservationWindow', 'msDS-PSOAppliesTo'))
        
        $results = $searcher.FindAll()
        $policies = @()
        
        foreach ($result in $results) {
            $props = $result.Properties
            
            $policy = [PSCustomObject]@{
                Name = $($props['name'][0])
                Precedence = $($props['msds-passwordsettingsprecedence'][0])
                MinPasswordLength = $($props['msds-minimumpasswordlength'][0])
                PasswordHistoryCount = $($props['msds-passwordhistorylength'][0])
                MaxPasswordAge = if ($props['msds-maximumpasswordage'][0]) {
                    [TimeSpan]::FromTicks([Math]::Abs([long]$props['msds-maximumpasswordage'][0]))
                } else { $null }
                MinPasswordAge = if ($props['msds-minimumpasswordage'][0]) {
                    [TimeSpan]::FromTicks([Math]::Abs([long]$props['msds-minimumpasswordage'][0]))
                } else { $null }
                ComplexityEnabled = $($props['msds-passwordcomplexityenabled'][0])
                ReversibleEncryptionEnabled = $($props['msds-passwordreversibleencryptionenabled'][0])
                LockoutThreshold = $($props['msds-lockoutthreshold'][0])
                LockoutDuration = if ($props['msds-lockoutduration'][0]) {
                    [TimeSpan]::FromTicks([Math]::Abs([long]$props['msds-lockoutduration'][0]))
                } else { $null }
                LockoutObservationWindow = if ($props['msds-lockoutobservationwindow'][0]) {
                    [TimeSpan]::FromTicks([Math]::Abs([long]$props['msds-lockoutobservationwindow'][0]))
                } else { $null }
                AppliesTo = @($props['msds-psoappliesto'] | ForEach-Object { $_ })
                DistinguishedName = $result.Path -replace '^LDAP://', ''
            }
            
            $policies += $policy
        }
        
        $results.Dispose()
        $searcher.Dispose()
        
        return $policies
    }
    catch {
        throw "Failed to get Fine-Grained Password Policies: $_"
    }
}

function Get-IVADOrganizationalUnit {
    <#
    .SYNOPSIS
    Gets AD Organizational Units without ActiveDirectory module
    
    .PARAMETER Filter
    LDAP filter for OUs
    
    .PARAMETER SearchBase
    Base DN to search from
    
    .PARAMETER SearchScope
    Search scope (Base, OneLevel, Subtree)
    #>
    param(
        [string]$Filter = "(objectClass=organizationalUnit)",
        [string]$SearchBase = "",
        [string]$SearchScope = "Subtree"
    )
    
    try {
        if (-not $SearchBase) {
            $domainInfo = Get-IVDomainInfo
            $SearchBase = $domainInfo.DistinguishedName
        }
        
        $searcher = [adsisearcher]$Filter
        $searcher.SearchRoot = [ADSI]"LDAP://$SearchBase"
        $searcher.PageSize = 1000
        $searcher.PropertiesToLoad.AddRange(@('name', 'distinguishedName', 'ou', 'description'))
        
        # Set search scope
        switch ($SearchScope) {
            "Base" { $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Base }
            "OneLevel" { $searcher.SearchScope = [System.DirectoryServices.SearchScope]::OneLevel }
            default { $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree }
        }
        
        $results = $searcher.FindAll()
        $ous = @()
        
        foreach ($result in $results) {
            $props = $result.Properties
            $ou = [PSCustomObject]@{
                Name = $($props['name'][0])
                DistinguishedName = $result.Path -replace '^LDAP://', ''
                Description = $($props['description'][0])
            }
            $ous += $ou
        }
        
        $results.Dispose()
        $searcher.Dispose()
        
        return $ous
    }
    catch {
        throw "Failed to get OUs: $_"
    }
}

function Get-IVADObjectACL {
    <#
    .SYNOPSIS
    Gets ACL for an AD object without ActiveDirectory module
    
    .PARAMETER DistinguishedName
    DN of the object to get ACL for
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$DistinguishedName
    )
    
    try {
        $adsiObject = [ADSI]"LDAP://$DistinguishedName"
        $security = $adsiObject.ObjectSecurity
        
        # Create a custom object with essential ACL info
        $acl = [PSCustomObject]@{
            Owner = $security.Owner
            Group = $security.Group
            Access = @()
        }
        
        foreach ($ace in $security.Access) {
            $customAce = [PSCustomObject]@{
                IdentityReference = $ace.IdentityReference
                AccessControlType = $ace.AccessControlType
                ActiveDirectoryRights = $ace.ActiveDirectoryRights
                ObjectType = $ace.ObjectType
                InheritedObjectType = $ace.InheritedObjectType
                InheritanceType = $ace.InheritanceType
                PropagationFlags = $ace.PropagationFlags
                IsInherited = $ace.IsInherited
            }
            $acl.Access += $customAce
        }
        
        $adsiObject.Dispose()
        
        return $acl
    }
    catch {
        throw "Failed to get ACL: $_"
    }
}

function Get-IVADObject {
    <#
    .SYNOPSIS
    Gets AD object by filter or identity without ActiveDirectory module
    
    .PARAMETER Filter
    LDAP filter
    
    .PARAMETER Identity
    Object identity (DN, SID, or sAMAccountName)
    
    .PARAMETER Properties
    Additional properties to retrieve
    #>
    param(
        [string]$Filter,
        [string]$Identity,
        [string[]]$Properties = @()
    )
    
    try {
        # Build filter based on parameters
        if ($Identity) {
            if ($Identity -match "^S-1-") {
                # SID
                $Filter = "(objectSID=$Identity)"
            }
            elseif ($Identity -match "^CN=|^OU=|^DC=") {
                # DN - get directly
                $adsiObject = [ADSI]"LDAP://$Identity"
                
                $obj = [PSCustomObject]@{
                    DistinguishedName = $Identity
                    Name = $adsiObject.Properties["name"][0]
                    ObjectClass = $adsiObject.Properties["objectClass"][-1]
                    ObjectSID = if ($adsiObject.Properties["objectSID"][0]) {
                        (New-Object System.Security.Principal.SecurityIdentifier($adsiObject.Properties["objectSID"][0], 0)).Value
                    } else { $null }
                }
                
                # Add requested properties
                foreach ($prop in $Properties) {
                    $obj | Add-Member -NotePropertyName $prop -NotePropertyValue $adsiObject.Properties[$prop][0] -Force
                }
                
                $adsiObject.Dispose()
                return $obj
            }
            else {
                # sAMAccountName
                $Filter = "(sAMAccountName=$Identity)"
            }
        }
        
        if (-not $Filter) {
            throw "Must specify either Filter or Identity"
        }
        
        # Search for object
        $results = Search-IVADObjects -Filter $Filter -Properties $Properties
        
        if ($results.Count -eq 0) {
            return $null
        }
        
        return $results[0]
    }
    catch {
        throw "Failed to get AD object: $_"
    }
}

function Get-IVADGroupMember {
    <#
    .SYNOPSIS
    Gets members of an AD group without ActiveDirectory module
    
    .PARAMETER Identity
    Group identity (DN, SID, or sAMAccountName)
    
    .PARAMETER Recursive
    Get members recursively
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Identity,
        [switch]$Recursive
    )
    
    try {
        $members = @()
        $processedGroups = @{}
        
        function Get-GroupMembersInternal {
            param($GroupDN)
            
            if ($processedGroups.ContainsKey($GroupDN)) {
                return
            }
            $processedGroups[$GroupDN] = $true
            
            try {
                $groupEntry = [ADSI]"LDAP://$GroupDN"
                $memberDNs = @($groupEntry.Properties["member"])
                $groupEntry.Dispose()
                
                foreach ($memberDN in $memberDNs) {
                    if (-not $memberDN) { continue }
                    
                    try {
                        $memberEntry = [ADSI]"LDAP://$memberDN"
                        $objectClass = $memberEntry.Properties["objectClass"][-1]
                        
                        $memberObj = [PSCustomObject]@{
                            DistinguishedName = $memberDN
                            Name = $memberEntry.Properties["name"][0]
                            SamAccountName = $memberEntry.Properties["sAMAccountName"][0]
                            ObjectClass = $objectClass
                            SID = if ($memberEntry.Properties["objectSID"][0]) {
                                (New-Object System.Security.Principal.SecurityIdentifier($memberEntry.Properties["objectSID"][0], 0)).Value
                            } else { $null }
                        }
                        
                        $members += $memberObj
                        $memberEntry.Dispose()
                        
                        # If recursive and this is a group, get its members too
                        if ($Recursive -and $objectClass -eq "group") {
                            Get-GroupMembersInternal -GroupDN $memberDN
                        }
                    }
                    catch {
                        # Skip member that can't be accessed
                    }
                }
            }
            catch {
                # Skip group that can't be accessed
            }
        }
        
        # Get the group DN first
        $groupDN = $null
        if ($Identity -match "^CN=|^OU=|^DC=") {
            $groupDN = $Identity
        }
        elseif ($Identity -match "^S-1-") {
            # Search by SID
            $sidBytes = (New-Object System.Security.Principal.SecurityIdentifier($Identity)).GetBinaryForm()
            $hexSid = ($sidBytes | ForEach-Object { "\{0:x2}" -f $_ }) -join ""
            $result = Search-IVADObjects -Filter "(objectSID=$hexSid)" -Properties @('distinguishedName')
            if ($result -and $result.Count -gt 0) {
                $groupDN = $result[0].DistinguishedName
            }
        }
        else {
            # Search by sAMAccountName
            $result = Search-IVADObjects -Filter "(sAMAccountName=$Identity)" -Properties @('distinguishedName')
            if ($result -and $result.Count -gt 0) {
                $groupDN = $result[0].DistinguishedName
            }
        }
        
        if ($groupDN) {
            Get-GroupMembersInternal -GroupDN $groupDN
        }
        
        return $members
    }
    catch {
        throw "Failed to get group members: $_"
    }
}

# Functions are automatically available when dot-sourced
# No Export-ModuleMember needed for .ps1 files