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

# Functions are automatically available when dot-sourced
# No Export-ModuleMember needed for .ps1 files