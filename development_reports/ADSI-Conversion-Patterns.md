# ADSI Conversion Patterns for IronVeil

**Document**: ADSI Conversion Patterns  
**Purpose**: Convert PowerShell security rules from ActiveDirectory module to pure ADSI  
**Goal**: Eliminate RSAT dependency for truly standalone operation  
**Date**: August 31, 2025  

## Executive Summary

This document provides conversion patterns for migrating IronVeil security rules from the ActiveDirectory PowerShell module (RSAT dependency) to pure System.DirectoryServices (ADSI) implementation. This eliminates the need for users to install RSAT, making IronVeil a truly standalone security scanner.

## Why ADSI Over ActiveDirectory Module?

### Problems with ActiveDirectory Module:
- **Installation Barrier**: Requires RSAT installation (500MB+, admin rights)
- **User Experience**: "Please install RSAT first" = immediate abandonment
- **Deployment Complexity**: Different installation methods per Windows version
- **Corporate Restrictions**: Often blocked by IT policies
- **Dependencies**: Not available by default on workstations

### Benefits of ADSI Approach:
- ✅ **Truly Standalone**: Works on any domain-joined Windows machine
- ✅ **No Dependencies**: Uses .NET Framework already present
- ✅ **Instant Deployment**: Download and run immediately
- ✅ **Better Performance**: Direct LDAP queries, no PowerShell overhead
- ✅ **Lower Resource Usage**: Minimal memory footprint
- ✅ **Corporate Friendly**: No additional software installation required

## Core Conversion Patterns

### 1. Module Import Replacement

**Before (Requires RSAT):**
```powershell
Import-Module ActiveDirectory -ErrorAction SilentlyContinue
```

**After (No Dependencies):**
```powershell
# Load helper library
$helperPath = Join-Path $PSScriptRoot "IronVeil-ADSIHelper.ps1"
. $helperPath
```

### 2. Domain Information

**Before:**
```powershell
$domain = Get-ADDomain -Identity $DomainName
$domainDN = $domain.DistinguishedName
$domainSID = $domain.DomainSID
```

**After:**
```powershell
$domainInfo = Get-IVDomainInfo -DomainName $DomainName
$domainDN = $domainInfo.DistinguishedName
$domainSID = $domainInfo.DomainSID
```

### 3. User Queries

**Before:**
```powershell
$users = Get-ADUser -Filter {Enabled -eq $true} -Properties memberOf, lastLogonDate
```

**After:**
```powershell
$filter = "(&(objectClass=user)(objectCategory=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
$users = Search-IVADObjects -Filter $filter -Properties @('memberOf', 'lastLogonTimestamp')
```

### 4. Computer Queries

**Before:**
```powershell
$computers = Get-ADComputer -Filter {Enabled -eq $true} -Properties servicePrincipalName
```

**After:**
```powershell
$filter = "(&(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
$computers = Search-IVADObjects -Filter $filter -Properties @('servicePrincipalName')
```

### 5. Group Queries

**Before:**
```powershell
$groups = Get-ADGroup -Filter {GroupScope -eq "DomainLocal"} -Properties member
```

**After:**
```powershell
$filter = "(&(objectClass=group)(groupType:1.2.840.113556.1.4.803:=4))"
$groups = Search-IVADObjects -Filter $filter -Properties @('member')
```

### 6. Domain Controller Queries

**Before:**
```powershell
$dcs = Get-ADDomainController -Filter *
```

**After:**
```powershell
$dcs = Get-IVADDomainController
```

## Advanced Conversion Patterns

### 7. UserAccountControl Flag Testing

**Before:**
```powershell
if ($user.TrustedForDelegation) { }
```

**After:**
```powershell
if (Test-IVUserAccountControl -UAC $user.userAccountControl -Flag 'TRUSTED_FOR_DELEGATION') { }
```

### 8. LDAP Filter Translations

| ActiveDirectory Filter | ADSI LDAP Filter |
|----------------------|------------------|
| `{Enabled -eq $true}` | `(!(userAccountControl:1.2.840.113556.1.4.803:=2))` |
| `{Enabled -eq $false}` | `(userAccountControl:1.2.840.113556.1.4.803:=2)` |
| `{TrustedForDelegation -eq $true}` | `(userAccountControl:1.2.840.113556.1.4.803:=524288)` |
| `{PasswordNotRequired -eq $true}` | `(userAccountControl:1.2.840.113556.1.4.803:=32)` |
| `{SmartcardLogonRequired -eq $true}` | `(userAccountControl:1.2.840.113556.1.4.803:=262144)` |

### 9. Date/Time Handling

**Before:**
```powershell
$user.LastLogonDate
```

**After:**
```powershell
Convert-IVFileTimeToDateTime -FileTime ([Int64]$user.lastLogonTimestamp)
```

### 10. Group Membership

**Before:**
```powershell
$members = Get-ADGroupMember -Identity "Domain Admins"
```

**After:**
```powershell
$groupDN = "CN=Domain Admins,CN=Users,DC=domain,DC=com"
$members = Get-IVGroupMembers -GroupDN $groupDN
```

## Complete Rule Conversion Example

### Original Rule (Requires RSAT):
```powershell
Import-Module ActiveDirectory -ErrorAction SilentlyContinue

$domain = Get-ADDomain
$users = Get-ADUser -Filter {TrustedForDelegation -eq $true} -Properties memberOf

foreach ($user in $users) {
    if ($user.memberOf -contains "CN=Domain Admins,...") {
        # Process privileged user with delegation
    }
}
```

### Converted Rule (No Dependencies):
```powershell
. $PSScriptRoot\IronVeil-ADSIHelper.ps1

$domainInfo = Get-IVDomainInfo
$filter = "(userAccountControl:1.2.840.113556.1.4.803:=524288)"
$users = Search-IVADObjects -Filter $filter -Properties @('memberOf')

$privilegedGroupDN = "CN=Domain Admins,CN=Users,$($domainInfo.DistinguishedName)"

foreach ($user in $users) {
    if ($user.memberOf -contains $privilegedGroupDN) {
        # Process privileged user with delegation
    }
}
```

## Performance Optimizations

### Batch Queries
```powershell
# Good: Single query with multiple conditions
$filter = "(|" +
    "(userAccountControl:1.2.840.113556.1.4.803:=524288)" +      # Unconstrained delegation
    "(userAccountControl:1.2.840.113556.1.4.803:=16777216)" +    # Protocol transition
    ")"

# Bad: Multiple separate queries
$delegation = Search-IVADObjects -Filter "(userAccountControl:1.2.840.113556.1.4.803:=524288)"
$transition = Search-IVADObjects -Filter "(userAccountControl:1.2.840.113556.1.4.803:=16777216)"
```

### Property Selection
```powershell
# Good: Only request needed properties
Search-IVADObjects -Filter $filter -Properties @('sAMAccountName', 'memberOf')

# Bad: Request all properties (default)
Search-IVADObjects -Filter $filter
```

### Size Limits
```powershell
# For large environments, use size limits during testing
Search-IVADObjects -Filter $filter -SizeLimit 1000
```

## Error Handling Patterns

### Domain Connectivity Check
```powershell
try {
    $domainInfo = Get-IVDomainInfo
} catch {
    return @{
        Status = "Error"
        Message = "Not domain-joined or cannot access domain controller: $_"
        # ... rest of error response
    }
}
```

### Graceful Permission Handling
```powershell
try {
    $results = Search-IVADObjects -Filter $filter -Properties $properties
} catch [System.DirectoryServices.DirectoryServiceException] {
    if ($_.Exception.Message -like "*insufficient access rights*") {
        return @{
            Status = "Failed"
            Message = "Insufficient permissions to perform this check"
            # ... limited results
        }
    }
    throw
}
```

## Helper Library Functions

The `IronVeil-ADSIHelper.ps1` provides these core functions:

1. **Get-IVDomainInfo**: Domain information without Get-ADDomain
2. **Search-IVADObjects**: Generic LDAP search wrapper
3. **Get-IVADUser**: User-specific search with common properties
4. **Get-IVADComputer**: Computer-specific search with common properties
5. **Get-IVADGroup**: Group-specific search with common properties
6. **Get-IVADDomainController**: Domain controller enumeration
7. **Convert-IVFileTimeToDateTime**: Convert AD timestamps
8. **Test-IVUserAccountControl**: UAC flag testing
9. **Get-IVWellKnownSID**: Well-known SID mappings
10. **Get-IVGroupMembers**: Group membership enumeration

## Testing and Validation

### Validation Steps:
1. Test on non-domain machine (should fail gracefully)
2. Test on domain-joined machine without RSAT
3. Compare results with original ActiveDirectory module version
4. Performance testing on large environments
5. Permission testing with limited accounts

### Test Environment Setup:
```powershell
# Verify ADSI availability (always present on Windows)
$searcher = New-Object System.DirectoryServices.DirectorySearcher
if ($searcher) { Write-Host "ADSI Available" }

# Verify no RSAT dependency
try { Import-Module ActiveDirectory } catch { Write-Host "RSAT not required" }

# Test domain connectivity
$computerSystem = Get-WmiObject Win32_ComputerSystem
Write-Host "Domain: $($computerSystem.Domain)"
```

## Migration Checklist

For each rule conversion:

- [ ] Replace `Import-Module ActiveDirectory` with helper library
- [ ] Convert `Get-ADDomain` to `Get-IVDomainInfo`
- [ ] Convert `Get-ADUser/Computer/Group` to `Search-IVADObjects` or helper functions
- [ ] Replace filter syntax with LDAP filters
- [ ] Convert UserAccountControl property tests to bitwise operations
- [ ] Convert date properties with `Convert-IVFileTimeToDateTime`
- [ ] Update error handling for ADSI exceptions
- [ ] Test with limited permissions
- [ ] Validate output format matches original
- [ ] Performance test with reasonable limits

## Implementation Benefits

After conversion to ADSI:

### User Experience:
- ⬇️ **Download**: 150KB executable vs 500MB+ RSAT installation
- ⚡ **Instant Start**: Run immediately after download
- 🔒 **No Admin Rights**: No installation required
- 🏢 **Corporate Friendly**: No policy violations

### Technical Benefits:
- 🚀 **Performance**: Direct LDAP queries, no PowerShell module overhead
- 💾 **Memory**: Lower memory footprint
- 🛡️ **Security**: No additional attack surface from RSAT tools
- 🔄 **Compatibility**: Works on all Windows versions with .NET Framework

### Business Impact:
- 📈 **Higher Adoption**: Lower barrier to entry
- ⏰ **Faster Time to Value**: Immediate scanning capability
- 💰 **Lower Support Costs**: No installation troubleshooting
- 🎯 **Better Market Position**: True standalone solution

## Conclusion

Converting IronVeil rules from ActiveDirectory module to pure ADSI eliminates the biggest barrier to adoption while maintaining full security assessment capabilities. The conversion patterns provided ensure consistent, performant, and reliable operation across diverse Windows environments without external dependencies.

This transformation makes IronVeil a truly standalone MicroSaaS solution that can be deployed instantly in any Windows domain environment.

---

**Status**: ✅ Patterns Documented  
**Next Step**: Convert remaining critical rules using these patterns  
**Impact**: Eliminates RSAT dependency barrier for IronVeil adoption