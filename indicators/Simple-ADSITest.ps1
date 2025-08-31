# Simple ADSI test without RSAT dependency
Write-Host "Testing ADSI connectivity..." -ForegroundColor Yellow

try {
    # Test 1: Check if machine is domain joined
    $computerSystem = Get-WmiObject Win32_ComputerSystem
    $domain = $computerSystem.Domain
    
    if ($domain -and $domain -ne $computerSystem.Name) {
        Write-Host "Domain joined: $domain" -ForegroundColor Green
        
        # Test 2: Try LDAP connection
        $rootDSE = New-Object System.DirectoryServices.DirectoryEntry("LDAP://RootDSE")
        $defaultNC = $rootDSE.defaultNamingContext
        
        if ($defaultNC) {
            Write-Host "LDAP connection successful" -ForegroundColor Green
            Write-Host "Domain DN: $defaultNC" -ForegroundColor Green
            
            # Test 3: Simple search
            $searchBase = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$defaultNC")
            $searcher = New-Object System.DirectoryServices.DirectorySearcher($searchBase)
            $searcher.Filter = "(objectClass=domain)"
            $searcher.PageSize = 1
            
            $result = $searcher.FindOne()
            if ($result) {
                Write-Host "Domain object found: $($result.Path)" -ForegroundColor Green
                Write-Host "SUCCESS: ADSI works without RSAT!" -ForegroundColor Cyan
            }
            
            # Cleanup
            $result = $null
            $searcher.Dispose()
            $searchBase.Dispose()
        }
        
        $rootDSE.Dispose()
    } else {
        Write-Host "Machine is not domain joined" -ForegroundColor Yellow
        Write-Host "Domain: $domain" -ForegroundColor Gray
    }
}
catch {
    Write-Host "Error: $_" -ForegroundColor Red
}