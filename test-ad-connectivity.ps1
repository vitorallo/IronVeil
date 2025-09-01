# Test Active Directory connectivity
Write-Host "=== Testing AD Connectivity ===" -ForegroundColor Green

try {
    # Test domain info
    Write-Host "`n1. Domain Information:" -ForegroundColor Yellow
    $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    Write-Host "Domain: $($domain.Name)"
    Write-Host "Forest: $($domain.Forest.Name)"
    
    # Test ADSI search for users
    Write-Host "`n2. ADSI User Query (first 5):" -ForegroundColor Yellow
    $searcher = [adsisearcher]"(objectClass=user)"
    $searcher.PageSize = 5
    $users = $searcher.FindAll()
    Write-Host "Found $($users.Count) users"
    
    foreach($user in $users) {
        $sam = $user.Properties["samaccountname"][0]
        $cn = $user.Properties["cn"][0]
        Write-Host "  - $sam ($cn)"
    }
    
    # Test ADSI search for groups
    Write-Host "`n3. ADSI Group Query (first 5):" -ForegroundColor Yellow
    $groupSearcher = [adsisearcher]"(objectClass=group)"
    $groupSearcher.PageSize = 5
    $groups = $groupSearcher.FindAll()
    Write-Host "Found $($groups.Count) groups"
    
    foreach($group in $groups) {
        $groupName = $group.Properties["samaccountname"][0]
        Write-Host "  - $groupName"
    }
    
    # Test ADSI search for computers
    Write-Host "`n4. ADSI Computer Query (first 5):" -ForegroundColor Yellow
    $computerSearcher = [adsisearcher]"(objectClass=computer)"
    $computerSearcher.PageSize = 5
    $computers = $computerSearcher.FindAll()
    Write-Host "Found $($computers.Count) computers"
    
    foreach($computer in $computers) {
        $computerName = $computer.Properties["samaccountname"][0]
        Write-Host "  - $computerName"
    }
    
    Write-Host "`n=== AD Connectivity Test PASSED ===" -ForegroundColor Green
    
} catch {
    Write-Host "`nERROR: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "=== AD Connectivity Test FAILED ===" -ForegroundColor Red
}