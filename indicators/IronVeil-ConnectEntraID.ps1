<#
.SYNOPSIS
IronVeil Entra ID Connection Helper - Simplifies authentication for security assessments

.DESCRIPTION
This script provides helper functions to connect to Microsoft Graph with all permissions
required for IronVeil's Entra ID security assessment rules. It handles module installation,
authentication, and permission verification.

.NOTES
Version: 1.0.0
Author: IronVeil Security Team
Required: PowerShell 5.1 or higher
Dependencies: Microsoft.Graph PowerShell module

.EXAMPLE
# Connect with all required permissions
Connect-IronVeilEntraID

.EXAMPLE
# Check if module is installed first
Install-IronVeilGraphModule

.EXAMPLE
# Test current connection
Test-IronVeilEntraIDConnection
#>

# Set strict mode for better error handling
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Define all unique permissions required across all EID rules
$script:IronVeilRequiredScopes = @(
    "Directory.Read.All",              # Required by most rules
    "User.Read.All",                   # User information
    "Application.Read.All",            # Application and service principal info
    "Policy.Read.All",                 # Security and compliance policies
    "AuditLog.Read.All",              # Audit log access
    "Reports.Read.All",               # Security and usage reports
    "RoleManagement.Read.All",        # Role assignments
    "RoleManagement.Read.Directory",  # Directory role management
    "UserAuthenticationMethod.Read.All", # MFA and auth methods
    "AdministrativeUnit.Read.All",    # Administrative units
    "SecurityEvents.Read.All",        # Security events and alerts
    "Group.Read.All"                  # Group information
)

function Get-IronVeilRequiredPermissions {
    <#
    .SYNOPSIS
    Returns the list of Microsoft Graph permissions required for IronVeil
    
    .DESCRIPTION
    Lists all Graph API permissions needed for complete Entra ID security assessment
    
    .EXAMPLE
    Get-IronVeilRequiredPermissions
    #>
    
    [CmdletBinding()]
    param()
    
    Write-Host "`n=== IronVeil Required Permissions ===" -ForegroundColor Cyan
    Write-Host "The following Microsoft Graph permissions are required:" -ForegroundColor Yellow
    
    $script:IronVeilRequiredScopes | ForEach-Object {
        Write-Host "  • $_" -ForegroundColor Gray
    }
    
    $scopeCount = if ($script:IronVeilRequiredScopes) { $script:IronVeilRequiredScopes.Count } else { 0 }
    Write-Host "`nTotal: $scopeCount permissions" -ForegroundColor White
    Write-Host "Note: These are read-only permissions for security assessment" -ForegroundColor Green
    
    return $script:IronVeilRequiredScopes
}

function Install-IronVeilGraphModule {
    <#
    .SYNOPSIS
    Checks and installs Microsoft.Graph module if needed
    
    .DESCRIPTION
    Verifies if Microsoft.Graph module is installed and offers to install it if missing
    
    .PARAMETER Force
    Force installation even if module exists
    
    .EXAMPLE
    Install-IronVeilGraphModule
    
    .EXAMPLE
    Install-IronVeilGraphModule -Force
    #>
    
    [CmdletBinding()]
    param(
        [switch]$Force
    )
    
    Write-Host "`n=== Microsoft.Graph Module Check ===" -ForegroundColor Cyan
    
    # Check if module is already installed
    $graphModule = Get-Module -ListAvailable -Name Microsoft.Graph | 
        Sort-Object Version -Descending | 
        Select-Object -First 1
    
    if ($graphModule -and -not $Force) {
        Write-Host "✅ Microsoft.Graph module is installed" -ForegroundColor Green
        Write-Host "   Version: $($graphModule.Version)" -ForegroundColor Gray
        
        # Check if it's reasonably recent
        $minVersion = [Version]"2.0.0"
        if ($graphModule.Version -lt $minVersion) {
            Write-Host "⚠️  Your version is older than recommended ($minVersion)" -ForegroundColor Yellow
            Write-Host "   Consider updating with: Update-Module Microsoft.Graph" -ForegroundColor Yellow
        }
        
        return $true
    }
    
    if ($Force) {
        Write-Host "Force flag specified - reinstalling module..." -ForegroundColor Yellow
    } else {
        Write-Host "❌ Microsoft.Graph module is not installed" -ForegroundColor Red
    }
    
    # Prompt for installation
    Write-Host "`nThe Microsoft.Graph module is required for Entra ID security assessments." -ForegroundColor Yellow
    Write-Host "This is a one-time installation (~150MB download)." -ForegroundColor Gray
    
    $install = Read-Host "`nDo you want to install it now? (Y/N)"
    
    if ($install -ne 'Y' -and $install -ne 'y') {
        Write-Host "Installation cancelled. Microsoft.Graph module is required to proceed." -ForegroundColor Red
        return $false
    }
    
    # Check for admin rights (not required for CurrentUser scope)
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    try {
        Write-Host "`nInstalling Microsoft.Graph module..." -ForegroundColor Yellow
        Write-Host "This may take a few minutes..." -ForegroundColor Gray
        
        $installParams = @{
            Name = "Microsoft.Graph"
            Scope = if ($isAdmin) { "AllUsers" } else { "CurrentUser" }
            Force = $true
            AllowClobber = $true
        }
        
        # Try to install from PSGallery
        if (-not (Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue)) {
            Write-Host "Registering PSGallery repository..." -ForegroundColor Yellow
            Register-PSRepository -Default -ErrorAction SilentlyContinue
        }
        
        Install-Module @installParams
        
        Write-Host "✅ Microsoft.Graph module installed successfully!" -ForegroundColor Green
        
        # Import the module
        Import-Module Microsoft.Graph.Authentication -ErrorAction SilentlyContinue
        
        return $true
    }
    catch {
        Write-Host "❌ Failed to install Microsoft.Graph module" -ForegroundColor Red
        Write-Host "Error: $_" -ForegroundColor Red
        
        Write-Host "`nAlternative: Install manually with:" -ForegroundColor Yellow
        Write-Host "  Install-Module Microsoft.Graph -Scope CurrentUser" -ForegroundColor White
        
        return $false
    }
}

function Connect-IronVeilEntraID {
    <#
    .SYNOPSIS
    Connects to Microsoft Graph with all permissions required for IronVeil
    
    .DESCRIPTION
    Establishes connection to Microsoft Graph API with all scopes needed for
    comprehensive Entra ID security assessment
    
    .PARAMETER TenantId
    Optional tenant ID to connect to a specific tenant
    
    .PARAMETER ForceReconnect
    Force a new connection even if already connected
    
    .EXAMPLE
    Connect-IronVeilEntraID
    
    .EXAMPLE
    Connect-IronVeilEntraID -TenantId "contoso.onmicrosoft.com"
    
    .EXAMPLE
    Connect-IronVeilEntraID -ForceReconnect
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$TenantId,
        
        [Parameter(Mandatory=$false)]
        [switch]$ForceReconnect
    )
    
    Write-Host "`n=== IronVeil Entra ID Connection ===" -ForegroundColor Cyan
    
    # Check if module is available
    try {
        Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    }
    catch {
        Write-Host "❌ Microsoft.Graph module not found" -ForegroundColor Red
        Write-Host "Running installation check..." -ForegroundColor Yellow
        
        if (-not (Install-IronVeilGraphModule)) {
            throw "Cannot proceed without Microsoft.Graph module"
        }
        
        Import-Module Microsoft.Graph.Authentication
    }
    
    # Check if already connected
    $currentContext = Get-MgContext -ErrorAction SilentlyContinue
    
    if ($currentContext -and -not $ForceReconnect) {
        Write-Host "Already connected to Microsoft Graph" -ForegroundColor Green
        Write-Host "  Tenant: $($currentContext.TenantId)" -ForegroundColor Gray
        Write-Host "  Account: $($currentContext.Account)" -ForegroundColor Gray
        
        # Always force reconnect for IronVeil to ensure fresh authentication
        Write-Host "`nDisconnecting current session to establish fresh connection..." -ForegroundColor Yellow
        Disconnect-MgGraph -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 500  # Brief pause to ensure clean disconnect
    }
    
    # Prepare connection parameters
    $connectParams = @{
        Scopes = $script:IronVeilRequiredScopes
        NoWelcome = $true
    }
    
    if ($TenantId) {
        $connectParams['TenantId'] = $TenantId
        Write-Host "Connecting to tenant: $TenantId" -ForegroundColor Yellow
    }
    
    # Connect to Microsoft Graph with extensive logging
    try {
        Write-Host "`nConnecting to Microsoft Graph..." -ForegroundColor Yellow
        Write-Host "Authentication method: Interactive browser-based" -ForegroundColor Gray
        Write-Host "Please sign in with an account that has Global Reader or higher privileges" -ForegroundColor Gray
        
        # Log connection parameters for debugging
        Write-Host "`nDEBUG: Connection parameters:" -ForegroundColor DarkGray
        if ($connectParams.Scopes) {
            Write-Host "  Scopes requested: $($connectParams.Scopes.Count) permissions" -ForegroundColor DarkGray
        } else {
            Write-Host "  Scopes: Using default permissions" -ForegroundColor DarkGray
        }
        if ($TenantId) {
            Write-Host "  Tenant ID: $TenantId" -ForegroundColor DarkGray
        }
        
        # Try browser-based authentication first (simplest approach)
        Write-Host "`nAttempting browser-based authentication..." -ForegroundColor Yellow
        
        Connect-MgGraph @connectParams
        
        # Verify connection
        $context = Get-MgContext
        
        if ($context) {
            Write-Host "`n✅ Successfully connected to Entra ID!" -ForegroundColor Green
            Write-Host "  Tenant ID: $($context.TenantId)" -ForegroundColor White
            Write-Host "  Account: $($context.Account)" -ForegroundColor White
            Write-Host "  Environment: $($context.Environment)" -ForegroundColor White
            if ($context.Scopes) {
                Write-Host "  Scopes: $($context.Scopes.Count) permissions granted" -ForegroundColor White
            } else {
                Write-Host "  Scopes: Default permissions granted" -ForegroundColor White
            }
            
            # Get tenant details
            try {
                $org = Get-MgOrganization -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($org) {
                    Write-Host "  Organization: $($org.DisplayName)" -ForegroundColor White
                }
            }
            catch {
                # Ignore if we can't get org details
            }
            
            Write-Host "`n✅ Ready to run IronVeil security assessments!" -ForegroundColor Green
            
            return $context
        }
        else {
            throw "Connection established but context verification failed"
        }
    }
    catch {
        Write-Host "`n❌ Failed to connect to Microsoft Graph" -ForegroundColor Red
        Write-Host "Error: $_" -ForegroundColor Red
        
        if ($_.Exception.Message -like "*AADSTS65001*") {
            Write-Host "`n⚠️  Admin consent required!" -ForegroundColor Yellow
            Write-Host "An administrator must consent to the requested permissions." -ForegroundColor Yellow
            Write-Host "Please have a Global Administrator run this command." -ForegroundColor Yellow
        }
        elseif ($_.Exception.Message -like "*AADSTS50076*") {
            Write-Host "`n⚠️  Multi-factor authentication required!" -ForegroundColor Yellow
            Write-Host "Please complete MFA and try again." -ForegroundColor Yellow
        }
        
        throw
    }
}

function Test-IronVeilEntraIDConnection {
    <#
    .SYNOPSIS
    Tests the current Microsoft Graph connection and permissions
    
    .DESCRIPTION
    Verifies that the current connection has all required permissions for IronVeil
    
    .EXAMPLE
    Test-IronVeilEntraIDConnection
    #>
    
    [CmdletBinding()]
    param()
    
    Write-Host "`n=== Testing Entra ID Connection ===" -ForegroundColor Cyan
    
    # Check if connected
    $context = Get-MgContext -ErrorAction SilentlyContinue
    
    if (-not $context) {
        Write-Host "❌ Not connected to Microsoft Graph" -ForegroundColor Red
        Write-Host "Run Connect-IronVeilEntraID to establish connection" -ForegroundColor Yellow
        return $false
    }
    
    Write-Host "✅ Connected to Microsoft Graph" -ForegroundColor Green
    Write-Host "  Tenant: $($context.TenantId)" -ForegroundColor Gray
    Write-Host "  Account: $($context.Account)" -ForegroundColor Gray
    
    # Check permissions
    Write-Host "`nChecking permissions..." -ForegroundColor Yellow
    
    $grantedScopes = $context.Scopes
    $missingScopes = @()
    $availableScopes = @()
    
    foreach ($scope in $script:IronVeilRequiredScopes) {
        if ($grantedScopes -contains $scope) {
            $availableScopes += $scope
            Write-Host "  ✅ $scope" -ForegroundColor Green
        }
        else {
            $missingScopes += $scope
            Write-Host "  ❌ $scope" -ForegroundColor Red
        }
    }
    
    # Summary
    Write-Host "`n=== Permission Summary ===" -ForegroundColor Cyan
    $availCount = if ($availableScopes) { $availableScopes.Count } else { 0 }
    $reqCount = if ($script:IronVeilRequiredScopes) { $script:IronVeilRequiredScopes.Count } else { 0 }
    $missCount = if ($missingScopes) { $missingScopes.Count } else { 0 }
    Write-Host "Granted: $availCount/$reqCount permissions" -ForegroundColor $(if ($missCount -eq 0) { "Green" } else { "Yellow" })
    
    if ($missingScopes -and $missingScopes.Count -gt 0) {
        Write-Host "`n⚠️  Missing permissions may cause some rules to fail" -ForegroundColor Yellow
        Write-Host "Run Connect-IronVeilEntraID to reconnect with all permissions" -ForegroundColor Yellow
        return $false
    }
    else {
        Write-Host "`n✅ All required permissions are granted!" -ForegroundColor Green
        
        # Test basic API call
        Write-Host "`nTesting API access..." -ForegroundColor Yellow
        try {
            $testUser = Get-MgUser -Top 1 -ErrorAction Stop
            Write-Host "✅ API access confirmed" -ForegroundColor Green
            return $true
        }
        catch {
            Write-Host "⚠️  API test failed: $_" -ForegroundColor Yellow
            return $false
        }
    }
}

function Disconnect-IronVeilEntraID {
    <#
    .SYNOPSIS
    Disconnects from Microsoft Graph
    
    .DESCRIPTION
    Cleanly disconnects the current Microsoft Graph session
    
    .EXAMPLE
    Disconnect-IronVeilEntraID
    #>
    
    [CmdletBinding()]
    param()
    
    Write-Host "`nDisconnecting from Microsoft Graph..." -ForegroundColor Yellow
    
    try {
        Disconnect-MgGraph -ErrorAction Stop
        Write-Host "✅ Successfully disconnected" -ForegroundColor Green
    }
    catch {
        Write-Host "No active connection to disconnect" -ForegroundColor Gray
    }
}

# Functions are automatically available when script is dot-sourced
# No export needed for .ps1 scripts

# Display banner when script is dot-sourced
if ($MyInvocation.InvocationName -eq '.') {
    Write-Host ""
    Write-Host "===================================================" -ForegroundColor Cyan
    Write-Host "     IronVeil Entra ID Connection Helper          " -ForegroundColor Cyan
    Write-Host "              Version 1.0.0                        " -ForegroundColor Cyan
    Write-Host "===================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Available commands:" -ForegroundColor Yellow
    Write-Host "  Connect-IronVeilEntraID         - Connect with all required permissions" -ForegroundColor White
    Write-Host "  Test-IronVeilEntraIDConnection  - Test current connection" -ForegroundColor White
    Write-Host "  Get-IronVeilRequiredPermissions - List required permissions" -ForegroundColor White
    Write-Host "  Install-IronVeilGraphModule     - Install Microsoft.Graph module" -ForegroundColor White
    Write-Host "  Disconnect-IronVeilEntraID      - Disconnect from Graph" -ForegroundColor White
    Write-Host ""
    Write-Host "Quick start: Run Connect-IronVeilEntraID to begin" -ForegroundColor Green
}