using Microsoft.Extensions.Logging;
using System.Management.Automation;
using System.Management.Automation.Runspaces;

namespace IronVeil.PowerShell.Services;

public interface IEntraIDAuthenticationManager : IDisposable
{
    bool IsAuthenticated { get; }
    string? CurrentUser { get; }
    string? TenantId { get; }
    event EventHandler<EntraIdAuthenticationEventArgs>? AuthenticationStateChanged;
    
    Task<EntraIdAuthenticationResult> ConnectAsync();
    Task<bool> TestConnectionAsync();
    Task DisconnectAsync();
    Runspace? GetAuthenticatedRunspace();
    List<string> GetRequiredPermissions();
    Task<bool> ValidatePermissionsAsync();
}

public class EntraIDAuthenticationManager : IEntraIDAuthenticationManager, IDisposable
{
    private readonly ILogger<EntraIDAuthenticationManager>? _logger;
    private Runspace? _authenticatedRunspace;
    private bool _isAuthenticated = false;
    private string? _currentUser;
    private string? _tenantId;
    private bool _disposed = false;

    public bool IsAuthenticated => _isAuthenticated;
    public string? CurrentUser => _currentUser;
    public string? TenantId => _tenantId;

    public event EventHandler<EntraIdAuthenticationEventArgs>? AuthenticationStateChanged;

    private readonly List<string> _requiredPermissions = new()
    {
        "Directory.Read.All",
        "User.Read.All",
        "Application.Read.All",
        "Policy.Read.All",
        "AuditLog.Read.All",
        "Reports.Read.All",
        "RoleManagement.Read.All",
        "RoleManagement.Read.Directory",
        "UserAuthenticationMethod.Read.All",
        "AdministrativeUnit.Read.All",
        "SecurityEvents.Read.All",
        "Group.Read.All"
    };

    public EntraIDAuthenticationManager(ILogger<EntraIDAuthenticationManager>? logger = null)
    {
        _logger = logger;
    }

    public async Task<EntraIdAuthenticationResult> ConnectAsync()
    {
        try
        {
            _logger?.LogInformation("Starting Entra ID authentication process");

            // Clean up any existing connection
            await DisconnectAsync();

            // Create new runspace for authentication
            _authenticatedRunspace = RunspaceFactory.CreateRunspace();
            _authenticatedRunspace.Open();

            using var powerShell = System.Management.Automation.PowerShell.Create();
            powerShell.Runspace = _authenticatedRunspace;

            // Load the IronVeil Entra ID connection helper
            var helperScriptPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "indicators", "IronVeil-ConnectEntraID.ps1");
            
            if (!File.Exists(helperScriptPath))
            {
                var error = $"IronVeil-ConnectEntraID.ps1 not found at {helperScriptPath}";
                _logger?.LogError(error);
                return new EntraIdAuthenticationResult
                {
                    Success = false,
                    ErrorMessage = error
                };
            }

            // Dot-source the helper script to load functions
            _logger?.LogDebug("Loading IronVeil-ConnectEntraID.ps1 helper script");
            powerShell.AddScript($". '{helperScriptPath}'");
            
            var loadResult = await Task.Run(() => powerShell.Invoke());
            
            if (powerShell.HadErrors)
            {
                var errors = powerShell.Streams.Error.Select(e => e.ToString()).ToList();
                var errorMessage = $"Failed to load helper script: {string.Join("; ", errors)}";
                _logger?.LogError(errorMessage);
                return new EntraIdAuthenticationResult
                {
                    Success = false,
                    ErrorMessage = errorMessage
                };
            }

            // Clear previous commands and connect to Entra ID
            powerShell.Commands.Clear();
            
            _logger?.LogDebug("Executing Connect-IronVeilEntraID");
            powerShell.AddScript("Connect-IronVeilEntraID -Verbose");
            
            // Execute with timeout
            using var timeoutCts = new CancellationTokenSource(TimeSpan.FromMinutes(5));
            
            var connectTask = Task.Run(async () =>
            {
                var results = new PSDataCollection<PSObject>();
                var asyncResult = powerShell.BeginInvoke<PSObject, PSObject>(null, results);
                
                while (!asyncResult.IsCompleted)
                {
                    timeoutCts.Token.ThrowIfCancellationRequested();
                    await Task.Delay(500, timeoutCts.Token);
                }
                
                powerShell.EndInvoke(asyncResult);
                return results.ToList();
            }, timeoutCts.Token);

            var connectResults = await connectTask;

            if (powerShell.HadErrors)
            {
                var errors = powerShell.Streams.Error.Select(e => e.ToString()).ToList();
                var errorMessage = $"Authentication failed: {string.Join("; ", errors)}";
                _logger?.LogError(errorMessage);
                return new EntraIdAuthenticationResult
                {
                    Success = false,
                    ErrorMessage = errorMessage
                };
            }

            // Test the connection
            var testResult = await TestConnectionInternalAsync(powerShell);
            
            if (testResult.Success)
            {
                _isAuthenticated = true;
                _currentUser = testResult.UserPrincipalName;
                _tenantId = testResult.TenantId;

                _logger?.LogInformation("Successfully authenticated to Entra ID as {User} in tenant {TenantId}", 
                    _currentUser, _tenantId);

                var result = new EntraIdAuthenticationResult
                {
                    Success = true,
                    UserPrincipalName = _currentUser,
                    TenantId = _tenantId,
                    AuthenticatedRunspace = _authenticatedRunspace
                };

                // Raise authentication state changed event
                AuthenticationStateChanged?.Invoke(this, new EntraIdAuthenticationEventArgs
                {
                    IsAuthenticated = true,
                    UserPrincipalName = _currentUser,
                    TenantId = _tenantId
                });

                return result;
            }
            else
            {
                await DisconnectAsync();
                return new EntraIdAuthenticationResult
                {
                    Success = false,
                    ErrorMessage = testResult.ErrorMessage ?? "Connection test failed"
                };
            }
        }
        catch (OperationCanceledException)
        {
            _logger?.LogWarning("Entra ID authentication timed out");
            await DisconnectAsync();
            return new EntraIdAuthenticationResult
            {
                Success = false,
                ErrorMessage = "Authentication timed out. Please try again."
            };
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Entra ID authentication failed with exception");
            await DisconnectAsync();
            return new EntraIdAuthenticationResult
            {
                Success = false,
                ErrorMessage = $"Authentication failed: {ex.Message}"
            };
        }
    }

    public async Task<bool> TestConnectionAsync()
    {
        if (!_isAuthenticated || _authenticatedRunspace == null)
            return false;

        try
        {
            using var powerShell = System.Management.Automation.PowerShell.Create();
            powerShell.Runspace = _authenticatedRunspace;

            var result = await TestConnectionInternalAsync(powerShell);
            return result.Success;
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to test Entra ID connection");
            return false;
        }
    }

    private async Task<(bool Success, string? UserPrincipalName, string? TenantId, string? ErrorMessage)> TestConnectionInternalAsync(System.Management.Automation.PowerShell powerShell)
    {
        try
        {
            powerShell.Commands.Clear();
            powerShell.AddScript("Test-IronVeilEntraIDConnection");
            
            var testResults = await Task.Run(() => powerShell.Invoke());

            if (powerShell.HadErrors)
            {
                var errors = powerShell.Streams.Error.Select(e => e.ToString()).ToList();
                return (false, null, null, string.Join("; ", errors));
            }

            // Try to get user context
            powerShell.Commands.Clear();
            powerShell.AddScript("Get-MgContext | Select-Object Account, TenantId");
            var contextResults = await Task.Run(() => powerShell.Invoke());

            if (contextResults.Any() && !powerShell.HadErrors)
            {
                var context = contextResults.First();
                var account = context.Properties["Account"]?.Value?.ToString();
                var tenantId = context.Properties["TenantId"]?.Value?.ToString();
                
                return (true, account, tenantId, null);
            }

            return (true, "authenticated-user", null, null);
        }
        catch (Exception ex)
        {
            return (false, null, null, ex.Message);
        }
    }

    public async Task DisconnectAsync()
    {
        try
        {
            if (_authenticatedRunspace != null)
            {
                // Try to disconnect from Microsoft Graph
                try
                {
                    using var powerShell = System.Management.Automation.PowerShell.Create();
                    powerShell.Runspace = _authenticatedRunspace;
                    powerShell.AddScript("Disconnect-MgGraph -ErrorAction SilentlyContinue");
                    await Task.Run(() => powerShell.Invoke());
                }
                catch (Exception ex)
                {
                    _logger?.LogDebug(ex, "Error during Graph disconnection (expected if not connected)");
                }

                // Close and dispose runspace
                _authenticatedRunspace.Close();
                _authenticatedRunspace.Dispose();
                _authenticatedRunspace = null;
            }

            if (_isAuthenticated)
            {
                _logger?.LogInformation("Disconnected from Entra ID");
            }

            _isAuthenticated = false;
            _currentUser = null;
            _tenantId = null;

            // Raise authentication state changed event
            AuthenticationStateChanged?.Invoke(this, new EntraIdAuthenticationEventArgs
            {
                IsAuthenticated = false,
                UserPrincipalName = null,
                TenantId = null
            });
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Error during Entra ID disconnection");
        }
    }

    public Runspace? GetAuthenticatedRunspace()
    {
        return _isAuthenticated ? _authenticatedRunspace : null;
    }

    public List<string> GetRequiredPermissions()
    {
        return new List<string>(_requiredPermissions);
    }

    public async Task<bool> ValidatePermissionsAsync()
    {
        if (!_isAuthenticated || _authenticatedRunspace == null)
            return false;

        try
        {
            using var powerShell = System.Management.Automation.PowerShell.Create();
            powerShell.Runspace = _authenticatedRunspace;

            // Try a simple operation that requires permissions
            powerShell.AddScript("Get-MgUser -Top 1 -ErrorAction Stop");
            
            var results = await Task.Run(() => powerShell.Invoke());
            
            return !powerShell.HadErrors;
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Permission validation failed");
            return false;
        }
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            _ = DisconnectAsync(); // Fire and forget
            _disposed = true;
        }
    }
}

public class EntraIdAuthenticationResult
{
    public bool Success { get; set; }
    public string? UserPrincipalName { get; set; }
    public string? TenantId { get; set; }
    public string? ErrorMessage { get; set; }
    public Runspace? AuthenticatedRunspace { get; set; }
}

public class EntraIdAuthenticationEventArgs : EventArgs
{
    public bool IsAuthenticated { get; set; }
    public string? UserPrincipalName { get; set; }
    public string? TenantId { get; set; }
}