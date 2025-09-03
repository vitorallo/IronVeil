using Microsoft.Extensions.Logging;
using System.Diagnostics;
using System.Text;
using System.Text.Json;
using IronVeil.Core.Services;

namespace IronVeil.PowerShell.Services;

/// <summary>
/// External PowerShell-based Entra ID authentication manager that extracts access tokens
/// for use in external PowerShell processes during scanning.
/// </summary>
public class ExternalEntraIDAuthenticationManager : IEntraIDAuthenticationManager, IDisposable
{
    private readonly ILogger<ExternalEntraIDAuthenticationManager>? _logger;
    private readonly SessionLogger _sessionLogger;
    private readonly string _powerShellPath;
    private bool _isAuthenticated = false;
    private string? _currentUser;
    private string? _tenantId;
    private string? _accessToken;
    private bool _disposed = false;

    public bool IsAuthenticated => _isAuthenticated;
    public string? CurrentUser => _currentUser;
    public string? TenantId => _tenantId;
    public string? AccessToken => _accessToken;

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

    public ExternalEntraIDAuthenticationManager(ILogger<ExternalEntraIDAuthenticationManager>? logger = null, SessionLogger? sharedSessionLogger = null)
    {
        _logger = logger;
        _powerShellPath = FindPowerShell();
        
        // Use shared session logger or create a simple one without file conflicts
        if (sharedSessionLogger != null)
        {
            _sessionLogger = sharedSessionLogger;
            _sessionLogger.LogSection("External Entra ID Authentication Manager", "Initializing external authentication manager");
        }
        else
        {
            // Create a minimal session logger that logs to console only to avoid file conflicts
            var sessionId = $"entra-auth-{Guid.NewGuid().ToString()[..8]}";
            _sessionLogger = new SessionLogger(sessionId, logger);
            _sessionLogger.LogSection("External Entra ID Authentication Manager", "Initializing external authentication manager");
        }
        
        _sessionLogger.LogInfo("PowerShell path: {0}", _powerShellPath);
        _logger?.LogInformation("External Entra ID authentication manager initialized with PowerShell at: {PowerShellPath}", _powerShellPath);
    }

    private string FindPowerShell()
    {
        // Find PowerShell 7 first, fallback to Windows PowerShell
        var paths = new[]
        {
            @"C:\Program Files\PowerShell\7\pwsh.exe",
            @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        };

        foreach (var path in paths)
        {
            if (File.Exists(path))
            {
                return path;
            }
        }

        // Try PATH environment
        var pathEnv = Environment.GetEnvironmentVariable("PATH");
        if (!string.IsNullOrEmpty(pathEnv))
        {
            var pathDirs = pathEnv.Split(Path.PathSeparator);
            foreach (var dir in pathDirs)
            {
                var pwshPath = Path.Combine(dir, "pwsh.exe");
                if (File.Exists(pwshPath))
                {
                    return pwshPath;
                }
            }
        }

        return "powershell.exe"; // Fallback to system PATH
    }

    public async Task<EntraIdAuthenticationResult> ConnectAsync()
    {
        try
        {
            _sessionLogger.LogSection("Entra ID Authentication", "Starting simplified authentication process");
            _logger?.LogInformation("Starting simplified Entra ID authentication");

            // Log current state
            _sessionLogger.LogInfo("Current authentication state: Authenticated={0}, User={1}, Tenant={2}", 
                _isAuthenticated, _currentUser ?? "none", _tenantId ?? "none");

            // Clean up any existing connection
            _sessionLogger.LogInfo("Cleaning up any existing connections");
            await DisconnectAsync();

            // Create authentication script
            var helperScriptPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "indicators", "IronVeil-ConnectEntraID.ps1");
            
            _sessionLogger.LogInfo("Checking for helper script at: {0}", helperScriptPath);
            if (!File.Exists(helperScriptPath))
            {
                var error = $"IronVeil-ConnectEntraID.ps1 not found at {helperScriptPath}";
                _sessionLogger.LogError("Authentication helper script not found", new FileNotFoundException(error));
                _logger?.LogError(error);
                return new EntraIdAuthenticationResult
                {
                    Success = false,
                    ErrorMessage = error
                };
            }
            
            _sessionLogger.LogInfo("Helper script found, preparing authentication");

            // Simplified PowerShell script with extensive logging
            var authScript = $@"
                $VerbosePreference = 'Continue'
                $DebugPreference = 'Continue'
                $ErrorActionPreference = 'Stop'
                
                Write-Host '===============================================' -ForegroundColor Cyan
                Write-Host 'IRONVEIL ENTRA ID AUTHENTICATION' -ForegroundColor Cyan
                Write-Host '===============================================' -ForegroundColor Cyan
                Write-Host ''
                
                try {{
                    Write-Host '[1/5] Loading authentication helper script...' -ForegroundColor Yellow
                    Write-Host '  Path: {helperScriptPath.Replace("'", "''")}' -ForegroundColor DarkGray
                    
                    # Dot-source the helper script
                    . '{helperScriptPath.Replace("'", "''")}'
                    
                    Write-Host '[2/5] Helper script loaded successfully' -ForegroundColor Green
                    Write-Host ''
                    
                    Write-Host '[3/5] Starting Microsoft Graph connection...' -ForegroundColor Yellow
                    Write-Host '  This will open your default browser for authentication' -ForegroundColor Gray
                    Write-Host '  Please complete the sign-in process in your browser' -ForegroundColor Gray
                    Write-Host ''
                    
                    # Connect using the helper function - this is the simplest approach
                    $context = Connect-IronVeilEntraID
                    
                    Write-Host ''
                    Write-Host '[4/5] Verifying connection...' -ForegroundColor Yellow
                    
                    if ($context) {{
                        # Verify we can actually make API calls
                        $mgContext = Get-MgContext
                        
                        if ($mgContext) {{
                            Write-Host '[5/5] Connection successful!' -ForegroundColor Green
                            Write-Host ''
                            Write-Host '=== CONNECTION DETAILS ===' -ForegroundColor Cyan
                            Write-Host ""  Tenant ID: $($mgContext.TenantId)"" -ForegroundColor White
                            Write-Host ""  Account: $($mgContext.Account)"" -ForegroundColor White
                            $scopeCount = if ($mgContext.Scopes) {{ $mgContext.Scopes.Count }} else {{ 0 }}
                            Write-Host ""  Scopes: $scopeCount permissions granted"" -ForegroundColor White
                            Write-Host ''
                            
                            # Test with a simple API call
                            Write-Host 'Testing API access...' -ForegroundColor Yellow
                            try {{
                                $testUser = Get-MgUser -Top 1 -ErrorAction Stop
                                Write-Host 'API test successful - connection is working' -ForegroundColor Green
                            }} catch {{
                                Write-Host 'API test failed but connection exists' -ForegroundColor Yellow
                            }}
                            
                            # Return simplified result
                            $result = @{{
                                Success = $true
                                TenantId = $mgContext.TenantId
                                Account = $mgContext.Account
                                Scopes = $mgContext.Scopes
                            }}
                            
                            Write-Host ''
                            Write-Host 'Returning authentication result...' -ForegroundColor Gray
                            $result | ConvertTo-Json -Depth 10 -Compress
                        }} else {{
                            throw 'Connection succeeded but context is null'
                        }}
                    }} else {{
                        throw 'Authentication failed - no context returned from Connect-IronVeilEntraID'
                    }}
                }}
                catch {{
                    Write-Host ''
                    Write-Host '=== AUTHENTICATION ERROR ===' -ForegroundColor Red
                    Write-Host ""Error: $($_.Exception.Message)"" -ForegroundColor Red
                    Write-Host ""Type: $($_.Exception.GetType().Name)"" -ForegroundColor Red
                    Write-Host ''
                    Write-Host 'Stack trace:' -ForegroundColor DarkRed
                    Write-Host $_.ScriptStackTrace -ForegroundColor DarkRed
                    
                    # Return error as JSON
                    @{{
                        Success = $false
                        ErrorMessage = $_.Exception.Message
                        ErrorType = $_.Exception.GetType().Name
                    }} | ConvertTo-Json -Depth 10 -Compress
                }}
            ";

            // Execute authentication script with logging
            _sessionLogger.LogInfo("Executing PowerShell authentication script");
            _sessionLogger.LogInfo("Timeout: 5 minutes (browser authentication may take time)");
            
            var result = await ExecutePowerShellScriptAsync(authScript, TimeSpan.FromMinutes(5));
            
            _sessionLogger.LogInfo("Script execution completed with exit code: {0}", result.ExitCode);
            
            if (!string.IsNullOrWhiteSpace(result.Error))
            {
                _sessionLogger.LogWarning("PowerShell stderr output: {0}", result.Error);
            }
            
            if (string.IsNullOrWhiteSpace(result.Output))
            {
                _sessionLogger.LogError("Authentication script returned no output");
                throw new InvalidOperationException("Authentication script returned no output");
            }

            _sessionLogger.LogInfo("Parsing authentication result JSON");
            
            // Find the JSON in the output (last line that looks like JSON)
            var lines = result.Output.Split('\n', StringSplitOptions.RemoveEmptyEntries);
            string? jsonLine = null;
            for (int i = lines.Length - 1; i >= 0; i--)
            {
                if (lines[i].TrimStart().StartsWith("{") && lines[i].TrimEnd().EndsWith("}"))
                {
                    jsonLine = lines[i];
                    break;
                }
            }
            
            if (jsonLine == null)
            {
                _sessionLogger.LogError("No JSON found in script output", new InvalidOperationException("No JSON found"));
                _sessionLogger.LogInfo("Full output: {0}", result.Output);
                throw new InvalidOperationException("No JSON result found in authentication script output");
            }
            
            _sessionLogger.LogInfo("Found JSON result, deserializing");
            
            var authResult = JsonSerializer.Deserialize<AuthenticationScriptResult>(jsonLine, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            });

            if (authResult?.Success == true)
            {
                _isAuthenticated = true;
                _currentUser = authResult.Account;
                _tenantId = authResult.TenantId;

                _sessionLogger.LogSection("Authentication Success", "Successfully connected to Entra ID");
                _sessionLogger.LogInfo("User: {0}", _currentUser);
                _sessionLogger.LogInfo("Tenant ID: {0}", _tenantId);
                _sessionLogger.LogInfo("Granted scopes: {0}", authResult.Scopes?.Length ?? 0);
                
                _logger?.LogInformation("Successfully authenticated to Entra ID as {User} in tenant {TenantId}", 
                    _currentUser, _tenantId);

                // Raise authentication state changed event
                AuthenticationStateChanged?.Invoke(this, new EntraIdAuthenticationEventArgs
                {
                    IsAuthenticated = true,
                    UserPrincipalName = _currentUser,
                    TenantId = _tenantId
                });

                return new EntraIdAuthenticationResult
                {
                    Success = true,
                    UserPrincipalName = _currentUser,
                    TenantId = _tenantId,
                    AuthenticatedRunspace = null
                };
            }
            else
            {
                var errorMsg = authResult?.ErrorMessage ?? "Unknown authentication error";
                _sessionLogger.LogError("Authentication failed", new Exception(errorMsg));
                _logger?.LogError("External authentication failed: {Error}", errorMsg);
                
                return new EntraIdAuthenticationResult
                {
                    Success = false,
                    ErrorMessage = errorMsg
                };
            }
        }
        catch (TimeoutException tex)
        {
            _sessionLogger.LogError("Authentication timed out", tex);
            _logger?.LogError(tex, "Authentication timed out after 5 minutes");
            await DisconnectAsync();
            return new EntraIdAuthenticationResult
            {
                Success = false,
                ErrorMessage = "Authentication timed out. Please ensure you complete the browser sign-in process."
            };
        }
        catch (Exception ex)
        {
            _sessionLogger.LogError("Authentication failed with exception", ex);
            _logger?.LogError(ex, "External Entra ID authentication failed with exception");
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
        if (!_isAuthenticated)
            return false;

        try
        {
            // Test connection by running a simple Graph query
            var testScript = @"
                $ErrorActionPreference = 'Stop'
                try {
                    $testResult = Get-MgUser -Top 1 -ErrorAction Stop
                    @{ Success = $true; UserCount = 1 } | ConvertTo-Json
                }
                catch {
                    @{ Success = $false; Error = $_.Exception.Message } | ConvertTo-Json
                }
            ";

            var result = await ExecutePowerShellScriptAsync(testScript, TimeSpan.FromSeconds(30));
            
            if (!string.IsNullOrWhiteSpace(result.Output))
            {
                var testResult = JsonSerializer.Deserialize<TestConnectionResult>(result.Output, new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                });
                
                return testResult?.Success == true;
            }

            return false;
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to test Entra ID connection");
            return false;
        }
    }

    public async Task DisconnectAsync()
    {
        try
        {
            if (_isAuthenticated)
            {
                // Disconnect from Microsoft Graph
                var disconnectScript = @"
                    try {
                        Disconnect-MgGraph -ErrorAction SilentlyContinue
                        @{ Success = $true } | ConvertTo-Json
                    }
                    catch {
                        @{ Success = $false; Error = $_.Exception.Message } | ConvertTo-Json
                    }
                ";

                await ExecutePowerShellScriptAsync(disconnectScript, TimeSpan.FromSeconds(10));
                _logger?.LogInformation("Disconnected from Entra ID");
            }

            _isAuthenticated = false;
            _currentUser = null;
            _tenantId = null;
            _accessToken = null;

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

    public System.Management.Automation.Runspaces.Runspace? GetAuthenticatedRunspace()
    {
        // External approach doesn't use runspaces
        return null;
    }

    public List<string> GetRequiredPermissions()
    {
        return new List<string>(_requiredPermissions);
    }

    public async Task<bool> ValidatePermissionsAsync()
    {
        if (!_isAuthenticated)
            return false;

        try
        {
            // Test a few key operations to validate permissions
            var permissionTestScript = @"
                $ErrorActionPreference = 'Stop'
                $testResults = @()
                
                try {
                    Get-MgUser -Top 1 -ErrorAction Stop | Out-Null
                    $testResults += 'User.Read.All: OK'
                }
                catch {
                    $testResults += 'User.Read.All: FAILED'
                }
                
                try {
                    Get-MgApplication -Top 1 -ErrorAction Stop | Out-Null  
                    $testResults += 'Application.Read.All: OK'
                }
                catch {
                    $testResults += 'Application.Read.All: FAILED'
                }
                
                @{ Results = $testResults } | ConvertTo-Json
            ";

            var result = await ExecutePowerShellScriptAsync(permissionTestScript, TimeSpan.FromSeconds(60));
            
            if (!string.IsNullOrWhiteSpace(result.Output))
            {
                var testResult = JsonSerializer.Deserialize<PermissionTestResult>(result.Output, new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                });
                
                var failedTests = testResult?.Results?.Count(r => r.Contains("FAILED")) ?? 0;
                return failedTests == 0;
            }

            return false;
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Permission validation failed");
            return false;
        }
    }

    /// <summary>
    /// Gets authentication context for external PowerShell script execution
    /// </summary>
    public EntraIdAuthenticationContext? GetAuthenticationContext()
    {
        if (!_isAuthenticated)
            return null;

        return new EntraIdAuthenticationContext
        {
            TenantId = _tenantId,
            UserPrincipalName = _currentUser,
            AccessToken = _accessToken,
            RequiredScopes = _requiredPermissions
        };
    }

    private async Task<PowerShellExecutionResult> ExecutePowerShellScriptAsync(string script, TimeSpan timeout)
    {
        _sessionLogger.LogInfo("Starting PowerShell process: {0}", _powerShellPath);
        
        using var process = new Process();
        process.StartInfo = new ProcessStartInfo
        {
            FileName = _powerShellPath,
            // Remove -NonInteractive to allow browser authentication
            Arguments = "-NoProfile -ExecutionPolicy Bypass -Command -",
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8
        };

        var outputBuilder = new StringBuilder();
        var errorBuilder = new StringBuilder();
        var outputLock = new object();
        
        process.OutputDataReceived += (sender, e) =>
        {
            if (!string.IsNullOrEmpty(e.Data))
            {
                lock (outputLock)
                {
                    outputBuilder.AppendLine(e.Data);
                    // Log important output lines in real-time
                    if (e.Data.Contains("[ERROR]") || e.Data.Contains("Error:"))
                    {
                        _sessionLogger.LogWarning("PS Output: {0}", e.Data);
                    }
                    else if (e.Data.Contains("[WARNING]") || e.Data.Contains("Warning:"))
                    {
                        _sessionLogger.LogWarning("PS Output: {0}", e.Data);
                    }
                    else if (e.Data.Contains("successful") || e.Data.Contains("SUCCESS"))
                    {
                        _sessionLogger.LogInfo("PS Output: {0}", e.Data);
                    }
                }
            }
        };
        
        process.ErrorDataReceived += (sender, e) =>
        {
            if (!string.IsNullOrEmpty(e.Data))
            {
                lock (outputLock)
                {
                    errorBuilder.AppendLine(e.Data);
                    _sessionLogger.LogWarning("PS Error: {0}", e.Data);
                }
            }
        };

        _sessionLogger.LogInfo("Starting PowerShell process");
        process.Start();
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();
        
        // Write script to stdin
        _sessionLogger.LogInfo("Writing authentication script to PowerShell stdin");
        await process.StandardInput.WriteAsync(script);
        process.StandardInput.Close();
        
        _sessionLogger.LogInfo("Waiting for PowerShell process to complete (timeout: {0} seconds)", timeout.TotalSeconds);
        
        // Wait for completion with timeout
        using var cts = new CancellationTokenSource(timeout);
        
        try
        {
            await Task.Run(() => process.WaitForExit(), cts.Token);
            _sessionLogger.LogInfo("PowerShell process completed with exit code: {0}", process.ExitCode);
        }
        catch (OperationCanceledException)
        {
            if (!process.HasExited)
            {
                _sessionLogger.LogWarning("PowerShell process timed out after {0:F1} seconds, killing process", timeout.TotalSeconds);
                process.Kill();
                throw new TimeoutException($"PowerShell script execution timed out after {timeout.TotalSeconds} seconds");
            }
        }
        
        var output = outputBuilder.ToString();
        var error = errorBuilder.ToString();
        
        if (!string.IsNullOrEmpty(error))
        {
            _sessionLogger.LogWarning("PowerShell stderr output: {0}", error);
            _logger?.LogWarning("PowerShell stderr output during authentication: {Error}", error);
        }
        
        return new PowerShellExecutionResult
        {
            Output = output,
            Error = error,
            ExitCode = process.ExitCode
        };
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

/// <summary>
/// Authentication context that can be passed to external PowerShell processes
/// </summary>
public class EntraIdAuthenticationContext
{
    public string? TenantId { get; set; }
    public string? UserPrincipalName { get; set; }
    public string? AccessToken { get; set; }
    public List<string> RequiredScopes { get; set; } = new();
}

/// <summary>
/// Result from PowerShell authentication script
/// </summary>
internal class AuthenticationScriptResult
{
    public bool Success { get; set; }
    public string? TenantId { get; set; }
    public string? Account { get; set; }
    public string[]? Scopes { get; set; }
    public string? Environment { get; set; }
    public string? AccessToken { get; set; }
    public string? Endpoint { get; set; }
    public string? ErrorMessage { get; set; }
    public string? ErrorType { get; set; }
}

/// <summary>
/// Result from PowerShell connection test
/// </summary>
internal class TestConnectionResult
{
    public bool Success { get; set; }
    public int UserCount { get; set; }
    public string? Error { get; set; }
}

/// <summary>
/// Result from permission validation test
/// </summary>
internal class PermissionTestResult
{
    public string[]? Results { get; set; }
}

/// <summary>
/// Result from PowerShell script execution
/// </summary>
internal class PowerShellExecutionResult
{
    public string Output { get; set; } = string.Empty;
    public string Error { get; set; } = string.Empty;
    public int ExitCode { get; set; }
}