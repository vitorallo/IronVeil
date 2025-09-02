using IronVeil.Core.Configuration;
using IronVeil.Core.Models;
using IronVeil.PowerShell.Models;
using IronVeil.PowerShell.Services;
using Microsoft.Extensions.Logging;
using System.Collections.ObjectModel;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Text.Json;

namespace IronVeil.PowerShell;

public interface IPowerShellExecutor
{
    event EventHandler<RuleExecutionEventArgs>? RuleStarted;
    event EventHandler<RuleExecutionEventArgs>? RuleCompleted;
    event EventHandler<RuleExecutionEventArgs>? RuleError;
    event EventHandler<ScanProgressEventArgs>? ProgressChanged;
    
    Task<ScanSession> ExecuteScanAsync(ScanConfiguration config, CancellationToken cancellationToken = default);
    Task<ScanSession> ExecuteScanWithProfileAsync(ScanProfileConfiguration profileConfig, IEntraIDAuthenticationManager? entraIdAuth = null, CancellationToken cancellationToken = default);
    Task<ScanResult> ExecuteRuleAsync(string rulePath, CancellationToken cancellationToken = default);
    Task<ScanResult> ExecuteRuleAsync(RuleExecutionInfo ruleInfo, Runspace? authenticatedRunspace = null, CancellationToken cancellationToken = default);
    Task<List<string>> DiscoverRulesAsync(string rulesDirectory);
    Task<List<RuleExecutionInfo>> GetAvailableRulesAsync(ScanProfileConfiguration? profileConfig = null);
}

public class PowerShellExecutor : IPowerShellExecutor, IDisposable
{
    private readonly ILogger<PowerShellExecutor>? _logger;
    private readonly IRuleManifestService _ruleManifestService;
    private RunspacePool? _runspacePool;
    private readonly SemaphoreSlim _executionSemaphore;
    private readonly int _maxConcurrentRules;
    private RuleManifest? _manifest;
    private SessionLogger? _sessionLogger;
    private bool _disposed = false;

    public event EventHandler<RuleExecutionEventArgs>? RuleStarted;
    public event EventHandler<RuleExecutionEventArgs>? RuleCompleted;
    public event EventHandler<RuleExecutionEventArgs>? RuleError;
    public event EventHandler<ScanProgressEventArgs>? ProgressChanged;

    public PowerShellExecutor(ILogger<PowerShellExecutor>? logger = null, IRuleManifestService? ruleManifestService = null, int maxConcurrentRules = 5)
    {
        _logger = logger;
        _ruleManifestService = ruleManifestService ?? new RuleManifestService(logger as ILogger<RuleManifestService>);
        _maxConcurrentRules = maxConcurrentRules;
        _executionSemaphore = new SemaphoreSlim(maxConcurrentRules, maxConcurrentRules);
        
        // Initialize session logger
        var sessionId = Guid.NewGuid().ToString();
        _sessionLogger = new SessionLogger(sessionId, logger);
        _sessionLogger.LogInfo("PowerShell executor initializing with session ID: {0}", sessionId);
        _sessionLogger.LogInfo("Max concurrent rules: {0}", maxConcurrentRules);
        
        // Ensure PowerShell modules are deployed before initializing runspace
        _sessionLogger.LogInfo("Deploying PowerShell modules to application directory...");
        PowerShellModuleDeployer.EnsureModulesDeployed(_logger);
        
        InitializeRunspacePool();
    }

    private void InitializeRunspacePool()
    {
        _sessionLogger?.LogSection("PowerShell Runspace Initialization", "Starting PowerShell runspace pool initialization");
        
        try
        {
            // Log PowerShell environment information
            _sessionLogger?.LogInfo("PowerShell SDK Version: 7.4.6");
            _sessionLogger?.LogInfo("CLR Version: {0}", Environment.Version);
            _sessionLogger?.LogInfo("Application Domain: {0}", AppDomain.CurrentDomain.BaseDirectory);
            
            // Set up module paths to include our deployed modules
            var modulesPath = PowerShellModuleDeployer.GetModulesPath();
            var existingModulePath = Environment.GetEnvironmentVariable("PSModulePath") ?? "";
            var newModulePath = $"{modulesPath}{Path.PathSeparator}{existingModulePath}";
            Environment.SetEnvironmentVariable("PSModulePath", newModulePath);
            
            _sessionLogger?.LogInfo("Set PSModulePath to include: {0}", modulesPath);
            _sessionLogger?.LogInfo("Full PSModulePath: {0}", newModulePath);
            
            // Try multiple initialization approaches
            InitialSessionState? initialSessionState = null;
            string initMethod = "";
            
            try
            {
                // First try: CreateDefault2() - best for PowerShell Core
                initialSessionState = InitialSessionState.CreateDefault2();
                initMethod = "CreateDefault2()";
                _sessionLogger?.LogInfo("Using CreateDefault2() for PowerShell Core compatibility");
            }
            catch (Exception ex1)
            {
                _sessionLogger?.LogWarning("CreateDefault2() failed: {0}, trying CreateDefault()", ex1.Message);
                
                try
                {
                    // Second try: CreateDefault() - fallback
                    initialSessionState = InitialSessionState.CreateDefault();
                    initMethod = "CreateDefault()";
                    _sessionLogger?.LogInfo("Using CreateDefault() as fallback");
                }
                catch (Exception ex2)
                {
                    _sessionLogger?.LogWarning("CreateDefault() failed: {0}, using minimal initialization", ex2.Message);
                    
                    // Last resort: Create minimal session state
                    initialSessionState = InitialSessionState.Create();
                    initMethod = "Create() with manual setup";
                    
                    // Import modules from our deployed location
                    var moduleNames = new[] { "Microsoft.PowerShell.Management", "Microsoft.PowerShell.Utility" };
                    foreach (var moduleName in moduleNames)
                    {
                        var modulePath = Path.Combine(modulesPath, moduleName);
                        if (Directory.Exists(modulePath))
                        {
                            initialSessionState.ImportPSModule(new[] { modulePath });
                            _sessionLogger?.LogInfo("Imported module from: {0}", modulePath);
                        }
                    }
                    _sessionLogger?.LogInfo("Using minimal initialization with manual module imports from deployed location");
                }
            }
            
            // Set execution policies for security scanning
            initialSessionState.LanguageMode = PSLanguageMode.FullLanguage;
            initialSessionState.ExecutionPolicy = Microsoft.PowerShell.ExecutionPolicy.Bypass;
            
            _sessionLogger?.LogInfo("Initial session state created with {0}", initMethod);
            _sessionLogger?.LogInfo("LanguageMode: {0}, ExecutionPolicy: {1}", 
                initialSessionState.LanguageMode, initialSessionState.ExecutionPolicy);
            
            // Create runspace pool with proper configuration
            _runspacePool = RunspaceFactory.CreateRunspacePool(initialSessionState);
            _runspacePool.SetMinRunspaces(1);
            _runspacePool.SetMaxRunspaces(_maxConcurrentRules);
            _runspacePool.ThreadOptions = PSThreadOptions.UseNewThread;
            _runspacePool.Open();
            
            // Skip verification for now - we'll test during actual rule execution
            // VerifyPowerShellFunctionality();
            
            _sessionLogger?.LogInfo("PowerShell runspace pool opened successfully with {0} concurrent runspaces", _maxConcurrentRules);
            _sessionLogger?.LogInfo("Skipping functionality verification - will test during rule execution");
            _logger?.LogInformation("PowerShell runspace pool initialized successfully with PowerShell Core 7.4.6 ({MaxConcurrency} concurrent runspaces)", _maxConcurrentRules);
        }
        catch (Exception ex)
        {
            var errorMessage = $"CRITICAL: PowerShell runspace initialization failed. " +
                             $"This system cannot execute PowerShell scripts required for security scanning.\n\n" +
                             $"Error: {ex.Message}\n\n" +
                             $"Please ensure:\n" +
                             $"1. .NET 8 runtime is properly installed\n" +
                             $"2. Microsoft.PowerShell.SDK 7.4.6 is properly referenced\n" +
                             $"3. System.Management.Automation 7.4.6 is properly referenced";
            
            _sessionLogger?.LogError("PowerShell initialization failed", ex);
            _sessionLogger?.LogSection("Critical Error", errorMessage);
            
            _logger?.LogCritical(ex, "PowerShell runspace pool initialization failed");
            
            throw new InvalidOperationException(errorMessage, ex);
        }
    }

    private void VerifyPowerShellFunctionality()
    {
        _sessionLogger?.LogInfo("Verifying PowerShell functionality...");
        
        using (var powerShell = System.Management.Automation.PowerShell.Create())
        {
            powerShell.RunspacePool = _runspacePool;
            
            // Test basic PowerShell functionality
            var testCommands = new[] 
            { 
                "Get-Date",
                "$PSVersionTable.PSVersion",
                "Get-Command Get-Date"
            };
            
            foreach (var command in testCommands)
            {
                powerShell.Commands.Clear();
                powerShell.AddScript(command);
                
                try
                {
                    var results = powerShell.Invoke();
                    
                    if (powerShell.HadErrors)
                    {
                        var errors = string.Join("; ", powerShell.Streams.Error.Select(e => e.ToString()));
                        throw new InvalidOperationException($"PowerShell test command '{command}' failed: {errors}");
                    }
                    
                    _sessionLogger?.LogInfo("✓ Test command '{0}' executed successfully", command);
                }
                catch (Exception ex)
                {
                    _sessionLogger?.LogError($"✗ Test command '{command}' failed", ex);
                    throw new InvalidOperationException($"PowerShell functionality test failed for command '{command}'", ex);
                }
            }
        }
        
        _sessionLogger?.LogInfo("PowerShell functionality verified successfully");
    }

    public async Task<ScanSession> ExecuteScanAsync(ScanConfiguration config, CancellationToken cancellationToken = default)
    {
        var session = new ScanSession
        {
            Configuration = config,
            Status = ScanStatus.Running,
            StartTime = DateTime.UtcNow
        };

        try
        {
            _logger?.LogInformation("Starting scan session {SessionId}", session.SessionId);
            
            // Discover rules
            var rulesDirectory = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "indicators");
            var ruleFiles = await DiscoverRulesAsync(rulesDirectory);
            
            // Filter rules based on configuration
            var filteredRules = FilterRules(ruleFiles, config);
            
            _logger?.LogInformation("Discovered {TotalRules} rules, {FilteredRules} after filtering", 
                ruleFiles.Count, filteredRules.Count);

            // Execute rules in parallel with concurrency control
            var tasks = new List<Task<ScanResult>>();
            int completedRules = 0;
            
            foreach (var rulePath in filteredRules)
            {
                if (cancellationToken.IsCancellationRequested)
                {
                    session.Status = ScanStatus.Cancelled;
                    break;
                }

                var task = ExecuteRuleWithSemaphoreAsync(rulePath, session, completedRules, filteredRules.Count, cancellationToken);
                tasks.Add(task);
            }

            // Wait for all rules to complete
            var results = await Task.WhenAll(tasks);
            session.Results.AddRange(results.Where(r => r != null));
            
            session.Status = cancellationToken.IsCancellationRequested ? ScanStatus.Cancelled : ScanStatus.Completed;
            session.EndTime = DateTime.UtcNow;
            
            _logger?.LogInformation("Scan session {SessionId} completed with {ResultCount} results in {Duration}ms", 
                session.SessionId, session.Results.Count, (session.EndTime - session.StartTime)?.TotalMilliseconds);
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Scan session {SessionId} failed", session.SessionId);
            session.Status = ScanStatus.Failed;
            session.ErrorMessage = ex.Message;
            session.EndTime = DateTime.UtcNow;
        }

        return session;
    }

    private async Task<ScanResult> ExecuteRuleWithSemaphoreAsync(string rulePath, ScanSession session, int completedRules, int totalRules, CancellationToken cancellationToken)
    {
        await _executionSemaphore.WaitAsync(cancellationToken);
        
        try
        {
            var result = await ExecuteRuleAsync(rulePath, cancellationToken);
            
            Interlocked.Increment(ref completedRules);
            var progress = (double)completedRules / totalRules * 100;
            
            ProgressChanged?.Invoke(this, new ScanProgressEventArgs
            {
                SessionId = session.SessionId,
                Progress = progress,
                CompletedRules = completedRules,
                TotalRules = totalRules,
                CurrentRule = Path.GetFileNameWithoutExtension(rulePath)
            });
            
            return result;
        }
        finally
        {
            _executionSemaphore.Release();
        }
    }

    public async Task<ScanResult> ExecuteRuleAsync(string rulePath, CancellationToken cancellationToken = default)
    {
        var ruleName = Path.GetFileNameWithoutExtension(rulePath);
        var startTime = DateTime.UtcNow;
        
        _sessionLogger?.LogInfo("Starting rule execution: {0}", ruleName);
        _sessionLogger?.LogInfo("Rule path: {0}", rulePath);
        
        RuleStarted?.Invoke(this, new RuleExecutionEventArgs
        {
            RuleName = ruleName,
            RulePath = rulePath,
            StartTime = startTime
        });

        try
        {
            if (_runspacePool == null)
            {
                var errorMsg = "PowerShell runspace pool is not initialized";
                _logger?.LogWarning("{ErrorMessage} for rule {RuleName}", errorMsg, ruleName);
                _sessionLogger?.LogError("CRITICAL: {0} for rule {1}", null, errorMsg, ruleName);
                return new ScanResult
                {
                    CheckId = ruleName,
                    Status = "Skipped",
                    Message = "PowerShell runtime is not available",
                    Metadata = new ScanMetadata
                    {
                        ExecutionTime = 0,
                        RuleVersion = "1.0.0"
                    }
                };
            }

            // Ensure runspace pool is initialized
            if (_runspacePool == null || _runspacePool.RunspacePoolStateInfo.State != RunspacePoolState.Opened)
            {
                _sessionLogger?.LogWarning("Runspace pool not available, reinitializing...");
                InitializeRunspacePool();
            }
            
            using var powerShell = System.Management.Automation.PowerShell.Create();
            powerShell.RunspacePool = _runspacePool;

            // Set up timeout
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(TimeSpan.FromSeconds(30)); // 30-second timeout per rule

            // Load and execute the rule script
            _sessionLogger?.LogInfo("Loading PowerShell script from: {0}", rulePath);
            var scriptContent = await File.ReadAllTextAsync(rulePath, cancellationToken);
            _sessionLogger?.LogPowerShellScript(ruleName, scriptContent);
            
            // Clear any previous commands and add the script
            powerShell.Commands.Clear();
            powerShell.AddScript(scriptContent);

            // Execute asynchronously with timeout
            _sessionLogger?.LogInfo("Executing PowerShell script for rule: {0}", ruleName);
            var invokeTask = Task.Run(async () =>
            {
                var results = new PSDataCollection<PSObject>();
                var asyncResult = powerShell.BeginInvoke<PSObject, PSObject>(null, results);
                
                while (!asyncResult.IsCompleted)
                {
                    timeoutCts.Token.ThrowIfCancellationRequested();
                    await Task.Delay(100, timeoutCts.Token);
                }
                
                powerShell.EndInvoke(asyncResult);
                return results.ToList();
            }, timeoutCts.Token);

            var psResults = await invokeTask;
            var executionTime = (DateTime.UtcNow - startTime).TotalSeconds;

            _sessionLogger?.LogInfo("PowerShell execution completed for rule: {0} in {1:F3}s", ruleName, executionTime);

            // Process PowerShell errors
            if (powerShell.HadErrors)
            {
                var errors = powerShell.Streams.Error.Select(e => e.ToString()).ToList();
                _sessionLogger?.LogError("PowerShell execution errors for rule {0}:", null, ruleName);
                foreach (var error in errors)
                {
                    _sessionLogger?.LogError("  - {0}", null, error);
                }
                
                var errorResult = new ScanResult
                {
                    CheckId = ruleName,
                    Status = "Error",
                    Message = string.Join("; ", errors),
                    Metadata = new ScanMetadata
                    {
                        ExecutionTime = executionTime,
                        RuleVersion = "1.0.0"
                    }
                };

                _sessionLogger?.LogRuleExecution(ruleName, ruleName, "Error", executionTime, string.Join("; ", errors));

                RuleError?.Invoke(this, new RuleExecutionEventArgs
                {
                    RuleName = ruleName,
                    RulePath = rulePath,
                    StartTime = startTime,
                    EndTime = DateTime.UtcNow,
                    Error = string.Join("; ", errors)
                });

                return errorResult;
            }

            // Parse the result from PowerShell output
            _sessionLogger?.LogInfo("Parsing PowerShell results for rule: {0} ({1} result objects)", ruleName, psResults.Count);
            var result = ParsePowerShellResult(psResults, ruleName, executionTime);
            
            _sessionLogger?.LogRuleExecution(ruleName, ruleName, result.Status, executionTime);
            _sessionLogger?.LogInfo("Rule {0} completed successfully - Status: {1}, Score: {2}", 
                ruleName, result.Status, result.Score);
            
            RuleCompleted?.Invoke(this, new RuleExecutionEventArgs
            {
                RuleName = ruleName,
                RulePath = rulePath,
                StartTime = startTime,
                EndTime = DateTime.UtcNow,
                Result = result
            });

            return result;
        }
        catch (OperationCanceledException)
        {
            var executionTime = (DateTime.UtcNow - startTime).TotalSeconds;
            _sessionLogger?.LogWarning("Rule execution cancelled: {0} (after {1:F3}s)", ruleName, executionTime);
            
            var cancelResult = new ScanResult
            {
                CheckId = ruleName,
                Status = "Cancelled",
                Message = "Rule execution was cancelled",
                Metadata = new ScanMetadata
                {
                    ExecutionTime = executionTime
                }
            };

            _sessionLogger?.LogRuleExecution(ruleName, ruleName, "Cancelled", executionTime);

            RuleError?.Invoke(this, new RuleExecutionEventArgs
            {
                RuleName = ruleName,
                RulePath = rulePath,
                StartTime = startTime,
                EndTime = DateTime.UtcNow,
                Error = "Execution cancelled"
            });

            return cancelResult;
        }
        catch (Exception ex)
        {
            var executionTime = (DateTime.UtcNow - startTime).TotalSeconds;
            _logger?.LogError(ex, "Failed to execute rule {RuleName}", ruleName);
            _sessionLogger?.LogError("EXCEPTION during rule execution: {0}", ex, ruleName);
            
            var errorResult = new ScanResult
            {
                CheckId = ruleName,
                Status = "Error",
                Message = ex.Message,
                Metadata = new ScanMetadata
                {
                    ExecutionTime = executionTime
                }
            };

            _sessionLogger?.LogRuleExecution(ruleName, ruleName, "Error", executionTime, ex.Message);

            RuleError?.Invoke(this, new RuleExecutionEventArgs
            {
                RuleName = ruleName,
                RulePath = rulePath,
                StartTime = startTime,
                EndTime = DateTime.UtcNow,
                Error = ex.Message
            });

            return errorResult;
        }
    }

    private ScanResult ParsePowerShellResult(IEnumerable<PSObject> psResults, string ruleName, double executionTime)
    {
        try
        {
            // Look for properly formatted JSON output
            var jsonOutput = psResults.LastOrDefault()?.ToString();
            if (!string.IsNullOrEmpty(jsonOutput) && jsonOutput.TrimStart().StartsWith("{"))
            {
                var result = JsonSerializer.Deserialize<ScanResult>(jsonOutput);
                if (result != null)
                {
                    result.Metadata.ExecutionTime = executionTime;
                    return result;
                }
            }

            // Fallback: create result from raw PowerShell output
            var findings = new List<Finding>();
            foreach (var psObject in psResults)
            {
                if (psObject.BaseObject is System.Management.Automation.PSCustomObject customObj)
                {
                    findings.Add(new Finding
                    {
                        ObjectName = GetPropertyValue(customObj, "ObjectName") ?? "Unknown",
                        ObjectType = GetPropertyValue(customObj, "ObjectType") ?? "Unknown",
                        Description = GetPropertyValue(customObj, "Description") ?? psObject.ToString(),
                        RiskLevel = GetPropertyValue(customObj, "RiskLevel") ?? "Medium"
                    });
                }
            }

            return new ScanResult
            {
                CheckId = ruleName,
                Status = "Success",
                Severity = findings.Any(f => f.RiskLevel == "Critical") ? "Critical" :
                          findings.Any(f => f.RiskLevel == "High") ? "High" : "Medium",
                Findings = findings,
                AffectedObjects = findings.Count,
                Message = $"Rule completed with {findings.Count} findings",
                Metadata = new ScanMetadata
                {
                    ExecutionTime = executionTime,
                    RuleVersion = "1.0.0"
                }
            };
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to parse PowerShell result for rule {RuleName}", ruleName);
            
            return new ScanResult
            {
                CheckId = ruleName,
                Status = "Error",
                Message = $"Failed to parse result: {ex.Message}",
                Metadata = new ScanMetadata
                {
                    ExecutionTime = executionTime
                }
            };
        }
    }

    private string? GetPropertyValue(object obj, string propertyName)
    {
        try
        {
            var property = obj.GetType().GetProperty(propertyName);
            return property?.GetValue(obj)?.ToString();
        }
        catch
        {
            return null;
        }
    }

    public Task<List<string>> DiscoverRulesAsync(string rulesDirectory)
    {
        var rules = new List<string>();
        
        if (!Directory.Exists(rulesDirectory))
        {
            _logger?.LogWarning("Rules directory not found: {Directory}", rulesDirectory);
            return Task.FromResult(rules);
        }

        try
        {
            var psFiles = Directory.GetFiles(rulesDirectory, "*.ps1", SearchOption.AllDirectories);
            
            foreach (var file in psFiles)
            {
                // Skip reference files and test files
                if (file.Contains("pk-reference") || file.Contains(".test.") || file.Contains("_test"))
                    continue;
                    
                rules.Add(file);
            }
            
            _logger?.LogInformation("Discovered {RuleCount} PowerShell rules in {Directory}", rules.Count, rulesDirectory);
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to discover rules in directory {Directory}", rulesDirectory);
        }

        return Task.FromResult(rules);
    }

    public async Task<ScanSession> ExecuteScanWithProfileAsync(ScanProfileConfiguration profileConfig, IEntraIDAuthenticationManager? entraIdAuth = null, CancellationToken cancellationToken = default)
    {
        var session = new ScanSession
        {
            Configuration = new ScanConfiguration
            {
                ScanActiveDirectory = profileConfig.IncludeActiveDirectory,
                ScanEntraId = profileConfig.IncludeEntraID,
                ScanHybridIdentity = profileConfig.IncludeActiveDirectory && profileConfig.IncludeEntraID
            },
            Status = ScanStatus.Running,
            StartTime = DateTime.UtcNow
        };

        try
        {
            _logger?.LogInformation("Starting manifest-based scan session {SessionId} with profile {ProfileType}", session.SessionId, profileConfig.Type);
            
            // Load manifest if not already loaded
            _manifest ??= await _ruleManifestService.LoadManifestAsync(null);
            
            // Get rules for the specified profile
            var ruleInfos = _ruleManifestService.GetRulesForProfile(profileConfig);
            
            // Filter based on authentication state
            var executableRules = ruleInfos.Where(r => 
            {
                if (r.Definition.RequiresAuthentication && r.Definition.Environment.Equals("EntraID", StringComparison.OrdinalIgnoreCase))
                {
                    return entraIdAuth?.IsAuthenticated == true;
                }
                return true;
            }).ToList();

            _logger?.LogInformation("Discovered {TotalRules} rules, {ExecutableRules} executable after filtering", 
                ruleInfos.Count, executableRules.Count);

            // Execute rules with concurrency control
            var tasks = new List<Task<ScanResult>>();
            int completedRules = 0;
            
            foreach (var ruleInfo in executableRules)
            {
                if (cancellationToken.IsCancellationRequested)
                {
                    session.Status = ScanStatus.Cancelled;
                    break;
                }

                var authenticatedRunspace = ruleInfo.Definition.RequiresAuthentication && 
                                          ruleInfo.Definition.Environment.Equals("EntraID", StringComparison.OrdinalIgnoreCase)
                    ? entraIdAuth?.GetAuthenticatedRunspace()
                    : null;

                var task = ExecuteRuleWithSemaphoreAsync(ruleInfo, authenticatedRunspace, session, completedRules, executableRules.Count, cancellationToken);
                tasks.Add(task);
            }

            // Wait for all rules to complete
            var results = await Task.WhenAll(tasks);
            session.Results.AddRange(results.Where(r => r != null));
            
            session.Status = cancellationToken.IsCancellationRequested ? ScanStatus.Cancelled : ScanStatus.Completed;
            session.EndTime = DateTime.UtcNow;
            
            _logger?.LogInformation("Scan session {SessionId} completed with {ResultCount} results in {Duration}ms", 
                session.SessionId, session.Results.Count, (session.EndTime - session.StartTime)?.TotalMilliseconds);
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Scan session {SessionId} failed", session.SessionId);
            session.Status = ScanStatus.Failed;
            session.ErrorMessage = ex.Message;
            session.EndTime = DateTime.UtcNow;
        }

        return session;
    }

    public async Task<ScanResult> ExecuteRuleAsync(RuleExecutionInfo ruleInfo, Runspace? authenticatedRunspace = null, CancellationToken cancellationToken = default)
    {
        var startTime = DateTime.UtcNow;
        
        _sessionLogger?.LogSeparator($"Starting Rule Execution: {ruleInfo.RuleId}");
        _sessionLogger?.LogInfo("Rule: {0} - {1}", ruleInfo.RuleId, ruleInfo.Definition.Name);
        _sessionLogger?.LogInfo("Category: {0}, Tier: {1}, Environment: {2}", 
            ruleInfo.Definition.Category, ruleInfo.Definition.Tier, ruleInfo.Definition.Environment);
        _sessionLogger?.LogInfo("Rule path: {0}", ruleInfo.RulePath);
        _sessionLogger?.LogInfo("Requires authentication: {0}", ruleInfo.Definition.RequiresAuthentication);
        _sessionLogger?.LogInfo("Can execute: {0}", ruleInfo.CanExecute);
        
        RuleStarted?.Invoke(this, new RuleExecutionEventArgs
        {
            RuleName = ruleInfo.RuleId,
            RulePath = ruleInfo.RulePath,
            StartTime = startTime
        });

        try
        {
            if (!ruleInfo.CanExecute)
            {
                var errorMessage = $"Rule cannot execute: {string.Join(", ", ruleInfo.BlockingReasons)}";
                _sessionLogger?.LogWarning("Rule {0} blocked from execution: {1}", ruleInfo.RuleId, errorMessage);
                return CreateErrorResult(ruleInfo.RuleId, errorMessage, (DateTime.UtcNow - startTime).TotalSeconds);
            }

            // Use authenticated runspace for Entra ID rules, regular pool for others
            System.Management.Automation.PowerShell? powerShell = null;

            if (authenticatedRunspace != null && ruleInfo.Definition.RequiresAuthentication)
            {
                powerShell = System.Management.Automation.PowerShell.Create();
                powerShell.Runspace = authenticatedRunspace;
                _logger?.LogDebug("Executing rule {RuleId} with authenticated Entra ID runspace", ruleInfo.RuleId);
            }
            else
            {
                powerShell = System.Management.Automation.PowerShell.Create();
                
                if (_runspacePool != null)
                {
                    // Use the runspace pool if available
                    powerShell.RunspacePool = _runspacePool;
                    _logger?.LogDebug("Executing rule {RuleId} with regular runspace pool", ruleInfo.RuleId);
                }
                else
                {
                    // Create individual runspace with proper PowerShell Core initialization
                    // CRITICAL: Use CreateDefault2() for PowerShell Core compatibility
                    var initialSessionState = InitialSessionState.CreateDefault2();
                    initialSessionState.LanguageMode = PSLanguageMode.FullLanguage;
                    initialSessionState.ExecutionPolicy = Microsoft.PowerShell.ExecutionPolicy.Bypass;
                    
                    var runspace = RunspaceFactory.CreateRunspace(initialSessionState);
                    runspace.Open();
                    powerShell.Runspace = runspace;
                    _logger?.LogDebug("Executing rule {RuleId} with individual runspace using CreateDefault2() for PowerShell Core", ruleInfo.RuleId);
                }
            }

            // Track if we created an individual runspace that needs disposal
            var individualRunspace = _runspacePool == null ? powerShell.Runspace : null;
            
            using (powerShell)
            {
                try
                {
                    // Set up timeout
                    using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                    timeoutCts.CancelAfter(TimeSpan.FromSeconds(Math.Max(ruleInfo.Definition.EstimatedTime * 2, 30)));

                    // Load and execute the rule script
                    _sessionLogger?.LogInfo("Loading PowerShell script from: {0}", ruleInfo.RulePath);
                    var scriptContent = await File.ReadAllTextAsync(ruleInfo.RulePath, cancellationToken);
                    _sessionLogger?.LogPowerShellScript(ruleInfo.RuleId, scriptContent);
                    _sessionLogger?.LogInfo("Adding script to PowerShell runspace");
                    
                    // Clear any previous commands and add the script
                    powerShell.Commands.Clear();
                    powerShell.AddScript(scriptContent);

                // Execute asynchronously with timeout
                var invokeTask = Task.Run(async () =>
                {
                    var results = new PSDataCollection<PSObject>();
                    var asyncResult = powerShell.BeginInvoke<PSObject, PSObject>(null, results);
                    
                    while (!asyncResult.IsCompleted)
                    {
                        timeoutCts.Token.ThrowIfCancellationRequested();
                        await Task.Delay(100, timeoutCts.Token);
                    }
                    
                    powerShell.EndInvoke(asyncResult);
                    return results.ToList();
                }, timeoutCts.Token);

                var psResults = await invokeTask;
                var executionTime = (DateTime.UtcNow - startTime).TotalSeconds;

                // Process PowerShell errors
                if (powerShell.HadErrors)
                {
                    var errors = powerShell.Streams.Error.Select(e => e.ToString()).ToList();
                    var errorResult = CreateErrorResult(ruleInfo.RuleId, string.Join("; ", errors), executionTime);

                    RuleError?.Invoke(this, new RuleExecutionEventArgs
                    {
                        RuleName = ruleInfo.RuleId,
                        RulePath = ruleInfo.RulePath,
                        StartTime = startTime,
                        EndTime = DateTime.UtcNow,
                        Error = string.Join("; ", errors)
                    });

                    return errorResult;
                }

                // Parse the result from PowerShell output
                var result = ParsePowerShellResult(psResults, ruleInfo, executionTime);
                
                RuleCompleted?.Invoke(this, new RuleExecutionEventArgs
                {
                    RuleName = ruleInfo.RuleId,
                    RulePath = ruleInfo.RulePath,
                    StartTime = startTime,
                    EndTime = DateTime.UtcNow,
                    Result = result
                });

                    return result;
                }
                finally
                {
                    // Dispose individual runspace if we created one
                    if (individualRunspace != null)
                    {
                        try
                        {
                            individualRunspace.Close();
                            individualRunspace.Dispose();
                        }
                        catch (Exception ex)
                        {
                            _logger?.LogWarning(ex, "Failed to dispose individual runspace for rule {RuleId}", ruleInfo.RuleId);
                        }
                    }
                }
            }
        }
        catch (OperationCanceledException)
        {
            var cancelResult = CreateCancelledResult(ruleInfo.RuleId, (DateTime.UtcNow - startTime).TotalSeconds);

            RuleError?.Invoke(this, new RuleExecutionEventArgs
            {
                RuleName = ruleInfo.RuleId,
                RulePath = ruleInfo.RulePath,
                StartTime = startTime,
                EndTime = DateTime.UtcNow,
                Error = "Execution cancelled"
            });

            return cancelResult;
        }
        catch (Exception ex)
        {
            var errorMessage = $"PowerShell execution failed for rule {ruleInfo.RuleId}: {ex.Message}";
            _logger?.LogError(ex, "Failed to execute rule {RuleName}: {ErrorMessage}", ruleInfo.RuleId, errorMessage);
            
            // If it's a critical PowerShell error, show popup
            if (ex is System.Management.Automation.Runspaces.PSSnapInException || 
                ex.Message.Contains("snap-in") || 
                ex.Message.Contains("PowerShell"))
            {
                var criticalError = $"CRITICAL PowerShell Error during rule execution:\n\n" +
                                  $"Rule: {ruleInfo.RuleId} - {ruleInfo.Definition.Name}\n" +
                                  $"Error: {ex.Message}\n\n" +
                                  $"This indicates a system-level PowerShell configuration issue.\n" +
                                  $"Please check Windows PowerShell installation and permissions.";
                
                _logger?.LogCritical(ex, criticalError);
            }
            
            var errorResult = CreateErrorResult(ruleInfo.RuleId, ex.Message, (DateTime.UtcNow - startTime).TotalSeconds);

            RuleError?.Invoke(this, new RuleExecutionEventArgs
            {
                RuleName = ruleInfo.RuleId,
                RulePath = ruleInfo.RulePath,
                StartTime = startTime,
                EndTime = DateTime.UtcNow,
                Error = ex.Message
            });

            return errorResult;
        }
    }

    public async Task<List<RuleExecutionInfo>> GetAvailableRulesAsync(ScanProfileConfiguration? profileConfig = null)
    {
        try
        {
            _manifest ??= await _ruleManifestService.LoadManifestAsync(null);
            
            if (profileConfig != null)
            {
                return _ruleManifestService.GetRulesForProfile(profileConfig);
            }
            else
            {
                var rulesDirectory = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "indicators");
                return await _ruleManifestService.GetAvailableRules(rulesDirectory);
            }
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to get available rules");
            return new List<RuleExecutionInfo>();
        }
    }

    private async Task<ScanResult> ExecuteRuleWithSemaphoreAsync(RuleExecutionInfo ruleInfo, Runspace? authenticatedRunspace, ScanSession session, int completedRules, int totalRules, CancellationToken cancellationToken)
    {
        await _executionSemaphore.WaitAsync(cancellationToken);
        
        try
        {
            var result = await ExecuteRuleAsync(ruleInfo, authenticatedRunspace, cancellationToken);
            
            Interlocked.Increment(ref completedRules);
            var progress = (double)completedRules / totalRules * 100;
            
            ProgressChanged?.Invoke(this, new ScanProgressEventArgs
            {
                SessionId = session.SessionId,
                Progress = progress,
                CompletedRules = completedRules,
                TotalRules = totalRules,
                CurrentRule = ruleInfo.RuleId
            });
            
            return result;
        }
        finally
        {
            _executionSemaphore.Release();
        }
    }

    private ScanResult ParsePowerShellResult(IEnumerable<PSObject> psResults, RuleExecutionInfo ruleInfo, double executionTime)
    {
        try
        {
            // Look for properly formatted JSON output
            var jsonOutput = psResults.LastOrDefault()?.ToString();
            if (!string.IsNullOrEmpty(jsonOutput) && jsonOutput.TrimStart().StartsWith("{"))
            {
                var result = JsonSerializer.Deserialize<ScanResult>(jsonOutput);
                if (result != null)
                {
                    result.CheckId = ruleInfo.RuleId;
                    result.Severity = ruleInfo.Tier.Name;
                    result.Category = ruleInfo.Definition.Category;
                    result.Metadata.ExecutionTime = executionTime;
                    result.Metadata.RuleVersion = "1.0.0";
                    result.Score = CalculateRuleScore(result, ruleInfo.Tier.Weight);
                    return result;
                }
            }

            // Fallback: create result from raw PowerShell output
            var findings = new List<Finding>();
            foreach (var psObject in psResults)
            {
                if (psObject.BaseObject is System.Management.Automation.PSCustomObject customObj)
                {
                    findings.Add(new Finding
                    {
                        ObjectName = GetPropertyValue(customObj, "ObjectName") ?? "Unknown",
                        ObjectType = GetPropertyValue(customObj, "ObjectType") ?? "Unknown",
                        Description = GetPropertyValue(customObj, "Description") ?? psObject.ToString(),
                        RiskLevel = GetPropertyValue(customObj, "RiskLevel") ?? ruleInfo.Tier.Name
                    });
                }
            }

            return new ScanResult
            {
                CheckId = ruleInfo.RuleId,
                Status = "Success",
                Severity = ruleInfo.Tier.Name,
                Category = ruleInfo.Definition.Category,
                Findings = findings,
                AffectedObjects = findings.Count,
                Message = $"Rule completed with {findings.Count} findings",
                Score = CalculateRuleScore(findings.Count, ruleInfo.Tier.Weight),
                Metadata = new ScanMetadata
                {
                    ExecutionTime = executionTime,
                    RuleVersion = "1.0.0",
                    Environment = ruleInfo.Definition.Environment
                }
            };
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to parse PowerShell result for rule {RuleName}", ruleInfo.RuleId);
            
            return CreateErrorResult(ruleInfo.RuleId, $"Failed to parse result: {ex.Message}", executionTime);
        }
    }

    private ScanResult CreateErrorResult(string ruleId, string errorMessage, double executionTime)
    {
        return new ScanResult
        {
            CheckId = ruleId,
            Status = "Error",
            Message = errorMessage,
            Severity = "High", // Errors are treated as high priority
            Score = 0,
            Metadata = new ScanMetadata
            {
                ExecutionTime = executionTime,
                RuleVersion = "1.0.0"
            }
        };
    }

    private ScanResult CreateCancelledResult(string ruleId, double executionTime)
    {
        return new ScanResult
        {
            CheckId = ruleId,
            Status = "Cancelled",
            Message = "Rule execution was cancelled",
            Severity = "Low",
            Score = 0,
            Metadata = new ScanMetadata
            {
                ExecutionTime = executionTime,
                RuleVersion = "1.0.0"
            }
        };
    }

    private int CalculateRuleScore(ScanResult result, int tierWeight)
    {
        return CalculateRuleScore(result.AffectedObjects, tierWeight);
    }

    private int CalculateRuleScore(int affectedObjects, int tierWeight)
    {
        if (affectedObjects == 0) return 0;
        
        // Base score on tier weight, modified by number of affected objects
        var baseScore = tierWeight;
        var objectModifier = Math.Min(affectedObjects * 0.1, 1.0); // Max 100% increase
        
        return (int)(baseScore * (1 + objectModifier));
    }

    private List<string> FilterRules(List<string> allRules, ScanConfiguration config)
    {
        var filteredRules = allRules.Where(rule =>
        {
            var fileName = Path.GetFileName(rule).ToLowerInvariant();
            
            // Include/exclude based on scan configuration
            if (!config.ScanActiveDirectory && fileName.Contains("ad"))
                return false;
            if (!config.ScanEntraId && (fileName.Contains("entra") || fileName.Contains("aad")))
                return false;
            if (!config.ScanHybridIdentity && fileName.Contains("hybrid"))
                return false;
            
            // Check excluded rules
            if (config.ExcludedRules.Any(excluded => fileName.Contains(excluded.ToLowerInvariant())))
                return false;
            
            // Check included rules (if specified)
            if (config.IncludedRules.Any() && !config.IncludedRules.Any(included => fileName.Contains(included.ToLowerInvariant())))
                return false;
            
            return true;
        }).ToList();

        return filteredRules;
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            try
            {
                _runspacePool?.Close();
                _runspacePool?.Dispose();
                _executionSemaphore?.Dispose();
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Error disposing PowerShellExecutor");
            }
            
            _disposed = true;
        }
    }
}

public class RuleExecutionEventArgs : EventArgs
{
    public string RuleName { get; set; } = string.Empty;
    public string RulePath { get; set; } = string.Empty;
    public DateTime StartTime { get; set; }
    public DateTime EndTime { get; set; }
    public string? Error { get; set; }
    public ScanResult? Result { get; set; }
}

public class ScanProgressEventArgs : EventArgs
{
    public string SessionId { get; set; } = string.Empty;
    public double Progress { get; set; }
    public int CompletedRules { get; set; }
    public int TotalRules { get; set; }
    public string CurrentRule { get; set; } = string.Empty;
}