using IronVeil.Core.Configuration;
using IronVeil.Core.Models;
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
    Task<ScanResult> ExecuteRuleAsync(string rulePath, CancellationToken cancellationToken = default);
    Task<List<string>> DiscoverRulesAsync(string rulesDirectory);
}

public class PowerShellExecutor : IPowerShellExecutor, IDisposable
{
    private readonly ILogger<PowerShellExecutor>? _logger;
    private RunspacePool? _runspacePool;
    private readonly SemaphoreSlim _executionSemaphore;
    private readonly int _maxConcurrentRules;
    private bool _disposed = false;

    public event EventHandler<RuleExecutionEventArgs>? RuleStarted;
    public event EventHandler<RuleExecutionEventArgs>? RuleCompleted;
    public event EventHandler<RuleExecutionEventArgs>? RuleError;
    public event EventHandler<ScanProgressEventArgs>? ProgressChanged;

    public PowerShellExecutor(ILogger<PowerShellExecutor>? logger = null, int maxConcurrentRules = 5)
    {
        _logger = logger;
        _maxConcurrentRules = maxConcurrentRules;
        _executionSemaphore = new SemaphoreSlim(maxConcurrentRules, maxConcurrentRules);
        InitializeRunspacePool();
    }

    private void InitializeRunspacePool()
    {
        try
        {
            // Try to create runspace pool with minimal session state to avoid snap-in issues
            if (TryInitializeMinimalRunspacePool())
            {
                _logger?.LogInformation("PowerShell runspace pool initialized with minimal session state ({MaxConcurrency} concurrent runspaces)", _maxConcurrentRules);
                return;
            }

            // Fallback to default runspace pool creation
            if (TryInitializeDefaultRunspacePool())
            {
                _logger?.LogInformation("PowerShell runspace pool initialized with default session state ({MaxConcurrency} concurrent runspaces)", _maxConcurrentRules);
                return;
            }

            throw new InvalidOperationException("Failed to initialize PowerShell runspace pool with any method");
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to initialize PowerShell runspace pool");
            throw;
        }
    }

    private bool TryInitializeMinimalRunspacePool()
    {
        try
        {
            // Create minimal session state to avoid problematic snap-ins
            var initialSessionState = InitialSessionState.CreateDefault2();
            
            // Use the minimal session state as-is to avoid snap-in issues
            // CreateDefault2() creates a more restricted environment than CreateDefault()
            _runspacePool = RunspaceFactory.CreateRunspacePool(1, _maxConcurrentRules, initialSessionState, null);
            _runspacePool.Open();
            
            return true;
        }
        catch (Exception ex)
        {
            _logger?.LogDebug(ex, "Failed to initialize minimal runspace pool");
            return false;
        }
    }

    private bool TryInitializeDefaultRunspacePool()
    {
        try
        {
            // Create a simple runspace pool without complex initialization
            // This avoids issues with missing snap-ins on development machines
            _runspacePool = RunspaceFactory.CreateRunspacePool(1, _maxConcurrentRules);
            _runspacePool.Open();
            
            return true;
        }
        catch (Exception ex)
        {
            _logger?.LogDebug(ex, "Failed to initialize default runspace pool");
            return false;
        }
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
                throw new InvalidOperationException("PowerShell runspace pool is not initialized");
            }

            using var powerShell = System.Management.Automation.PowerShell.Create();
            powerShell.RunspacePool = _runspacePool;

            // Set up timeout
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(TimeSpan.FromSeconds(30)); // 30-second timeout per rule

            // Load and execute the rule script
            var scriptContent = await File.ReadAllTextAsync(rulePath, cancellationToken);
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
            var result = ParsePowerShellResult(psResults, ruleName, executionTime);
            
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
            var cancelResult = new ScanResult
            {
                CheckId = ruleName,
                Status = "Cancelled",
                Message = "Rule execution was cancelled",
                Metadata = new ScanMetadata
                {
                    ExecutionTime = (DateTime.UtcNow - startTime).TotalSeconds
                }
            };

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
            _logger?.LogError(ex, "Failed to execute rule {RuleName}", ruleName);
            
            var errorResult = new ScanResult
            {
                CheckId = ruleName,
                Status = "Error",
                Message = ex.Message,
                Metadata = new ScanMetadata
                {
                    ExecutionTime = (DateTime.UtcNow - startTime).TotalSeconds
                }
            };

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