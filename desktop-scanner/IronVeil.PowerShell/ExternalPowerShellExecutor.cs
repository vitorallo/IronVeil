using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management.Automation.Runspaces;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using IronVeil.Core.Models;
using IronVeil.Core.Services;
using IronVeil.PowerShell.Models;
using IronVeil.PowerShell.Services;
using Microsoft.Extensions.Logging;

namespace IronVeil.PowerShell;

/// <summary>
/// Executes PowerShell scripts using external PowerShell 7 process for full cmdlet compatibility.
/// </summary>
public class ExternalPowerShellExecutor : IPowerShellExecutor
{
    private readonly ILogger<ExternalPowerShellExecutor>? _logger;
    private readonly IRuleManifestService _ruleManifestService;
    private readonly SessionLogger? _sessionLogger;
    private readonly int _maxConcurrentRules;
    private readonly SemaphoreSlim _executionSemaphore;
    private readonly string _powerShellPath;
    
    public event EventHandler<RuleExecutionEventArgs>? RuleStarted;
    public event EventHandler<RuleExecutionEventArgs>? RuleCompleted;
    public event EventHandler<RuleExecutionEventArgs>? RuleError;
    public event EventHandler<ScanProgressEventArgs>? ProgressChanged;

    public ExternalPowerShellExecutor(
        ILogger<ExternalPowerShellExecutor>? logger = null, 
        IRuleManifestService? ruleManifestService = null, 
        int maxConcurrentRules = 5)
    {
        _logger = logger;
        _ruleManifestService = ruleManifestService ?? new RuleManifestService(logger as ILogger<RuleManifestService>);
        _maxConcurrentRules = maxConcurrentRules;
        _executionSemaphore = new SemaphoreSlim(maxConcurrentRules, maxConcurrentRules);
        
        // Initialize session logger
        var sessionId = Guid.NewGuid().ToString();
        _sessionLogger = new SessionLogger(sessionId, logger);
        _sessionLogger.LogInfo("External PowerShell executor initializing with session ID: {0}", sessionId);
        _sessionLogger.LogInfo("Max concurrent rules: {0}", maxConcurrentRules);
        
        // Find PowerShell 7 installation
        _powerShellPath = FindPowerShell7();
        _sessionLogger.LogInfo("Using PowerShell at: {0}", _powerShellPath);
        
        // Verify PowerShell is working
        VerifyPowerShellInstallation();
    }

    private string FindPowerShell7()
    {
        _sessionLogger?.LogSection("PowerShell 7 Discovery", "Searching for PowerShell 7 installation");
        
        // Common PowerShell 7 installation paths
        var possiblePaths = new[]
        {
            @"C:\Program Files\PowerShell\7\pwsh.exe",
            @"C:\Program Files\PowerShell\7-preview\pwsh.exe",
            @"C:\Program Files (x86)\PowerShell\7\pwsh.exe",
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "PowerShell", "7", "pwsh.exe")
        };

        foreach (var path in possiblePaths)
        {
            if (File.Exists(path))
            {
                _sessionLogger?.LogInfo("Found PowerShell 7 at: {0}", path);
                return path;
            }
        }

        // Try to find from PATH
        var pathEnv = Environment.GetEnvironmentVariable("PATH");
        if (!string.IsNullOrEmpty(pathEnv))
        {
            var paths = pathEnv.Split(Path.PathSeparator);
            foreach (var path in paths)
            {
                var pwshPath = Path.Combine(path, "pwsh.exe");
                if (File.Exists(pwshPath))
                {
                    _sessionLogger?.LogInfo("Found PowerShell 7 in PATH at: {0}", pwshPath);
                    return pwshPath;
                }
            }
        }

        // Fallback to Windows PowerShell if PS7 not found
        var fallbackPath = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
        _sessionLogger?.LogWarning("PowerShell 7 not found, falling back to Windows PowerShell at: {0}", fallbackPath);
        return fallbackPath;
    }

    private void VerifyPowerShellInstallation()
    {
        _sessionLogger?.LogSection("PowerShell Verification", "Testing PowerShell functionality");
        
        try
        {
            var testScript = "$PSVersionTable.PSVersion.ToString()";
            var result = ExecutePowerShellCommand(testScript);
            
            _sessionLogger?.LogInfo("PowerShell version: {0}", result.Trim());
            _sessionLogger?.LogInfo("PowerShell verification successful");
        }
        catch (Exception ex)
        {
            _sessionLogger?.LogError("PowerShell verification failed", ex);
            throw new InvalidOperationException($"PowerShell verification failed: {ex.Message}", ex);
        }
    }

    private string ExecutePowerShellCommand(string command)
    {
        using var process = new Process();
        process.StartInfo = new ProcessStartInfo
        {
            FileName = _powerShellPath,
            Arguments = $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"{command}\"",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8
        };

        process.Start();
        var output = process.StandardOutput.ReadToEnd();
        var error = process.StandardError.ReadToEnd();
        process.WaitForExit();

        if (!string.IsNullOrEmpty(error))
        {
            throw new InvalidOperationException($"PowerShell error: {error}");
        }

        return output;
    }

    public async Task<ScanSession> ExecuteScanAsync(ScanConfiguration config, CancellationToken cancellationToken = default)
    {
        var session = new ScanSession
        {
            SessionId = Guid.NewGuid().ToString(),
            StartTime = DateTime.UtcNow,
            Configuration = config,
            Results = new List<ScanResult>()
        };

        _sessionLogger?.LogSection("Scan Session", $"Starting scan session {session.SessionId}");
        _logger?.LogInformation("Starting scan session {SessionId}", session.SessionId);

        try
        {
            // Get available rules
            var rulesDirectory = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "indicators");
            var availableRules = await _ruleManifestService.GetAvailableRules(rulesDirectory);
            var rulesToExecute = FilterRulesForExecution(availableRules, config);
            
            _sessionLogger?.LogInfo("Total rules to execute: {0}", rulesToExecute.Count);
            _logger?.LogInformation("Executing {RuleCount} rules based on configuration", rulesToExecute.Count);

            // Execute rules in parallel with concurrency limit
            var tasks = new List<Task<ScanResult>>();
            var completedRules = 0;
            var totalRules = rulesToExecute.Count;

            foreach (var rule in rulesToExecute)
            {
                await _executionSemaphore.WaitAsync(cancellationToken);
                
                var task = Task.Run(async () =>
                {
                    try
                    {
                        var result = await ExecuteRuleInternalAsync(rule.RuleId, rule.RulePath, cancellationToken);
                        
                        Interlocked.Increment(ref completedRules);
                        var progress = (double)completedRules * 100.0 / totalRules;
                        
                        ProgressChanged?.Invoke(this, new ScanProgressEventArgs
                        {
                            SessionId = session.SessionId,
                            TotalRules = totalRules,
                            CompletedRules = completedRules,
                            CurrentRule = rule.RuleId,
                            Progress = progress
                        });
                        
                        return result;
                    }
                    finally
                    {
                        _executionSemaphore.Release();
                    }
                }, cancellationToken);
                
                tasks.Add(task);
            }

            var results = await Task.WhenAll(tasks);
            session.Results = results.Where(r => r != null).ToList();
        }
        catch (Exception ex)
        {
            _sessionLogger?.LogError("Scan session failed", ex);
            _logger?.LogError(ex, "Scan session {SessionId} failed", session.SessionId);
            throw;
        }
        finally
        {
            session.EndTime = DateTime.UtcNow;
            _sessionLogger?.LogInfo("Scan session completed. Duration: {0:F2} seconds", 
                (session.EndTime.Value - session.StartTime).TotalSeconds);
        }

        return session;
    }

    private List<RuleExecutionInfo> FilterRulesForExecution(List<RuleExecutionInfo> rules, ScanConfiguration config)
    {
        var filtered = rules.AsEnumerable();

        // Filter by environment
        if (config.ScanActiveDirectory && !config.ScanEntraId)
            filtered = filtered.Where(r => r.Definition.Environment == "ActiveDirectory");
        else if (!config.ScanActiveDirectory && config.ScanEntraId)
            filtered = filtered.Where(r => r.Definition.Environment == "EntraID");

        // Apply include/exclude filters
        if (config.IncludedRules?.Any() == true)
            filtered = filtered.Where(r => config.IncludedRules.Contains(r.RuleId));
        
        if (config.ExcludedRules?.Any() == true)
            filtered = filtered.Where(r => !config.ExcludedRules.Contains(r.RuleId));

        return filtered.ToList();
    }

    public async Task<ScanResult> ExecuteRuleAsync(string rulePath, CancellationToken cancellationToken = default)
    {
        var ruleName = Path.GetFileNameWithoutExtension(rulePath);
        return await ExecuteRuleInternalAsync(ruleName, rulePath, cancellationToken);
    }
    
    private async Task<ScanResult> ExecuteRuleInternalAsync(string ruleName, string rulePath, CancellationToken cancellationToken = default)
    {
        _sessionLogger?.LogSection($"Rule Execution: {ruleName}", $"Starting execution of {ruleName}");
        
        RuleStarted?.Invoke(this, new RuleExecutionEventArgs 
        { 
            RuleName = ruleName,
            RulePath = rulePath,
            StartTime = DateTime.UtcNow
        });

        try
        {
            if (!File.Exists(rulePath))
            {
                _sessionLogger?.LogWarning("Rule file not found: {0}", rulePath);
                throw new FileNotFoundException($"Rule file not found: {rulePath}");
            }

            _sessionLogger?.LogInfo("Executing PowerShell script: {0}", rulePath);
            
            // Read the script content for logging
            var scriptContent = await File.ReadAllTextAsync(rulePath, cancellationToken);
            _sessionLogger?.LogPowerShellScript(ruleName, scriptContent);
            
            // Create a wrapper script that ensures JSON output
            var wrapperScript = $@"
                $ErrorActionPreference = 'Stop'
                try {{
                    # Execute the rule script
                    $result = & '{rulePath.Replace("'", "''")}'
                    
                    # Ensure we have a result object
                    if ($null -eq $result) {{
                        $result = @{{
                            CheckId = '{ruleName}'
                            Timestamp = (Get-Date).ToString('o')
                            Status = 'NoData'
                            Message = 'Rule executed but returned no data'
                            Score = 0
                            Severity = 'Low'
                            Category = 'Unknown'
                            Findings = @()
                            AffectedObjects = 0
                            IgnoredObjects = 0
                            Metadata = @{{}}
                        }}
                    }}
                    
                    # Convert to JSON and output
                    $result | ConvertTo-Json -Depth 10 -Compress
                }}
                catch {{
                    # Return error as JSON
                    @{{
                        CheckId = '{ruleName}'
                        Timestamp = (Get-Date).ToString('o')
                        Status = 'Error'
                        Message = $_.Exception.Message
                        Score = 0
                        Severity = 'High'
                        Category = ''
                        Findings = @()
                        AffectedObjects = 0
                        IgnoredObjects = 0
                        Metadata = @{{
                            ErrorType = $_.Exception.GetType().Name
                            StackTrace = $_.ScriptStackTrace
                        }}
                    }} | ConvertTo-Json -Depth 10 -Compress
                }}
            ";

            // Execute the script using external PowerShell process
            using var process = new Process();
            process.StartInfo = new ProcessStartInfo
            {
                FileName = _powerShellPath,
                Arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command -",
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
            
            process.OutputDataReceived += (sender, e) =>
            {
                if (!string.IsNullOrEmpty(e.Data))
                    outputBuilder.AppendLine(e.Data);
            };
            
            process.ErrorDataReceived += (sender, e) =>
            {
                if (!string.IsNullOrEmpty(e.Data))
                    errorBuilder.AppendLine(e.Data);
            };

            var stopwatch = Stopwatch.StartNew();
            process.Start();
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();
            
            // Write the wrapper script to stdin
            await process.StandardInput.WriteAsync(wrapperScript);
            process.StandardInput.Close();
            
            // Wait for completion with timeout
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(TimeSpan.FromSeconds(30));
            
            await Task.Run(() => process.WaitForExit(), cts.Token);
            stopwatch.Stop();
            
            var output = outputBuilder.ToString();
            var error = errorBuilder.ToString();
            
            _sessionLogger?.LogInfo("Rule execution completed in {0:F2} seconds", stopwatch.Elapsed.TotalSeconds);
            
            if (!string.IsNullOrEmpty(error))
            {
                _sessionLogger?.LogWarning("PowerShell stderr output: {0}", error);
            }
            
            // Parse the JSON result
            if (string.IsNullOrWhiteSpace(output))
            {
                throw new InvalidOperationException("PowerShell script returned no output");
            }
            
            var result = JsonSerializer.Deserialize<ScanResult>(output, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            });
            
            if (result != null)
            {
                result.Metadata.ExecutionTime = stopwatch.Elapsed.TotalSeconds;
                result.Metadata.RuleVersion = "1.0.0";
                
                _sessionLogger?.LogInfo("Rule {0} completed with status: {1}", ruleName, result.Status);
                
                RuleCompleted?.Invoke(this, new RuleExecutionEventArgs 
                { 
                    RuleName = ruleName,
                    RulePath = rulePath,
                    EndTime = DateTime.UtcNow,
                    Result = result
                });
            }
            
            return result;
        }
        catch (Exception ex)
        {
            _sessionLogger?.LogError($"Rule {ruleName} failed", ex);
            _logger?.LogError(ex, "Failed to execute rule {RuleName}", ruleName);
            
            var errorResult = new ScanResult
            {
                CheckId = ruleName,
                Timestamp = DateTime.UtcNow.ToString("o"),
                Status = "Error",
                Message = ex.Message,
                Score = 0,
                Severity = "High",
                Category = "",
                Findings = new List<Finding>(),
                AffectedObjects = 0,
                IgnoredObjects = 0,
                Metadata = new ScanMetadata
                {
                    Domain = null,
                    TenantId = null,
                    ExecutionTime = 0,
                    RuleVersion = "1.0.0",
                    Environment = null
                }
            };
            
            RuleError?.Invoke(this, new RuleExecutionEventArgs 
            { 
                RuleName = ruleName,
                RulePath = rulePath,
                EndTime = DateTime.UtcNow,
                Result = errorResult,
                Error = ex.ToString()
            });
            
            return errorResult;
        }
    }
    
    public async Task<ScanResult> ExecuteRuleAsync(RuleExecutionInfo ruleInfo, Runspace? authenticatedRunspace = null, CancellationToken cancellationToken = default)
    {
        // Note: authenticatedRunspace is ignored in external process implementation
        return await ExecuteRuleInternalAsync(ruleInfo.RuleId, ruleInfo.RulePath, cancellationToken);
    }
    
    public async Task<ScanSession> ExecuteScanWithProfileAsync(ScanProfileConfiguration profileConfig, IEntraIDAuthenticationManager? entraIdAuth = null, CancellationToken cancellationToken = default)
    {
        // Get available rules and filter by selected tiers
        var rulesDirectory = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "indicators");
        var allRules = await _ruleManifestService.GetAvailableRules(rulesDirectory);
        
        // Filter rules based on selected tiers from profile
        var filteredRuleIds = allRules
            .Where(r => profileConfig.SelectedTiers.Contains(r.Tier.Name))
            .Select(r => r.RuleId)
            .ToList();
        
        _sessionLogger?.LogInfo("Profile filtering: Selected tiers: {0}, Filtered to {1} rules from {2} total", 
            string.Join(", ", profileConfig.SelectedTiers), filteredRuleIds.Count, allRules.Count);
        
        // Convert profile config to standard scan config with filtered rules
        var config = new ScanConfiguration
        {
            ScanActiveDirectory = profileConfig.IncludeActiveDirectory,
            ScanEntraId = profileConfig.IncludeEntraID,
            IncludedRules = filteredRuleIds, // Use filtered rules based on tiers
            ExcludedRules = profileConfig.ExcludedRules ?? new List<string>(),
            MaxParallelRules = 5
        };
        
        return await ExecuteScanAsync(config, cancellationToken);
    }
    
    public async Task<List<string>> DiscoverRulesAsync(string rulesDirectory)
    {
        if (!Directory.Exists(rulesDirectory))
        {
            _logger?.LogWarning("Rules directory not found: {Directory}", rulesDirectory);
            return new List<string>();
        }
        
        var rules = await Task.Run(() => Directory.GetFiles(rulesDirectory, "*.ps1", SearchOption.AllDirectories).ToList());
        _logger?.LogInformation("Discovered {Count} rules in {Directory}", rules.Count, rulesDirectory);
        return rules;
    }
    
    public async Task<List<RuleExecutionInfo>> GetAvailableRulesAsync(ScanProfileConfiguration? profileConfig = null)
    {
        var rulesDirectory = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "indicators");
        var rules = await _ruleManifestService.GetAvailableRules(rulesDirectory);
        
        if (profileConfig != null)
        {
            // Filter by profile configuration
            if (profileConfig.IncludedRules?.Any() == true)
                rules = rules.Where(r => profileConfig.IncludedRules.Contains(r.RuleId)).ToList();
            
            if (profileConfig.ExcludedRules?.Any() == true)
                rules = rules.Where(r => !profileConfig.ExcludedRules.Contains(r.RuleId)).ToList();
        }
        
        return rules;
    }

    public void Dispose()
    {
        _executionSemaphore?.Dispose();
        _sessionLogger?.LogInfo("External PowerShell executor disposed");
    }
}