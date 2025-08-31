using IronVeil.Core.Models;
using Microsoft.Extensions.Logging;

namespace IronVeil.PowerShell;

/// <summary>
/// Mock implementation of PowerShellExecutor for development/testing when PowerShell isn't available
/// </summary>
public class MockPowerShellExecutor : IPowerShellExecutor
{
    private readonly ILogger? _logger;
    
    public event EventHandler<RuleExecutionEventArgs>? RuleStarted;
    public event EventHandler<RuleExecutionEventArgs>? RuleCompleted;
    public event EventHandler<RuleExecutionEventArgs>? RuleError;
    public event EventHandler<ScanProgressEventArgs>? ProgressChanged;
    
    public MockPowerShellExecutor(ILogger? logger = null)
    {
        _logger = logger;
        _logger?.LogWarning("Using mock PowerShell executor - no actual rules will be executed");
    }
    
    public async Task<ScanSession> ExecuteScanAsync(ScanConfiguration config, CancellationToken cancellationToken = default)
    {
        _logger?.LogInformation("Starting mock scan session");
        
        var session = new ScanSession
        {
            Configuration = config,
            Status = ScanStatus.Running,
            StartTime = DateTime.UtcNow
        };
        
        // Simulate progress
        for (int i = 0; i <= 100; i += 10)
        {
            if (cancellationToken.IsCancellationRequested)
            {
                session.Status = ScanStatus.Cancelled;
                break;
            }
            
            OnProgressChanged(new ScanProgressEventArgs 
            { 
                Progress = i,
                CurrentRule = $"Mock Rule {i / 10}",
                TotalRules = 10,
                CompletedRules = i / 10,
                SessionId = session.SessionId
            });
            
            await Task.Delay(200, cancellationToken);
        }
        
        // Add some mock results
        if (session.Status != ScanStatus.Cancelled)
        {
            session.Results.Add(CreateMockResult("Critical", "Mock unconstrained delegation finding"));
            session.Results.Add(CreateMockResult("High", "Mock password policy issue"));
            session.Results.Add(CreateMockResult("Medium", "Mock stale account detection"));
            session.Results.Add(CreateMockResult("Low", "Mock informational finding"));
            
            session.Status = ScanStatus.Completed;
        }
        
        session.EndTime = DateTime.UtcNow;
        _logger?.LogInformation("Mock scan session completed with {ResultCount} results", session.Results.Count);
        
        return session;
    }
    
    public async Task<ScanResult> ExecuteRuleAsync(string rulePath, CancellationToken cancellationToken = default)
    {
        _logger?.LogInformation("Mock executing rule: {RulePath}", rulePath);
        await Task.Delay(100, cancellationToken);
        return CreateMockResult("Medium", $"Mock result for {Path.GetFileNameWithoutExtension(rulePath)}");
    }
    
    public async Task<List<string>> DiscoverRulesAsync(string rulesDirectory)
    {
        _logger?.LogInformation("Mock discovering rules in: {Directory}", rulesDirectory);
        await Task.Delay(50);
        
        // Return some mock rule paths
        return new List<string>
        {
            "mock-rule-1.ps1",
            "mock-rule-2.ps1",
            "mock-rule-3.ps1"
        };
    }
    
    protected virtual void OnProgressChanged(ScanProgressEventArgs e)
    {
        ProgressChanged?.Invoke(this, e);
    }
    
    protected virtual void OnRuleCompleted(RuleExecutionEventArgs e)
    {
        RuleCompleted?.Invoke(this, e);
    }
    
    private ScanResult CreateMockResult(string severity, string description)
    {
        return new ScanResult
        {
            CheckId = $"mock-{Guid.NewGuid():N}",
            Timestamp = DateTime.UtcNow.ToString("o"),
            Status = "Success",
            Score = severity switch
            {
                "Critical" => 100,
                "High" => 75,
                "Medium" => 50,
                "Low" => 25,
                _ => 0
            },
            Severity = severity,
            Category = "Mock",
            Message = description,
            Findings = new List<Finding>
            {
                new Finding
                {
                    ObjectName = "MockObject",
                    ObjectType = "MockType",
                    RiskLevel = severity,
                    Description = description,
                    Remediation = "This is a mock finding for development"
                }
            },
            AffectedObjects = 1
        };
    }
    
    public void Dispose()
    {
        _logger?.LogInformation("Mock PowerShell executor disposed");
    }
}