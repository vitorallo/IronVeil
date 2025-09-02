using IronVeil.Core.Models;
using IronVeil.PowerShell.Models;
using IronVeil.PowerShell.Services;
using Microsoft.Extensions.Logging;
using System.Management.Automation.Runspaces;

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
    
    public async Task<ScanSession> ExecuteScanWithProfileAsync(ScanProfileConfiguration profileConfig, IEntraIDAuthenticationManager? entraIdAuth = null, CancellationToken cancellationToken = default)
    {
        _logger?.LogInformation("Starting mock scan session with profile {ProfileType}", profileConfig.Type);
        
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
        
        var estimatedRules = profileConfig.Type switch
        {
            ScanProfileType.Minimal => 8,
            ScanProfileType.Recommended => 23,
            ScanProfileType.Full => 50,
            _ => 15
        };
        
        // Simulate progress
        for (int i = 0; i <= estimatedRules; i++)
        {
            if (cancellationToken.IsCancellationRequested)
            {
                session.Status = ScanStatus.Cancelled;
                break;
            }
            
            OnProgressChanged(new ScanProgressEventArgs 
            { 
                Progress = (double)i / estimatedRules * 100,
                CurrentRule = $"Mock-Rule-{i}",
                TotalRules = estimatedRules,
                CompletedRules = i,
                SessionId = session.SessionId
            });
            
            await Task.Delay(100, cancellationToken);
        }
        
        // Add some mock results based on profile
        if (session.Status != ScanStatus.Cancelled)
        {
            if (profileConfig.SelectedTiers.Contains("T1"))
            {
                session.Results.Add(CreateMockResult("Critical", "Mock DCShadow attack evidence"));
                session.Results.Add(CreateMockResult("Critical", "Mock privileged SID in SIDHistory"));
            }
            if (profileConfig.SelectedTiers.Contains("T2"))
            {
                session.Results.Add(CreateMockResult("High", "Mock weak ACLs with DCSync rights"));
                session.Results.Add(CreateMockResult("High", "Mock print spooler on DC"));
            }
            if (profileConfig.SelectedTiers.Contains("T3"))
            {
                session.Results.Add(CreateMockResult("Medium", "Mock legacy authentication enabled"));
                session.Results.Add(CreateMockResult("Medium", "Mock stale accounts detected"));
            }
            if (profileConfig.SelectedTiers.Contains("T4"))
            {
                session.Results.Add(CreateMockResult("Low", "Mock default admin account not renamed"));
            }
            
            session.Status = ScanStatus.Completed;
        }
        
        session.EndTime = DateTime.UtcNow;
        _logger?.LogInformation("Mock scan session completed with {ResultCount} results", session.Results.Count);
        
        return session;
    }

    public async Task<ScanResult> ExecuteRuleAsync(RuleExecutionInfo ruleInfo, Runspace? authenticatedRunspace = null, CancellationToken cancellationToken = default)
    {
        _logger?.LogInformation("Mock executing rule: {RuleId}", ruleInfo.RuleId);
        await Task.Delay(100, cancellationToken);
        
        return new ScanResult
        {
            CheckId = ruleInfo.RuleId,
            Timestamp = DateTime.UtcNow.ToString("o"),
            Status = "Success",
            Score = ruleInfo.Tier.Weight,
            Severity = ruleInfo.Tier.Name,
            Category = ruleInfo.Definition.Category,
            Message = $"Mock result for {ruleInfo.Definition.Name}",
            Findings = new List<Finding>
            {
                new Finding
                {
                    ObjectName = "MockObject",
                    ObjectType = "MockType",
                    RiskLevel = ruleInfo.Tier.Name,
                    Description = $"Mock finding for {ruleInfo.Definition.Name}",
                    Remediation = "This is a mock finding for development"
                }
            },
            AffectedObjects = 1,
            Metadata = new ScanMetadata
            {
                ExecutionTime = 0.1,
                RuleVersion = "1.0.0",
                Environment = ruleInfo.Definition.Environment
            }
        };
    }

    public async Task<List<RuleExecutionInfo>> GetAvailableRulesAsync(ScanProfileConfiguration? profileConfig = null)
    {
        _logger?.LogInformation("Mock getting available rules for profile {ProfileType}", profileConfig?.Type);
        await Task.Delay(50);
        
        var rules = new List<RuleExecutionInfo>();
        
        // Create mock AD rules
        if (profileConfig?.IncludeActiveDirectory != false)
        {
            rules.AddRange(CreateMockRules("AD", "ActiveDirectory", profileConfig?.SelectedTiers ?? ["T1", "T2"]));
        }
        
        // Create mock EID rules
        if (profileConfig?.IncludeEntraID == true)
        {
            rules.AddRange(CreateMockRules("EID", "EntraID", profileConfig?.SelectedTiers ?? ["T1", "T2"]));
        }
        
        return rules;
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

    private List<RuleExecutionInfo> CreateMockRules(string prefix, string environment, List<string> tiers)
    {
        var rules = new List<RuleExecutionInfo>();
        
        foreach (var tier in tiers)
        {
            var ruleId = $"{prefix}-{tier}-001";
            rules.Add(new RuleExecutionInfo
            {
                RuleId = ruleId,
                RulePath = $"mock-{ruleId}.ps1",
                Definition = new RuleDefinition
                {
                    Name = $"Mock {environment} Rule {tier}",
                    Tier = tier,
                    Category = "Mock",
                    Environment = environment,
                    RequiresAuthentication = environment == "EntraID",
                    EstimatedTime = 30
                },
                Tier = new TierDefinition
                {
                    Name = tier switch
                    {
                        "T1" => "Critical",
                        "T2" => "High",
                        "T3" => "Medium",
                        "T4" => "Low",
                        _ => "Medium"
                    },
                    Weight = tier switch
                    {
                        "T1" => 100,
                        "T2" => 75,
                        "T3" => 50,
                        "T4" => 25,
                        _ => 50
                    },
                    Priority = int.Parse(tier.Substring(1))
                },
                CanExecute = true
            });
        }
        
        return rules;
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