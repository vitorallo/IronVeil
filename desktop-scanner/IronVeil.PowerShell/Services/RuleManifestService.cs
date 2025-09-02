using IronVeil.PowerShell.Models;
using Microsoft.Extensions.Logging;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace IronVeil.PowerShell.Services;

public interface IRuleManifestService
{
    Task<RuleManifest> LoadManifestAsync(string manifestPath);
    List<RuleExecutionInfo> GetRulesForProfile(ScanProfileConfiguration profileConfig);
    Task<List<RuleExecutionInfo>> GetAvailableRules(string rulesDirectory);
    ScanProfile? GetScanProfile(string profileName);
    Dictionary<string, int> GetRuleCountsByTier();
    TimeSpan GetEstimatedExecutionTime(List<RuleExecutionInfo> rules);
    bool ValidateRulePrerequisites(RuleExecutionInfo rule, bool isEntraIdAuthenticated = false);
}

public class RuleManifestService : IRuleManifestService
{
    private readonly ILogger<RuleManifestService>? _logger;
    private RuleManifest? _manifest;
    private readonly string _defaultManifestPath;

    public RuleManifestService(ILogger<RuleManifestService>? logger = null)
    {
        _logger = logger;
        _defaultManifestPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "indicators", "manifest.json");
    }

    public async Task<RuleManifest> LoadManifestAsync(string? manifestPath = null)
    {
        var path = manifestPath ?? _defaultManifestPath;
        
        try
        {
            if (!File.Exists(path))
            {
                _logger?.LogWarning("Manifest file not found at {Path}, using default configuration", path);
                return CreateDefaultManifest();
            }

            var jsonContent = await File.ReadAllTextAsync(path);
            var options = new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true,
                AllowTrailingCommas = true
            };

            _manifest = JsonSerializer.Deserialize<RuleManifest>(jsonContent, options);
            
            if (_manifest == null)
            {
                _logger?.LogError("Failed to deserialize manifest from {Path}", path);
                return CreateDefaultManifest();
            }

            _logger?.LogInformation("Loaded manifest v{Version} with {RuleCount} rules from {Path}", 
                _manifest.Version, _manifest.Rules.Count, path);
            
            return _manifest;
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to load manifest from {Path}", path);
            return CreateDefaultManifest();
        }
    }

    public List<RuleExecutionInfo> GetRulesForProfile(ScanProfileConfiguration profileConfig)
    {
        if (_manifest == null)
        {
            _logger?.LogWarning("Manifest not loaded, cannot get rules for profile");
            return new List<RuleExecutionInfo>();
        }

        var rules = new List<RuleExecutionInfo>();

        foreach (var kvp in _manifest.Rules)
        {
            var ruleId = kvp.Key;
            var ruleDef = kvp.Value;

            // Check tier inclusion
            if (profileConfig.SelectedTiers.Any() && !profileConfig.SelectedTiers.Contains(ruleDef.Tier))
                continue;

            // Check environment inclusion
            if (!profileConfig.IncludeActiveDirectory && ruleDef.Environment.Equals("ActiveDirectory", StringComparison.OrdinalIgnoreCase))
                continue;
            
            if (!profileConfig.IncludeEntraID && ruleDef.Environment.Equals("EntraID", StringComparison.OrdinalIgnoreCase))
                continue;

            // Check explicit inclusions/exclusions
            if (profileConfig.ExcludedRules.Contains(ruleId))
                continue;
            
            if (profileConfig.IncludedRules.Any() && !profileConfig.IncludedRules.Contains(ruleId))
                continue;

            // Get tier definition
            var tierDef = _manifest.Tiers.GetValueOrDefault(ruleDef.Tier, new TierDefinition
            {
                Name = ruleDef.Tier,
                Priority = 999,
                Weight = 25
            });

            var ruleInfo = new RuleExecutionInfo
            {
                RuleId = ruleId,
                RulePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "indicators", $"{ruleId}.ps1"),
                Definition = ruleDef,
                Tier = tierDef
            };

            // Check if rule can execute based on prerequisites
            ruleInfo.CanExecute = ValidateRulePrerequisites(ruleInfo, profileConfig.RequireAuthentication);

            rules.Add(ruleInfo);
        }

        // Sort by tier priority, then by estimated time
        return rules.OrderBy(r => r.Tier.Priority)
                   .ThenBy(r => r.Definition.EstimatedTime)
                   .ToList();
    }

    public async Task<List<RuleExecutionInfo>> GetAvailableRules(string rulesDirectory)
    {
        var rules = new List<RuleExecutionInfo>();

        if (!Directory.Exists(rulesDirectory))
        {
            _logger?.LogWarning("Rules directory not found: {Directory}", rulesDirectory);
            return rules;
        }

        try
        {
            var ruleFiles = Directory.GetFiles(rulesDirectory, "*.ps1", SearchOption.TopDirectoryOnly)
                .Where(f => !Path.GetFileName(f).StartsWith("IronVeil-") && 
                           !f.Contains("test", StringComparison.OrdinalIgnoreCase) &&
                           !f.Contains("pk-reference", StringComparison.OrdinalIgnoreCase))
                .ToList();

            foreach (var ruleFile in ruleFiles)
            {
                var ruleId = Path.GetFileNameWithoutExtension(ruleFile);
                
                // Try to get rule definition from manifest
                if (_manifest?.Rules.TryGetValue(ruleId, out var ruleDef) == true)
                {
                    var tierDef = _manifest.Tiers.GetValueOrDefault(ruleDef.Tier, new TierDefinition
                    {
                        Name = ruleDef.Tier,
                        Priority = 999,
                        Weight = 25
                    });

                    var ruleInfo = new RuleExecutionInfo
                    {
                        RuleId = ruleId,
                        RulePath = ruleFile,
                        Definition = ruleDef,
                        Tier = tierDef,
                        CanExecute = true
                    };

                    rules.Add(ruleInfo);
                }
                else
                {
                    // Parse metadata from PowerShell file directly
                    var parsedRule = await ParseRuleMetadataFromFileAsync(ruleFile);
                    if (parsedRule != null)
                    {
                        rules.Add(parsedRule);
                    }
                }
            }

            _logger?.LogInformation("Found {RuleCount} available rules in {Directory}", rules.Count, rulesDirectory);
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to discover rules in directory {Directory}", rulesDirectory);
        }

        return rules.OrderBy(r => r.Tier.Priority)
                   .ThenBy(r => r.Definition.EstimatedTime)
                   .ToList();
    }

    public ScanProfile? GetScanProfile(string profileName)
    {
        return _manifest?.Profiles.GetValueOrDefault(profileName.ToLowerInvariant());
    }

    public Dictionary<string, int> GetRuleCountsByTier()
    {
        if (_manifest == null) return new Dictionary<string, int>();

        return _manifest.Rules
            .GroupBy(r => r.Value.Tier)
            .ToDictionary(g => g.Key, g => g.Count());
    }

    public TimeSpan GetEstimatedExecutionTime(List<RuleExecutionInfo> rules)
    {
        var totalSeconds = rules.Where(r => r.CanExecute)
                                .Sum(r => r.Definition.EstimatedTime);
        
        return TimeSpan.FromSeconds(totalSeconds);
    }

    public bool ValidateRulePrerequisites(RuleExecutionInfo rule, bool isEntraIdAuthenticated = false)
    {
        var reasons = new List<string>();

        // Check authentication requirements
        if (rule.Definition.RequiresAuthentication && 
            rule.Definition.Environment.Equals("EntraID", StringComparison.OrdinalIgnoreCase) && 
            !isEntraIdAuthenticated)
        {
            reasons.Add("Requires Entra ID authentication");
        }

        // Check if rule file exists
        if (!File.Exists(rule.RulePath))
        {
            reasons.Add($"Rule file not found: {rule.RulePath}");
        }

        // Check dependencies
        foreach (var dependency in rule.Definition.Dependencies)
        {
            var dependencyPath = Path.Combine(Path.GetDirectoryName(rule.RulePath) ?? "", dependency);
            if (!File.Exists(dependencyPath))
            {
                reasons.Add($"Missing dependency: {dependency}");
            }
        }

        rule.BlockingReasons = reasons;
        return !reasons.Any();
    }

    private async Task<RuleExecutionInfo?> ParseRuleMetadataFromFile(string ruleFile)
    {
        try
        {
            var content = await File.ReadAllTextAsync(ruleFile);
            var ruleId = Path.GetFileNameWithoutExtension(ruleFile);

            // Extract metadata from PowerShell comment block
            var metadataMatch = Regex.Match(content, @"\.METADATA\s*\{([^}]+)\}", RegexOptions.Singleline | RegexOptions.IgnoreCase);
            
            if (metadataMatch.Success)
            {
                var jsonContent = "{" + metadataMatch.Groups[1].Value + "}";
                
                try
                {
                    var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
                    var metadata = JsonSerializer.Deserialize<Dictionary<string, object>>(jsonContent, options);
                    
                    if (metadata != null)
                    {
                        var ruleDef = new RuleDefinition
                        {
                            Name = metadata.GetValueOrDefault("name")?.ToString() ?? ruleId,
                            Tier = ExtractTierFromId(ruleId),
                            Category = metadata.GetValueOrDefault("category")?.ToString() ?? "Unknown",
                            Environment = DetermineEnvironment(ruleId),
                            RequiresAuthentication = ruleId.StartsWith("EID-"),
                            EstimatedTime = 30 // Default
                        };

                        var tierDef = new TierDefinition
                        {
                            Name = ruleDef.Tier,
                            Priority = GetTierPriority(ruleDef.Tier),
                            Weight = GetTierWeight(ruleDef.Tier)
                        };

                        return new RuleExecutionInfo
                        {
                            RuleId = ruleId,
                            RulePath = ruleFile,
                            Definition = ruleDef,
                            Tier = tierDef,
                            CanExecute = true
                        };
                    }
                }
                catch (JsonException ex)
                {
                    _logger?.LogWarning(ex, "Failed to parse metadata JSON from {RuleFile}", ruleFile);
                }
            }

            // Fallback: create minimal metadata
            return CreateFallbackRuleInfo(ruleId, ruleFile);
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to parse rule metadata from {RuleFile}", ruleFile);
            return null;
        }
    }

    private async Task<RuleExecutionInfo?> ParseRuleMetadataFromFileAsync(string ruleFile)
    {
        try
        {
            var content = await File.ReadAllTextAsync(ruleFile);
            var ruleId = Path.GetFileNameWithoutExtension(ruleFile);

            // Extract metadata from PowerShell comment block
            var metadataMatch = Regex.Match(content, @"\.METADATA\s*\{([^}]+)\}", RegexOptions.Singleline | RegexOptions.IgnoreCase);
            
            if (metadataMatch.Success)
            {
                var jsonContent = "{" + metadataMatch.Groups[1].Value + "}";
                
                try
                {
                    var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
                    var metadata = JsonSerializer.Deserialize<Dictionary<string, object>>(jsonContent, options);
                    
                    if (metadata != null)
                    {
                        var ruleDef = new RuleDefinition
                        {
                            Name = metadata.GetValueOrDefault("name")?.ToString() ?? ruleId,
                            Tier = ExtractTierFromId(ruleId),
                            Category = metadata.GetValueOrDefault("category")?.ToString() ?? "Unknown",
                            Environment = DetermineEnvironment(ruleId),
                            RequiresAuthentication = ruleId.StartsWith("EID-"),
                            EstimatedTime = 30 // Default
                        };

                        var tierDef = new TierDefinition
                        {
                            Name = ruleDef.Tier,
                            Priority = GetTierPriority(ruleDef.Tier),
                            Weight = GetTierWeight(ruleDef.Tier)
                        };

                        return new RuleExecutionInfo
                        {
                            RuleId = ruleId,
                            RulePath = ruleFile,
                            Definition = ruleDef,
                            Tier = tierDef,
                            CanExecute = true
                        };
                    }
                }
                catch (JsonException ex)
                {
                    _logger?.LogWarning(ex, "Failed to parse metadata JSON from {RuleFile}", ruleFile);
                }
            }

            // Fallback: create minimal metadata
            return CreateFallbackRuleInfo(ruleId, ruleFile);
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to parse rule metadata from {RuleFile}", ruleFile);
            return null;
        }
    }

    private RuleExecutionInfo CreateFallbackRuleInfo(string ruleId, string ruleFile)
    {
        var ruleDef = new RuleDefinition
        {
            Name = ruleId,
            Tier = ExtractTierFromId(ruleId),
            Category = "Unknown",
            Environment = DetermineEnvironment(ruleId),
            RequiresAuthentication = ruleId.StartsWith("EID-"),
            EstimatedTime = 30
        };

        var tierDef = new TierDefinition
        {
            Name = ruleDef.Tier,
            Priority = GetTierPriority(ruleDef.Tier),
            Weight = GetTierWeight(ruleDef.Tier)
        };

        return new RuleExecutionInfo
        {
            RuleId = ruleId,
            RulePath = ruleFile,
            Definition = ruleDef,
            Tier = tierDef,
            CanExecute = true
        };
    }

    private string ExtractTierFromId(string ruleId)
    {
        var match = Regex.Match(ruleId, @"T(\d+)");
        return match.Success ? $"T{match.Groups[1].Value}" : "T4";
    }

    private string DetermineEnvironment(string ruleId)
    {
        if (ruleId.StartsWith("AD-")) return "ActiveDirectory";
        if (ruleId.StartsWith("EID-")) return "EntraID";
        return "System";
    }

    private int GetTierPriority(string tier) => tier switch
    {
        "T1" => 1,
        "T2" => 2,
        "T3" => 3,
        "T4" => 4,
        _ => 999
    };

    private int GetTierWeight(string tier) => tier switch
    {
        "T1" => 100,
        "T2" => 75,
        "T3" => 50,
        "T4" => 25,
        _ => 25
    };

    private RuleManifest CreateDefaultManifest()
    {
        return new RuleManifest
        {
            Version = "1.0.0",
            LastUpdated = DateTime.UtcNow,
            Description = "Default manifest when none is available",
            Profiles = new Dictionary<string, ScanProfile>
            {
                ["minimal"] = new() { Name = "Essential", Description = "Critical checks only", Tiers = ["T1"] },
                ["recommended"] = new() { Name = "Recommended", Description = "Critical and high-impact", Tiers = ["T1", "T2"] },
                ["full"] = new() { Name = "Complete", Description = "All security checks", Tiers = ["T1", "T2", "T3", "T4"] }
            },
            Tiers = new Dictionary<string, TierDefinition>
            {
                ["T1"] = new() { Name = "Critical", Weight = 100, Priority = 1, Color = "#DC2626" },
                ["T2"] = new() { Name = "High", Weight = 75, Priority = 2, Color = "#EA580C" },
                ["T3"] = new() { Name = "Medium", Weight = 50, Priority = 3, Color = "#F59E0B" },
                ["T4"] = new() { Name = "Low", Weight = 25, Priority = 4, Color = "#22C55E" }
            }
        };
    }
}