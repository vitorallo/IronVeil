using System.Text.Json.Serialization;

namespace IronVeil.PowerShell.Models;

public class RuleManifest
{
    [JsonPropertyName("version")]
    public string Version { get; set; } = string.Empty;

    [JsonPropertyName("lastUpdated")]
    public DateTime LastUpdated { get; set; }

    [JsonPropertyName("description")]
    public string Description { get; set; } = string.Empty;

    [JsonPropertyName("profiles")]
    public Dictionary<string, ScanProfile> Profiles { get; set; } = new();

    [JsonPropertyName("tiers")]
    public Dictionary<string, TierDefinition> Tiers { get; set; } = new();

    [JsonPropertyName("categories")]
    public Dictionary<string, string> Categories { get; set; } = new();

    [JsonPropertyName("rules")]
    public Dictionary<string, RuleDefinition> Rules { get; set; } = new();

    [JsonPropertyName("helperScripts")]
    public Dictionary<string, HelperScript> HelperScripts { get; set; } = new();

    [JsonPropertyName("prerequisites")]
    public Dictionary<string, Prerequisites> Prerequisites { get; set; } = new();
}

public class ScanProfile
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("description")]
    public string Description { get; set; } = string.Empty;

    [JsonPropertyName("tiers")]
    public List<string> Tiers { get; set; } = new();

    [JsonPropertyName("estimatedRules")]
    public int EstimatedRules { get; set; }

    [JsonPropertyName("estimatedTime")]
    public string EstimatedTime { get; set; } = string.Empty;
}

public class TierDefinition
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("description")]
    public string Description { get; set; } = string.Empty;

    [JsonPropertyName("weight")]
    public int Weight { get; set; }

    [JsonPropertyName("color")]
    public string Color { get; set; } = string.Empty;

    [JsonPropertyName("priority")]
    public int Priority { get; set; }
}

public class RuleDefinition
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("tier")]
    public string Tier { get; set; } = string.Empty;

    [JsonPropertyName("category")]
    public string Category { get; set; } = string.Empty;

    [JsonPropertyName("environment")]
    public string Environment { get; set; } = string.Empty;

    [JsonPropertyName("requiresAuthentication")]
    public bool RequiresAuthentication { get; set; }

    [JsonPropertyName("requiresAdmin")]
    public bool RequiresAdmin { get; set; }

    [JsonPropertyName("dependencies")]
    public List<string> Dependencies { get; set; } = new();

    [JsonPropertyName("estimatedTime")]
    public int EstimatedTime { get; set; }

    [JsonPropertyName("frameworks")]
    public List<string> Frameworks { get; set; } = new();
}

public class HelperScript
{
    [JsonPropertyName("description")]
    public string Description { get; set; } = string.Empty;

    [JsonPropertyName("environment")]
    public string Environment { get; set; } = string.Empty;

    [JsonPropertyName("required")]
    public bool Required { get; set; }
}

public class Prerequisites
{
    [JsonPropertyName("powershellModules")]
    public List<string> PowerShellModules { get; set; } = new();

    [JsonPropertyName("systemRequirements")]
    public List<string> SystemRequirements { get; set; } = new();

    [JsonPropertyName("permissions")]
    public List<string> Permissions { get; set; } = new();
}

public class RuleExecutionInfo
{
    public string RuleId { get; set; } = string.Empty;
    public string RulePath { get; set; } = string.Empty;
    public RuleDefinition Definition { get; set; } = new();
    public TierDefinition Tier { get; set; } = new();
    public bool CanExecute { get; set; } = true;
    public List<string> BlockingReasons { get; set; } = new();
    public TimeSpan EstimatedDuration => TimeSpan.FromSeconds(Definition.EstimatedTime);
}

public enum ScanProfileType
{
    Minimal,
    Recommended, 
    Full,
    Custom
}

public enum RuleEnvironment
{
    ActiveDirectory,
    EntraID,
    Hybrid,
    System
}

public class ScanProfileConfiguration
{
    public ScanProfileType Type { get; set; } = ScanProfileType.Recommended;
    public List<string> SelectedTiers { get; set; } = new();
    public List<string> IncludedRules { get; set; } = new();
    public List<string> ExcludedRules { get; set; } = new();
    public bool IncludeActiveDirectory { get; set; } = true;
    public bool IncludeEntraID { get; set; } = true;
    public bool RequireAuthentication { get; set; } = true;
}